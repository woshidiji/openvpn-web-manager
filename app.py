import hmac
import hashlib
import inspect
import ipaddress
import json
import logging
import os
import re
import secrets
import subprocess
import threading
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, session
from werkzeug.exceptions import RequestEntityTooLarge


DEFAULT_CONFIG = {
    "server_name": "server",
    "port": 1194,
    "protocol": "udp",
    "device": "tun",
    "network": "10.8.0.0/24",
    "dns": ["1.1.1.1", "1.0.0.1"],
    "keepalive_interval": 10,
    "keepalive_timeout": 120,
    "max_clients": 50,
}
ALLOWED_CIPHERS = ("AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305")
PROFILE_MAX_BYTES = 1024 * 1024
SETUP_LOCK = threading.Lock()
OPENVPN_HELPER = "/usr/lib/openvpn-web/openvpn_web_helper.py"


def _secure_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(str(temporary), str(path))
        os.chmod(str(path), mode)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_json(path, default):
    try:
        with open(str(path), "r", encoding="utf-8") as source:
            return json.load(source)
    except FileNotFoundError:
        return default


def _password_record(password):
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return {
        "salt": salt.hex(),
        "hash": derived.hex(),
        "iterations": 310000,
    }


def _verify_password(password, record):
    try:
        salt = bytes.fromhex(record["salt"])
        expected = bytes.fromhex(record["hash"])
        iterations = int(record["iterations"])
    except (KeyError, TypeError, ValueError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def _validate_config(payload):
    if not isinstance(payload, dict):
        raise ValueError("配置格式无效")

    name = payload.get("server_name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name):
        raise ValueError("服务名称只能包含字母、数字、下划线和连字符，长度为 1–32")

    try:
        port = int(payload.get("port"))
        network = ipaddress.ip_network(payload.get("network"), strict=False)
        interval = int(payload.get("keepalive_interval"))
        timeout = int(payload.get("keepalive_timeout"))
        max_clients = int(payload.get("max_clients"))
    except (TypeError, ValueError):
        raise ValueError("端口、网段或连接参数格式无效")
    if not 1 <= port <= 65535:
        raise ValueError("端口范围必须为 1–65535")
    if not isinstance(network, ipaddress.IPv4Network) or not 8 <= network.prefixlen <= 30:
        raise ValueError("服务端网段必须是 IPv4 的 /8 至 /30 网段")
    if not 1 <= interval <= 60 or not interval < timeout <= 3600:
        raise ValueError("Keepalive 超时必须大于间隔，且不超过 3600 秒")
    if not 1 <= max_clients <= 10000:
        raise ValueError("最大客户端数范围必须为 1–10000")

    protocol = payload.get("protocol")
    if protocol not in ("udp", "tcp-server"):
        raise ValueError("协议只能选择 UDP 或 TCP")
    device = payload.get("device")
    if device != "tun":
        raise ValueError("当前配置生成器仅支持 TUN 设备")

    dns = payload.get("dns")
    if not isinstance(dns, list) or not 1 <= len(dns) <= 4:
        raise ValueError("请配置 1–4 个 DNS IPv4 地址")
    normalized_dns = []
    for address in dns:
        try:
            parsed = ipaddress.ip_address(address)
        except (TypeError, ValueError):
            raise ValueError("DNS 地址必须是有效的 IPv4 地址")
        if not isinstance(parsed, ipaddress.IPv4Address):
            raise ValueError("DNS 地址必须是 IPv4 地址")
        normalized_dns.append(str(parsed))

    return {
        "server_name": name,
        "port": port,
        "protocol": protocol,
        "device": device,
        "network": str(network),
        "dns": normalized_dns,
        "keepalive_interval": interval,
        "keepalive_timeout": timeout,
        "max_clients": max_clients,
    }


def _validate_remote_address(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise ValueError("服务器地址必须是 IPv4 地址或有效域名")
    address = value.strip()
    if not address or len(address) > 253:
        raise ValueError("服务器地址必须是 IPv4 地址或有效域名")
    try:
        ipaddress.ip_address(address)
        return address
    except ValueError:
        labels = address.rstrip(".").split(".")
        if not labels or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("服务器地址必须是 IPv4 地址或有效域名")
        return address


def _render_openvpn_config(config, config_path):
    directory = Path(config_path).parent
    network = ipaddress.ip_network(config["network"])
    netmask = str(network.netmask)
    lines = [
        "# Generated by OpenVPN Web Manager",
        "port {}".format(config["port"]),
        "proto {}".format(config["protocol"]),
        "dev {}".format(config["device"]),
        "topology subnet",
        "server {} {}".format(network.network_address, netmask),
        "max-clients {}".format(config["max_clients"]),
        "keepalive {} {}".format(config["keepalive_interval"], config["keepalive_timeout"]),
        "persist-key",
        "persist-tun",
        "user nobody",
        "group nogroup",
        "dh none",
        "tls-version-min 1.2",
        "remote-cert-tls client",
        "ca {}".format(directory / "web-pki" / "ca.crt"),
        "cert {}".format(directory / "web-pki" / "server.crt"),
        "key {}".format(directory / "web-pki" / "server.key"),
        "tls-crypt {}".format(directory / "web-pki" / "ta.key"),
        "ncp-ciphers {}".format(":".join(ALLOWED_CIPHERS)),
    ]
    for address in config["dns"]:
        lines.append('push "dhcp-option DNS {}"'.format(address))
    lines.extend(["verb 3", ""])
    return "\n".join(lines)


def create_app(data_dir=None, config_path=None, service_unit=None, setup_token=None):
    data_dir = Path(data_dir or os.environ.get("OPENVPN_WEB_DATA_DIR", "./data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(data_dir), 0o700)
    profiles_dir = data_dir / "profiles"
    profiles_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(str(profiles_dir), 0o700)

    secret_path = data_dir / "session.key"
    if secret_path.exists():
        secret_key = secret_path.read_bytes()
    else:
        secret_key = secrets.token_bytes(32)
        _secure_write(secret_path, secret_key)

    config_path = Path(
        config_path or os.environ.get("OPENVPN_CONFIG_PATH", "/etc/openvpn/server/web.conf")
    ).resolve()
    web_port = int(os.environ.get("OPENVPN_WEB_PORT", "18080"))
    if not 1 <= web_port <= 65535:
        raise ValueError("OPENVPN_WEB_PORT 必须为 1–65535")
    service_unit = service_unit if service_unit is not None else os.environ.get(
        "OPENVPN_SERVICE_UNIT", "openvpn-server@web.service"
    )
    if service_unit and service_unit != "openvpn-server@web.service":
        raise ValueError("当前特权助手只允许控制 openvpn-server@web.service")
    if service_unit and config_path != Path("/etc/openvpn/server/web.conf"):
        raise ValueError("当前特权助手只允许写入 /etc/openvpn/server/web.conf")

    generated_setup_token = setup_token or os.environ.get("OPENVPN_WEB_SETUP_TOKEN") or secrets.token_urlsafe(24)
    app = Flask(__name__)
    app.secret_key = secret_key
    app.config.update(
        DATA_DIR=data_dir,
        CONFIG_PATH=config_path,
        PROFILES_DIR=profiles_dir,
        SERVICE_UNIT=service_unit,
        WEB_PORT=web_port,
        HELPER_PATH=os.environ.get("OPENVPN_WEB_HELPER", OPENVPN_HELPER),
        SETUP_TOKEN=generated_setup_token,
        MAX_CONTENT_LENGTH=PROFILE_MAX_BYTES + 16 * 1024,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    auth_path = data_dir / "auth.json"
    settings_path = data_dir / "settings.json"
    logger = logging.getLogger("openvpn_web")

    if not auth_path.exists():
        logger.warning("Initial setup token (shown once; use on the local setup page): %s", generated_setup_token)

    def authenticated(handler):
        @wraps(handler)
        def wrapped(*args, **kwargs):
            if not session.get("authenticated"):
                return jsonify({"error": "请先登录"}), 401
            return handler(*args, **kwargs)
        return wrapped

    def csrf_protected(handler):
        @wraps(handler)
        def wrapped(*args, **kwargs):
            token = request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(token, expected):
                return jsonify({"error": "安全令牌无效，请刷新页面后重试"}), 403
            return handler(*args, **kwargs)
        return wrapped

    def load_config():
        return _validate_config(_read_json(settings_path, DEFAULT_CONFIG))

    def run_helper(action, content=None, timeout=30):
        helper_path = app.config["HELPER_PATH"]
        if not Path(helper_path).is_file():
            return None, "特权后端尚未安装。请在项目目录运行：sudo ./install_backend.sh"
        command = ["/usr/bin/sudo", "-n", helper_path, action]
        try:
            result = subprocess.run(
                command,
                input=content,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return None, "调用 OpenVPN 特权后端失败：{}".format(error)
        if result.returncode:
            return None, result.stdout.strip() or "OpenVPN 特权后端执行失败"
        return result.stdout.strip(), None

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return jsonify({"error": "文件过大，客户端配置文件上限为 1 MiB"}), 413

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/session", methods=["GET"])
    def get_session():
        return jsonify({
            "authenticated": bool(session.get("authenticated")),
            "setup_required": not auth_path.exists(),
            "csrf_token": session.get("csrf_token"),
        })

    @app.route("/api/setup", methods=["POST"])
    def setup():
        payload = request.get_json(silent=True) or {}
        password = payload.get("password")
        token = payload.get("setup_token")
        if not isinstance(password, str) or len(password) < 12:
            return jsonify({"error": "管理员密码至少需要 12 个字符"}), 400
        if not isinstance(token, str) or not hmac.compare_digest(token, app.config["SETUP_TOKEN"]):
            return jsonify({"error": "初始化令牌无效"}), 403
        with SETUP_LOCK:
            if auth_path.exists():
                return jsonify({"error": "管理员已初始化"}), 409
            encoded = json.dumps(_password_record(password)).encode("utf-8")
            _secure_write(auth_path, encoded)
        session.clear()
        session.permanent = True
        session["authenticated"] = True
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify({"ok": True, "csrf_token": session["csrf_token"]})

    @app.route("/api/login", methods=["POST"])
    def login():
        payload = request.get_json(silent=True) or {}
        password = payload.get("password")
        record = _read_json(auth_path, None)
        if not isinstance(password, str) or not isinstance(record, dict) or not _verify_password(password, record):
            return jsonify({"error": "密码错误"}), 401
        session.clear()
        session.permanent = True
        session["authenticated"] = True
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify({"ok": True, "csrf_token": session["csrf_token"]})

    @app.route("/api/logout", methods=["POST"])
    @authenticated
    @csrf_protected
    def logout():
        session.clear()
        return jsonify({"ok": True})

    @app.route("/api/config", methods=["GET"])
    @authenticated
    def get_config():
        return jsonify({
            "config": load_config(),
            "config_path": str(config_path),
            "generated_config": _render_openvpn_config(load_config(), config_path),
        })

    @app.route("/api/config", methods=["PUT"])
    @authenticated
    @csrf_protected
    def save_config():
        payload = request.get_json(silent=True)
        try:
            config = _validate_config(payload)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        _secure_write(settings_path, json.dumps(config, indent=2).encode("utf-8"))
        rendered = _render_openvpn_config(config, config_path).encode("utf-8")
        if service_unit:
            _, error = run_helper("write-config", rendered.decode("utf-8"))
            if error:
                return jsonify({"error": "配置已保存在网页管理器中，但写入系统配置失败：{}".format(error)}), 503
        else:
            try:
                _secure_write(config_path, rendered)
            except OSError as error:
                logger.exception("Could not write OpenVPN configuration")
                return jsonify({"error": "配置已保存，但写入 OpenVPN 文件失败：{}".format(error)}), 500
        return jsonify({"ok": True, "config": config, "generated_config": rendered.decode("utf-8")})

    @app.route("/api/service", methods=["GET"])
    @authenticated
    def service_status():
        if not service_unit:
            return jsonify({"configured": False, "active": False, "message": "服务控制尚未配置"})
        status, error = run_helper("status", timeout=8)
        if error:
            return jsonify({
                "configured": True,
                "active": False,
                "unit": service_unit,
                "message": error,
            }), 503
        return jsonify({
            "configured": True,
            "active": status == "active",
            "unit": service_unit,
            "status": status,
            "message": status,
        })

    @app.route("/api/service/<action>", methods=["POST"])
    @authenticated
    @csrf_protected
    def control_service(action):
        if action not in ("start", "stop", "restart"):
            return jsonify({"error": "不支持的服务操作"}), 404
        if not service_unit:
            return jsonify({"error": "当前未启用 OpenVPN systemd 后端"}), 503
        if action in ("start", "restart"):
            config = load_config()
            rendered = _render_openvpn_config(config, config_path)
            _, error = run_helper("init-pki", timeout=90)
            if error:
                return jsonify({"error": "准备服务端证书失败：{}".format(error)}), 503
            _, error = run_helper("write-config", rendered)
            if error:
                return jsonify({"error": "写入服务端配置失败：{}".format(error)}), 503
            _secure_write(settings_path, json.dumps(config, indent=2).encode("utf-8"))
        output, error = run_helper(action, timeout=90)
        if error:
            return jsonify({"error": "OpenVPN 服务操作失败：{}".format(error)}), 500
        return jsonify({"ok": True, "message": output or "操作已完成"})

    @app.route("/api/profiles", methods=["GET"])
    @authenticated
    def list_profiles():
        items = []
        for path in sorted(profiles_dir.glob("*.ovpn")):
            stat = path.stat()
            metadata = _read_json(path.with_suffix(".json"), {})
            items.append({
                "id": path.stem,
                "name": metadata.get("name", path.stem),
                "bytes": stat.st_size,
                "updated_at": int(stat.st_mtime),
            })
        return jsonify({"profiles": items})

    @app.route("/api/profiles", methods=["POST"])
    @authenticated
    @csrf_protected
    def add_profile():
        payload = request.get_json(silent=True) or {}
        name = payload.get("name")
        content = payload.get("content")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
            return jsonify({"error": "客户端名称长度需为 1–64 个字符"}), 400
        if not isinstance(content, str) or not content.strip():
            return jsonify({"error": "请提供 .ovpn 配置内容"}), 400
        encoded = content.encode("utf-8")
        if len(encoded) > PROFILE_MAX_BYTES or b"\x00" in encoded:
            return jsonify({"error": "客户端配置无效或超过 1 MiB"}), 400
        if not re.search(r"(?m)^\s*client\s*$", content):
            return jsonify({"error": "配置中必须包含 client 指令"}), 400
        profile_id = secrets.token_hex(16)
        _secure_write(profiles_dir / (profile_id + ".ovpn"), encoded)
        _secure_write(
            profiles_dir / (profile_id + ".json"),
            json.dumps({"name": name.strip()}).encode("utf-8"),
        )
        return jsonify({"ok": True, "id": profile_id})

    @app.route("/api/profiles/generate", methods=["POST"])
    @authenticated
    @csrf_protected
    def generate_profile():
        payload = request.get_json(silent=True) or {}
        name = payload.get("name")
        remote = payload.get("remote")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name):
            return jsonify({"error": "客户端名称只能包含字母、数字、下划线和连字符，长度为 1–32"}), 400
        try:
            remote = _validate_remote_address(remote)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        for profile_path in profiles_dir.glob("*.json"):
            metadata = _read_json(profile_path, {})
            if metadata.get("generated") and metadata.get("name") == name:
                return jsonify({"error": "此客户端名称已签发，请换一个名称"}), 409
        config = load_config()
        request_data = json.dumps({
            "name": name,
            "remote": remote,
            "port": config["port"],
            "protocol": config["protocol"],
        })
        _, error = run_helper("init-pki", timeout=90)
        if error:
            return jsonify({"error": "准备服务端 CA 失败：{}".format(error)}), 503
        output, error = run_helper("issue-client", request_data, timeout=120)
        if error:
            if "password is required" in error.lower() or "not allowed" in error.lower():
                return jsonify({
                    "error": "客户端签发后端尚未更新，请在项目目录运行 sudo ./install_backend.sh 后重试"
                }), 503
            return jsonify({"error": "生成客户端配置失败：{}".format(error)}), 503
        try:
            result = json.loads(output)
            content = result["profile"]
        except (TypeError, ValueError, KeyError):
            logger.error("OpenVPN helper returned an invalid client profile")
            return jsonify({"error": "客户端配置生成失败：后端返回格式无效"}), 500
        if not isinstance(content, str) or not content.startswith("client\n") or len(content.encode("utf-8")) > PROFILE_MAX_BYTES:
            logger.error("OpenVPN helper returned an invalid client profile")
            return jsonify({"error": "客户端配置生成失败：配置内容无效"}), 500
        profile_id = secrets.token_hex(16)
        _secure_write(profiles_dir / (profile_id + ".ovpn"), content.encode("utf-8"))
        _secure_write(
            profiles_dir / (profile_id + ".json"),
            json.dumps({"name": name, "generated": True}).encode("utf-8"),
        )
        return jsonify({"ok": True, "id": profile_id, "name": name})

    @app.route("/api/profiles/<profile_id>/download", methods=["GET"])
    @authenticated
    def download_profile(profile_id):
        if not re.fullmatch(r"[a-f0-9]{32}", profile_id):
            return jsonify({"error": "客户端配置不存在"}), 404
        profile_path = profiles_dir / (profile_id + ".ovpn")
        metadata = _read_json(profiles_dir / (profile_id + ".json"), {})
        if not profile_path.is_file():
            return jsonify({"error": "客户端配置不存在"}), 404
        download_name = "{}.ovpn".format(
            re.sub(r"[^A-Za-z0-9_-]", "_", metadata.get("name", "client"))
        )
        options = {"download_name": download_name}
        if "download_name" not in inspect.signature(send_file).parameters:
            options = {"attachment_filename": download_name}
        return send_file(
            str(profile_path),
            mimetype="application/x-openvpn-profile",
            as_attachment=True,
            **options
        )

    @app.route("/api/profiles/<profile_id>", methods=["DELETE"])
    @authenticated
    @csrf_protected
    def delete_profile(profile_id):
        if not re.fullmatch(r"[a-f0-9]{32}", profile_id):
            return jsonify({"error": "客户端配置不存在"}), 404
        profile_path = profiles_dir / (profile_id + ".ovpn")
        metadata_path = profiles_dir / (profile_id + ".json")
        if not profile_path.is_file():
            return jsonify({"error": "客户端配置不存在"}), 404
        profile_path.unlink()
        try:
            metadata_path.unlink()
        except FileNotFoundError:
            pass
        return jsonify({"ok": True})

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="127.0.0.1", port=application.config["WEB_PORT"], debug=False)
