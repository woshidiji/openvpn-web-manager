import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from app import DEFAULT_CONFIG, _render_openvpn_config, _validate_remote_address, create_app
from openvpn_web_helper import generate_client, validate_config


class OpenVPNWebTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.app = create_app(
            data_dir=str(self.root / "data"),
            config_path=str(self.root / "openvpn" / "server.conf"),
            service_unit="",
            setup_token="test-setup-token",
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temporary.cleanup()

    def setup_admin(self):
        response = self.client.post("/api/setup", json={
            "password": "a-very-long-test-password",
            "setup_token": "test-setup-token",
        })
        self.assertEqual(response.status_code, 200)
        return response.get_json()["csrf_token"]

    def test_setup_token_is_required_and_session_is_authenticated(self):
        bad = self.client.post("/api/setup", json={
            "password": "a-very-long-test-password",
            "setup_token": "wrong",
        })
        self.assertEqual(bad.status_code, 403)
        token = self.setup_admin()
        self.assertTrue(token)
        self.assertTrue(self.client.get("/api/session").get_json()["authenticated"])

    def test_config_is_validated_and_written_with_private_permissions(self):
        csrf = self.setup_admin()
        updated = dict(DEFAULT_CONFIG, port=443, network="10.10.0.0/24", dns=["9.9.9.9"])
        response = self.client.put(
            "/api/config", json=updated, headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(response.status_code, 200)
        config_path = self.root / "openvpn" / "server.conf"
        self.assertIn("port 443", config_path.read_text(encoding="utf-8"))
        self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)
        self.assertIn("ncp-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", response.get_json()["generated_config"])

    def test_invalid_network_is_rejected(self):
        csrf = self.setup_admin()
        updated = dict(DEFAULT_CONFIG, network="not-a-network")
        response = self.client.put(
            "/api/config", json=updated, headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse((self.root / "openvpn" / "server.conf").exists())

    def test_client_profile_upload_download_and_delete(self):
        csrf = self.setup_admin()
        content = "client\ndev tun\nremote vpn.example.test 1194 udp\n"
        added = self.client.post(
            "/api/profiles",
            json={"name": "laptop", "content": content},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(added.status_code, 200)
        profile_id = added.get_json()["id"]
        listed = self.client.get("/api/profiles").get_json()["profiles"]
        self.assertEqual(listed[0]["name"], "laptop")
        downloaded = self.client.get("/api/profiles/{}/download".format(profile_id))
        self.assertEqual(downloaded.data.decode("utf-8"), content)
        downloaded.close()
        removed = self.client.delete(
            "/api/profiles/{}".format(profile_id),
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(removed.status_code, 200)
        self.assertEqual(self.client.get("/api/profiles").get_json()["profiles"], [])

    def test_mutations_require_csrf_and_service_is_disabled_by_default(self):
        self.setup_admin()
        rejected = self.client.post("/api/service/start")
        self.assertEqual(rejected.status_code, 403)
        status = self.client.get("/api/service")
        self.assertFalse(status.get_json()["configured"])

    def test_saved_auth_record_does_not_contain_plaintext_password(self):
        self.setup_admin()
        auth_data = json.loads((self.root / "data" / "auth.json").read_text(encoding="utf-8"))
        self.assertNotIn("a-very-long-test-password", json.dumps(auth_data))

    def test_helper_accepts_generated_config_and_rejects_extra_directives(self):
        config_path = Path("/etc/openvpn/server/web.conf")
        rendered = _render_openvpn_config(DEFAULT_CONFIG, config_path)
        validate_config(rendered)
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                validate_config(rendered.replace("verb 3", "script-security 2\nverb 3"))

    def test_openssl_can_generate_ca_using_legacy_config_options(self):
        config = self.root / "ca.cnf"
        config.write_text(
            "[req]\nprompt = no\ndistinguished_name = ca_dn\n"
            "x509_extensions = v3_ca\n[ca_dn]\nCN = Test CA\n"
            "[v3_ca]\nbasicConstraints = critical,CA:TRUE\n"
            "keyUsage = critical,keyCertSign,cRLSign\n",
            encoding="ascii",
        )
        result = subprocess.run([
            "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-sha256", "-days", "1",
            "-config", str(config), "-extensions", "v3_ca",
            "-keyout", str(self.root / "ca.key"), "-out", str(self.root / "ca.crt"),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_remote_address_validation(self):
        self.assertEqual(_validate_remote_address("vpn.example.com"), "vpn.example.com")
        self.assertEqual(_validate_remote_address("203.0.113.10"), "203.0.113.10")
        for value in ("bad host", "-example.com", "", "a" * 254):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _validate_remote_address(value)

    def test_client_generation_creates_downloadable_profile(self):
        helper = self.root / "fake-helper"
        helper.write_text("# test helper\n", encoding="ascii")
        with patch.dict(os.environ, {"OPENVPN_WEB_HELPER": str(helper)}):
            app = create_app(
                data_dir=str(self.root / "generated-data"),
                service_unit="openvpn-server@web.service",
                setup_token="test-setup-token",
            )
        client = app.test_client()
        setup = client.post("/api/setup", json={
            "password": "a-very-long-test-password",
            "setup_token": "test-setup-token",
        })
        csrf = setup.get_json()["csrf_token"]
        profile_content = "client\ndev tun\nremote vpn.example.com 1194 udp\n"

        def fake_run(command, **_kwargs):
            if command[-1] == "issue-client":
                return subprocess.CompletedProcess(command, 0, json.dumps({"profile": profile_content}))
            return subprocess.CompletedProcess(command, 0, "")

        with patch("app.subprocess.run", side_effect=fake_run):
            response = client.post(
                "/api/profiles/generate",
                json={"name": "laptop_01", "remote": "vpn.example.com"},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        profile_id = response.get_json()["id"]
        download = client.get("/api/profiles/{}/download".format(profile_id))
        self.assertEqual(download.data.decode("utf-8"), profile_content)
        download.close()

    def test_client_certificate_is_signed_by_local_ca(self):
        pki = self.root / "pki"
        pki.mkdir()
        ca_config = self.root / "ca.cnf"
        ca_config.write_text(
            "[req]\nprompt = no\ndistinguished_name = ca_dn\n"
            "x509_extensions = v3_ca\n[ca_dn]\nCN = Test CA\n"
            "[v3_ca]\nbasicConstraints = critical,CA:TRUE\n"
            "keyUsage = critical,keyCertSign,cRLSign\n",
            encoding="ascii",
        )
        result = subprocess.run([
            "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-sha256", "-days", "1",
            "-config", str(ca_config), "-extensions", "v3_ca",
            "-keyout", str(pki / "ca.key"), "-out", str(pki / "ca.crt"),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        (pki / "ta.key").write_text("test tls-crypt key\n", encoding="ascii")

        with patch("openvpn_web_helper.PKI_PATH", pki):
            with patch("sys.stdin", StringIO(json.dumps({
                "name": "laptop_01",
                "remote": "vpn.example.com",
                "port": 1194,
                "protocol": "udp",
            }))):
                output = StringIO()
                with redirect_stdout(output):
                    generate_client()

        profile = json.loads(output.getvalue())["profile"]
        self.assertIn("remote vpn.example.com 1194 udp", profile)
        self.assertIn("<key>", profile)
        self.assertIn("<tls-crypt>\ntest tls-crypt key\n</tls-crypt>", profile)
        cert = profile.split("<cert>\n", 1)[1].split("\n</cert>", 1)[0] + "\n"
        cert_path = self.root / "client.crt"
        cert_path.write_text(cert, encoding="ascii")
        verify = subprocess.run(
            ["/usr/bin/openssl", "verify", "-purpose", "sslclient", "-CAfile",
             str(pki / "ca.crt"), str(cert_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=10, check=False,
        )
        self.assertEqual(verify.returncode, 0, verify.stdout)

    def test_service_start_explains_when_privileged_backend_is_missing(self):
        helper_path = str(self.root / "missing-helper")
        with patch.dict(os.environ, {"OPENVPN_WEB_HELPER": helper_path}):
            app = create_app(
                data_dir=str(self.root / "managed-data"),
                service_unit="openvpn-server@web.service",
                setup_token="test-setup-token",
            )
        client = app.test_client()
        setup = client.post("/api/setup", json={
            "password": "a-very-long-test-password",
            "setup_token": "test-setup-token",
        })
        csrf = setup.get_json()["csrf_token"]
        response = client.post("/api/service/start", headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 503)
        self.assertIn("sudo ./install_backend.sh", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
