#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 sudo 运行：sudo ./install_backend.sh" >&2
    exit 1
fi

web_user="${SUDO_USER:-${OPENVPN_WEB_USER:-}}"
if [ -z "$web_user" ] || ! id "$web_user" >/dev/null 2>&1; then
    echo "无法确定 Web 应用运行用户。请使用 sudo ./install_backend.sh，或设置 OPENVPN_WEB_USER。" >&2
    exit 1
fi
case "$web_user" in
    *[!A-Za-z0-9_-]* | [0-9]*)
        echo "Web 用户名格式无效。" >&2
        exit 1
        ;;
esac

systemctl_bin="$(command -v systemctl)"
openvpn_bin="$(command -v openvpn)"
if [ -z "$systemctl_bin" ] || [ -z "$openvpn_bin" ]; then
    echo "请先安装 systemd 和 OpenVPN。" >&2
    exit 1
fi
if ! "$systemctl_bin" cat openvpn-server@.service >/dev/null 2>&1; then
    echo "找不到 openvpn-server@.service systemd 模板单元。" >&2
    exit 1
fi

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
install -d -o root -g root -m 0755 /usr/lib/openvpn-web
install -o root -g root -m 0755 "$project_dir/openvpn_web_helper.py" /usr/lib/openvpn-web/openvpn_web_helper.py
install -d -o root -g root -m 0755 /etc/openvpn/server

sudoers_tmp="$(mktemp /etc/sudoers.d/.openvpn-web.XXXXXX)"
trap 'rm -f "$sudoers_tmp"' EXIT HUP INT TERM
cat >"$sudoers_tmp" <<EOF
# Allow the web manager UID to control only its fixed OpenVPN instance.
${web_user} ALL=(root) NOPASSWD: /usr/lib/openvpn-web/openvpn_web_helper.py init-pki, /usr/lib/openvpn-web/openvpn_web_helper.py write-config, /usr/lib/openvpn-web/openvpn_web_helper.py issue-client, /usr/lib/openvpn-web/openvpn_web_helper.py status, /usr/lib/openvpn-web/openvpn_web_helper.py start, /usr/lib/openvpn-web/openvpn_web_helper.py stop, /usr/lib/openvpn-web/openvpn_web_helper.py restart
EOF
chmod 0440 "$sudoers_tmp"
visudo -cf "$sudoers_tmp"
mv "$sudoers_tmp" /etc/sudoers.d/openvpn-web
trap - EXIT HUP INT TERM

echo "已安装最小权限 OpenVPN 后端，授权用户：$web_user"
echo "点击页面的“启动”即可生成本机服务端证书并启动 openvpn-server@web.service。"
