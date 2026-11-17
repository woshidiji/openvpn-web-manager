#!/bin/sh
set -eu

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
version="${1:-$(date +%Y%m%d)}"
case "$version" in
    *[!A-Za-z0-9._-]* | "") echo "版本名只允许字母、数字、点、下划线和连字符。" >&2; exit 2 ;;
esac

dist_dir="$project_dir/dist"
mkdir -p "$dist_dir"
archive="$dist_dir/openvpn-web-manager-${version}.tar.gz"
package="$dist_dir/openvpn-web-manager_${version}_all.deb"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT HUP INT TERM
rm -f -- "$archive"
tar -czf "$archive" -C "$project_dir" \
    --transform='s,^,openvpn-web-manager/,' \
    README.md requirements.txt app.py openvpn_web_helper.py \
    install_backend.sh package.sh test_app.py templates static debian
chmod 0644 "$archive"

root="$stage/root"
install -d "$root/DEBIAN" "$root/usr/lib/openvpn-web/templates" "$root/usr/lib/openvpn-web/static"
install -m 0644 "$project_dir/app.py" "$project_dir/README.md" "$project_dir/requirements.txt" \
    "$root/usr/lib/openvpn-web/"
install -m 0755 "$project_dir/openvpn_web_helper.py" "$root/usr/lib/openvpn-web/openvpn_web_helper.py"
install -m 0644 "$project_dir/templates/index.html" "$root/usr/lib/openvpn-web/templates/"
install -m 0644 "$project_dir/static/app.js" "$project_dir/static/style.css" "$root/usr/lib/openvpn-web/static/"
install -d "$root/usr/lib/systemd/system" "$root/usr/share/openvpn-web" "$root/usr/share/doc/openvpn-web-manager"
install -m 0644 "$project_dir/debian/openvpn-web.service" "$root/usr/lib/systemd/system/"
install -m 0644 "$project_dir/debian/openvpn-web.sudoers" "$root/usr/share/openvpn-web/"
install -m 0644 "$project_dir/install_backend.sh" "$root/usr/share/openvpn-web/"
install -m 0644 "$project_dir/README.md" "$root/usr/share/doc/openvpn-web-manager/"
install -m 0755 "$project_dir/debian/postinst" "$root/DEBIAN/postinst"
install -m 0755 "$project_dir/debian/prerm" "$root/DEBIAN/prerm"
install -m 0755 "$project_dir/debian/postrm" "$root/DEBIAN/postrm"
cat >"$root/DEBIAN/control" <<EOF
Package: openvpn-web-manager
Version: ${version}
Section: net
Priority: optional
Architecture: all
Depends: adduser, openvpn, openssl, python3, python3-flask, python3-waitress, sudo, systemd
Maintainer: OpenVPN Web Manager
Description: Local web management interface for OpenVPN server
 Configure OpenVPN server and generate client profiles from a local web
 interface. OpenVPN itself is installed as a system package dependency.
EOF
dpkg-deb --root-owner-group --build "$root" "$package"
chmod 0644 "$package"
printf 'Source archive: %s\nInstallable package: %s\n' "$archive" "$package"
