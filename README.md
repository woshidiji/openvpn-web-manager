# OpenVPN Web 管理

一个本机优先的 OpenVPN 服务端配置管理 MVP：提供管理员登录、结构化服务端配置生成、客户端 `.ovpn` 文件管理，以及固定 systemd 服务控制。

## 运行

需要 Python 3.8+、Flask 3.x 和 Linux。首次运行时会生成一次性初始化令牌，并写入启动终端日志：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python app.py
```

访问 <http://127.0.0.1:18080>，用终端中显示的令牌设置管理员密码。服务固定绑定 `127.0.0.1`。不要直接将应用端口暴露到局域网或公网；如需远程管理，应由管理员自行配置经过认证的 SSH 隧道或反向代理。

## 打包与迁移

在 Linux（GNU tar）环境中生成源码包：

```bash
./package.sh
```

默认生成 `dist/openvpn-web-manager-<日期>.tar.gz`，也可以指定包名版本：`./package.sh 1.0.0`。包内包含应用源代码、静态文件、测试和安装说明；**不会打包** `data/`、管理员凭据、客户端配置/私钥、系统 CA 私钥或服务端密钥。不要把这些机密塞进通用软件包。

该脚本也会生成可直接安装的 Debian/Ubuntu `.deb` 包 `dist/openvpn-web-manager_<版本>_all.deb`。当前包以 Ubuntu 20.04 amd64 环境构建，并通过系统依赖安装 OpenVPN、OpenSSL、Flask、Waitress 和 systemd（不内嵌或复制 OpenVPN 二进制）。目标机联网并使用支持这些依赖的软件源时：

```bash
sudo apt install ./openvpn-web-manager_<版本>_all.deb
```

安装程序会创建隔离的 `openvpn-web` 系统用户、安装仅允许操作固定 OpenVPN unit 的 sudo 规则，并启用 Web 管理 systemd 服务。安装后访问 <http://127.0.0.1:18080>；初始化令牌可通过以下命令读取：

```bash
sudo journalctl -u openvpn-web.service -n 50 --no-pager
```

`dpkg -i` 本身不会自动下载依赖；请使用 `apt install ./包名.deb`，或先安装包依赖。首次启动时在目标机重新创建管理员密码和服务端 CA；原服务器签发的客户端配置不会信任新服务器 CA，需要在新服务器重新签发并分发。

如果确实要迁移管理员登录和客户端文件，请在旧机器停止 Web 应用后，单独通过加密传输备份整个数据目录，并仅恢复到受信任目标机的 `/var/lib/openvpn-web`。该目录包含客户端私钥和登录验证数据，必须保持目录 `0700`、私有文件 `0600`，并确认恢复后 `openvpn-web` 用户对目录有访问权限。迁移旧数据不会迁移 `/etc/openvpn/server/web-pki` 中的服务端 CA/密钥。卸载软件包时保留 `/var/lib/openvpn-web`。

### 启用网页服务控制

网页进程保持普通用户运行。由系统管理员在项目目录中安装一个 root 所有、仅允许操作固定 OpenVPN 实例的后端助手：

```bash
sudo ./install_backend.sh
```

安装完成后刷新管理页面即可。页面的“启动”按钮会生成本机 CA、服务端证书和 `tls-crypt` 密钥（仅首次生成），把经过白名单校验的配置写入 `/etc/openvpn/server/web.conf`，再启动 `openvpn-server@web.service`。“客户端配置”页可签发客户端证书并打包为内嵌证书/私钥的 `.ovpn` 文件。此助手不会让 Web 应用以 root 身份运行，也不会执行任意命令。

如当前用户没有 sudo 权限，请让系统管理员执行安装命令。更新特权助手或 sudo 授权后需再次运行安装脚本。卸载授权时删除 `/etc/sudoers.d/openvpn-web` 和 `/usr/local/libexec/openvpn-web-helper`。

可选环境变量：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `OPENVPN_WEB_DATA_DIR` | `./data` | 存放认证信息、设置及客户端配置；目录权限收紧为 `0700`，私密文件为 `0600` |
| `OPENVPN_CONFIG_PATH` | `/etc/openvpn/server/web.conf` | 生成的 OpenVPN 服务端配置文件路径 |
| `OPENVPN_WEB_PORT` | `18080` | 本机 Web 页面端口 |
| `OPENVPN_WEB_SETUP_TOKEN` | 随机生成 | 自行指定首次初始化令牌；如未指定，随机令牌只显示在本机启动日志 |
| `OPENVPN_SERVICE_UNIT` | `openvpn-server@web.service` | 固定服务单元；特权助手只允许控制此实例 |

## OpenVPN 服务接入

页面服务控制绑定到 `openvpn-server@web.service`。发行版需提供 `openvpn-server@.service` 模板。生成的配置使用 OpenVPN 2.4 兼容的 `ncp-ciphers`。

首次启动自动生成本机 CA 和服务端证书。客户端页面可使用本机 CA 签发客户端证书，或导入已有 `.ovpn` 文件。生成的文件含有客户端私钥，并以明文保存在本机数据目录中。移除生成的客户端配置只会删除下载副本，不会吊销已签发证书；若需吊销，应通过独立的证书吊销流程操作。服务器要从公网接收连接，还需自行配置防火墙、IP 转发和 NAT；网页启动服务不会自动修改这些网络规则。

## 测试

```bash
python3 -m unittest -v
```
