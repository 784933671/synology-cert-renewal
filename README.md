# DS218+ / DNSPod 证书自动续期

在群晖本机为 `ttxli.cn` 现有证书自动续期并部署。使用 Let's Encrypt 和 DNSPod DNS 验证；本机部署优先使用 DSM 的 `synowebapi`，无需开放公网 80 端口。包装器使用 Python 3.8 以上标准库，无第三方 Python 依赖。

已在 NAS 完成安装、首次签发、本机导入、公网 HTTPS 校验、每日任务实测及故障邮件收件验收；部署方式、验收结果和后续复查见 [部署验收记录](DEPLOYMENT.md)。本地测试与真实签发、导入和通知验收分开记录。

## 安装前准备

1. 在“控制面板 → 信息中心”确认 DSM 为 6.2.4 或 7.x。若没有 Python 3.8 以上，在套件中心安装或更新 Python3。
2. 在“控制面板 → 安全性 → 证书”找到目标证书，记录其覆盖域名和服务绑定，确保描述唯一。本机 API 模式可以保留包含空格或中文的现有描述；临时管理员模式要求英文、数字、横线或下划线组合，例如 `ttxli-cn`。
3. 首次建议在该页面导出证书，保存至安全位置。工具后续也会自动备份，最多保留最近 5 份不同证书或配置版本。
4. 确认 NAS 能访问 DNSPod API、Let's Encrypt 和 GitHub，系统时间准确。
5. 新配置在存在 `synowebapi` 时使用本机 API 模式，以 root 身份指定现有证书 ID 导入，不保存管理员密码、不创建临时账号，也不修改强制双重验证策略。没有本机命令时使用原 acme.sh 临时管理员模式；该模式遇到强制双重验证或已有 `sc-acmesh-tmp` 账号会停止。旧配置未填写 `deployment_method` 时继续采用原模式；需要切换时重新运行 `configure`。

## 腾讯云 API 权限

在腾讯云访问管理中创建专用子账号和 API 密钥，仅给 `ttxli.cn` 对应 DNSPod 域名资源授予以下操作：

- `dnspod:DescribeRecordList`
- `dnspod:CreateRecord`
- `dnspod:DescribeRecordFilterList`
- `dnspod:DeleteRecord`

`dns-policy.example.json` 提供策略模板；将资源中的主账号 UIN 和 DNSPod DomainId 替换为控制台真实值，再绑定给子账号。模板中的资源标识不是域名字符串。实际授权需要在 DNSPod/CAM 中验证。

插件仅添加、清理验证用 TXT 记录，但上述 CAM 授权是域名资源级权限，并非“只能修改 TXT”。密钥在 NAS 交互配置时输入，不要发送到聊天、提交到代码仓库或写进任务命令。

## 首次安装

先检查是否已有 acme.sh 容器或续期任务，确认不会重复更新同一张证书后再安装。本机 NAS 的检查结果记录在部署进度中；目录存在本身不代表正在运行续期任务。

在群晖“控制面板 → 终端机和 SNMP”中开启 SSH。局域网安装不需要新增公网端口映射。通过 File Station 将整个安装包放到 NAS 的一个文件夹，然后从电脑连接 NAS：

```sh
ssh -p 22 你的用户名@NAS局域网IP
sudo -i
cd /你在NAS上放置安装包的实际路径
sh install.sh
```

若 SSH 使用其他端口，请替换 `22`。远程安装时按实际可达入口使用 `ssh -p 外部SSH端口 用户名@ttxli.cn`；NAS 内部端口与路由器外部端口可能不同，不能使用 DSM 网页端口代替。

安装脚本会检查 DSM、Python 和本机工具，下载并校验固定版本 acme.sh。已有安装目录时会停止，不覆盖配置和证书。

安装位置为 `/usr/local/share/synology-cert-renewal`。安装器不创建定时任务、不自动签发、不修改系统证书。

进入交互配置：

```sh
PYTHON=$(cat /usr/local/share/synology-cert-renewal/python-path)
"$PYTHON" -I /usr/local/share/synology-cert-renewal/certctl.py --home /usr/local/share/synology-cert-renewal configure
```

按提示选择现有证书，并填写邮箱、腾讯云 SecretId/SecretKey 和需要检查的 HTTPS 服务端点。只有临时管理员模式需要填写 DSM 本机 HTTP 端口，默认为 `5000`；HTTPS 常见为 `5001`，以 NAS 的实际设置为准。程序沿用选中证书已有的 DNS 域名，不自动增加泛域名或扩大覆盖范围。

列表中缺失、损坏、没有 DNS SAN 或只有 IP SAN 的证书会显示“不可用”，不妨碍选择其他有效证书；选中的目标仍需通过完整校验。

本机 API 模式直接调用 `synowebapi`，临时管理员模式只连接 NAS 本机 HTTP 回环地址。导入使用指定的现有 ID，并检查描述、默认证书和服务绑定不变；导入材料使用私有临时副本，避免接口消耗 ACME 源文件。HTTPS 验证端点使用实际服务地址、端口及域名，例如本机 DSM 可使用 `127.0.0.1`、`5001`、证书实际覆盖的域名。若证书绑定在反向代理服务上，应添加相应服务端点。服务器名称用于 TLS SNI，通配符证书应填写真实子域名。

先检查，再首次运行：

```sh
"$PYTHON" -I /usr/local/share/synology-cert-renewal/certctl.py --home /usr/local/share/synology-cert-renewal check
"$PYTHON" -I /usr/local/share/synology-cert-renewal/certctl.py --home /usr/local/share/synology-cert-renewal run
"$PYTHON" -I /usr/local/share/synology-cert-renewal/certctl.py --home /usr/local/share/synology-cert-renewal status
```

`check` 不签发、不部署，不修改 DNS 或 DSM 业务状态；可能写入本工具日志和互斥锁。`run` 按需签发或续期，再部署并检查证书指纹。首次部署失败时，再次执行 `run` 可重试已有证书，不需要强制重新申请。

如果本地候选证书、私钥或证书链已经损坏，或候选剩余有效期不足 14 天，工具会先验证历史配置，再隔离该域名的 ACME 工作目录并重新申请，避免被尚未到期的续期时间跳过。原有服务证书继续保留，只有新候选通过校验后才部署。恢复申请间隔至少 24 小时，连续最多 3 次；取得有效候选即清除恢复计数，后续部署失败只重试部署。

配置、私钥、日志和备份均保存在仅 root 可访问的安装目录中。`acme.sh` 也会持久保存 API 密钥，因此备份整个目录时必须同样保护。初始化完成后可关闭 SSH；DSM 任务计划仍可运行。

## 每日自动运行和故障通知

在 DSM“控制面板 → 任务计划”新建“计划的任务 → 用户定义的脚本”：

- 用户：`root`。
- 计划：每天 `03:17`，或 NAS 固定开机时段。
- 用户定义的脚本：

```sh
/bin/sh /usr/local/share/synology-cert-renewal/run-task.sh
```

启动脚本使用安装时探测到的 Python 绝对路径。不要依赖任务计划的交互式环境变量，也不要把 API 密钥写进任务设置。

在 DSM 中配置可用的邮件发送方式，任务设置勾选“通过电子邮件发送运行详情”和“仅当脚本异常终止时发送运行详情”。证书注册邮箱不会自动成为 DSM 的任务通知邮箱；通知邮箱需要在任务中单独填写。保存后点击“运行”，确认任务成功。另建一个临时通知测试任务，脚本填写 `exit 1`，使用相同邮件设置并手动运行，确认失败邮件送达后删除测试任务。不要修改正式任务来模拟故障。

工具每天只检查是否需要续期，不会每天强制签发。任务互斥执行，部署后核验目标 HTTPS 服务实际出示的证书，失败以非零退出码报告。不要同时运行其他更新同一张证书的脚本或 DSM 任务。

## 验收和故障处理

首次配置后确认：DNSPod 验证 TXT 记录已清理；群晖证书有效期更新；服务绑定与原来一致；浏览器访问目标域名时证书正确。NAS 重启后再手动运行一次任务；DSM 或 Python 套件升级后也要复查任务。Python 路径若发生变化，检查 `python-path` 和 `run-task.sh` 后更新到真实路径。

失败时先看任务详情、`status`、`state/events.log` 和 `state/acme-last.log`；自动备份位于 `state/backups`。DNS 授权失败时检查 DomainId、UIN、子账号策略和 DNSPod 解析托管；DNS 验证失败时确认网络及记录传播。部署失败时核查目标 ID、唯一描述和本机 API 返回状态；临时管理员模式还需核查 DSM HTTP 端口、强制双重验证状态及临时账号。HTTPS 指纹不一致时核对服务绑定、验证端口、SNI 域名和是否经过其他代理。

恢复申请的计数与时间保存在 `state/recovery.json`，隔离的域名工作目录保存在 `state/recovery-backups`，最多保留最近 3 份，其中可能含私钥。达到恢复上限会以非零退出码通知；先检查磁盘、网络及日志，确认原因已解决后，再移除 `state/recovery.json` 并运行任务。不要通过反复清除计数连续申请证书。

若提示存在 `state/deployment-active.json`，说明任务曾异常中断。先暂停任务并核对实际服务证书、目标 ID 和绑定；临时管理员模式还需核实 `sc-acmesh-tmp` 是否为该次任务遗留账号，以及双重验证策略是否正常。确认恢复后，才移除标记并重新执行 `check`。工具不会自动删除来源不明的已有账号。

若提示前次操作后绑定发生变化，根据 `state/backups/` 恢复原绑定；若是你有意调整服务绑定，确认当前状态后重新执行 `configure` 接受新配置。

需要恢复旧证书时，先暂停证书更新任务，在 DSM 的证书页面对同一个目标证书执行“替换现有证书”，从安全备份导入私钥、证书和中间证书，再核对原服务绑定和 HTTPS 访问。不要直接覆盖群晖系统证书目录。

安装器对已有目录会退出。如需更新工具，先暂停任务并备份现有配置和状态，再按经过验证的升级步骤处理；不要删掉目录后重新初始化。acme.sh 固定版本且关闭自动升级，更新后应重新验证临时管理员和证书部署行为。

## 版本和来源

- acme.sh：`3.1.6`。
- 固定提交：`807da6498377ee5e0cf43a78091f46f12dc59a89`。
- 官方源码归档 SHA-256：`ddbe1bcbd1a44a2623a2af167ebdc678669e6e2eb396742f2d1d28e02dc14220`。
- [acme.sh 群晖指南](https://github.com/acmesh-official/acme.sh/wiki/Synology-NAS-Guide)
- [固定版群晖部署源码](https://github.com/acmesh-official/acme.sh/blob/807da6498377ee5e0cf43a78091f46f12dc59a89/deploy/synology_dsm.sh)
- [固定版 DNSPod 插件](https://github.com/acmesh-official/acme.sh/blob/807da6498377ee5e0cf43a78091f46f12dc59a89/dnsapi/dns_tencent.sh)
- [Let's Encrypt DNS 验证](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)
- [Tailscale 本机群晖证书导入实现](https://github.com/tailscale/tailscale/blob/main/cmd/tailscale/cli/configure-synology-cert.go)
- [群晖本机部署原始实现](https://github.com/zaxbux/syno-acme/blob/main/acme.sh/deploy/synology_dsm_local.sh)

`synowebapi` 是 DSM 本机接口；升级 DSM 后需重新验证参数兼容性、服务绑定和实际 HTTPS 生效情况。

本地验证命令（需要 Python3 和 OpenSSL）：

```sh
python3 -m unittest discover -s tests -v
sh -n install.sh
```

离线 ACME 集成测试需要提供安装器所固定提交的源码目录；未指定时这 2 项测试会跳过，其余测试照常运行：

```sh
ACME_TEST_SOURCE=/固定提交的acme.sh源码目录 python3 -m unittest discover -s tests -v
```

共 70 项测试，包含 2 项可选离线集成测试，涵盖证书域名/密钥/链、真实本地 TLS 握手与 SNI、部署失败补偿、损坏候选恢复及频率限制、异常证书列表、绑定保护、输入及权限检查。本机 API 后端还覆盖强制双重验证保持、临时文件被接口消耗、目标 ID/默认状态、错误响应和部署后核验。离线集成测试使用真实 acme.sh 验证续期跳过行为，签发和 DSM 部署仍为模拟且阻断 HTTP 客户端。安装器另验证了固定归档校验、安全解包和已有安装保护。这些验证不代表已经在你的 NAS 上完成签发、服务重载和故障邮件验收。
