# 群晖证书管家 Docker 管理层

中文 Vue 3 页面，采用 DSM 蓝灰布局和较宽的表单留白，支持独立管理员登录、证书与 DNS 凭据配置、续期计划、成功/失败通知邮箱、失败归档、操作审计和密码修改。

## 运行结构

```
内网浏览器 → HTTPS 管理容器（非 root） → 受限 Unix socket
                                      ↓
                    群晖本机桥接 → 原任务 7 / certctl
                                      ↓
                    DNSPod → Let's Encrypt → DSM → 校验/通知
```

Docker 运行前端和管理 API。证书签发、DSM 导入及通知继续使用已部署的本机执行器，保持原任务的恢复机制；容器不再建立第二套续期定时器。无需在网页保存 DSM 管理员密码，也不需要关闭 DSM 双重验证。

## 内网访问边界

- 管理入口使用 `https://ttxli.cn:18443`，仅绑定 NAS 的 `10.10.10.37`，白名单为 `10.10.10.0/24`。网关 `10.10.10.1` 被单独排除，避免公网转发被路由器 SNAT 后伪装为允许的网关来源。
- 容器使用 host 网络，不创建 Docker 发布端口；NAS 原生监督进程维护只针对管理端口的专用链。DSM 会把针对内置 `INPUT` 的写操作重定向到较晚执行的 `DEFAULT_INPUT`，因此本项目把专用跳转置于 `INPUT_FIREWALL` 首条，并核验真实 `INPUT` 的第一条规则无条件跳入 `INPUT_FIREWALL`。只修改本服务的链与跳转，保留其他 DSM/Docker 规则；无法确认顺序时停止管理服务。普通 Linux 则直接使用 `INPUT` 首条。IPv6 的该管理端口单独拒绝，服务本身只监听指定 IPv4。
- API 再按实际 TCP 对端检查 IPv4 网段，不信任代理头，拒绝 `Forwarded`、`X-Forwarded-*`、`X-Real-IP`；同时限制精确 Host、HTTPS Origin 和 CSRF token。禁止通过 DSM 公网反向代理、QuickConnect 或公网端口映射发布此管理入口。
- 路由器和内网 DNS 暂不配置，由用户后续处理；18443 保持不做公网端口映射。不要改腾讯云的公网解析，也不要把管理页发布到现有公网反向代理。
- NAS 本机通过自身 LAN 地址访问是允许的，管理员现有 SSH 隧道也属于这一受信管理路径；这不构成对公网开放管理监听。仅 `/healthz` 额外允许真实回环来源，业务 API 不允许回环来源。
- NAS 仍需向外连接 DNSPod、证书机构及邮件服务。禁止外网访问管理入口，不等于禁止 NAS 出网。

host 网络共享 NAS 网络命名空间，因此不属于网络隔离；容器仍以非 root 身份运行，使用只读根文件系统、移除全部 capability，并启用 no-new-privileges。资源配置绑定一个逻辑 CPU（`cpuset: "0"`）、限制内存为 384 MiB；非 root 用户 UID 10100 的进程数软/硬上限均为 96，每个进程的打开文件数软/硬上限均为 1024。此 NAS 的 DSM 内核不支持 CFS CPU 配额和 PID cgroup 限制，进程上限使用 `ulimits.nproc`，不宣称启用了 PID cgroup 隔离。不挂载 Docker socket、NAS 根目录或完整续期配置。挂载仅包含登录数据库、受限 socket 和管理 HTTPS 所需的最小证书副本。

[Docker host 网络说明](https://docs.docker.com/engine/network/drivers/host/)与[防火墙说明](https://docs.docker.com/engine/network/packet-filtering-firewalls/)解释了此处选择 INPUT 规则而非依赖发布端口默认行为的原因。

## 打开管理页面

浏览器入口为 `https://ttxli.cn:18443`。服务绑定 `10.10.10.37`，但不能改用 `https://10.10.10.37:18443`：证书验证和允许的 Host 都要求管理域名。不开 HTTP 端口，也不通过忽略证书错误完成验收。

客户端需要位于允许的内网，并将 `ttxli.cn` 解析到 `10.10.10.37`。后续可在路由器设置仅内网生效的域名映射；暂不改路由器时，也可只在一台电脑的 hosts 文件增加以下记录，然后仍用域名打开：

```text
10.10.10.37 ttxli.cn
```

macOS 的 hosts 文件是 `/etc/hosts`，Windows 为 `C:\Windows\System32\drivers\etc\hosts`，编辑需要系统管理员权限。该记录也会影响这台电脑通过 `ttxli.cn` 访问其他服务；不再需要时移除。采用路由器 DNS 时，客户端需使用该 DNS，并确认浏览器自定义 DNS/DoH 没有绕过它。当前没有将这些客户端或路由器配置记录为已完成。

## 登录与凭据

无固定默认密码。管理员在私有终端初始化；首次登录必须改密。密码仅保存 scrypt 哈希，Cookie 使用 HttpOnly、Secure、SameSite=Strict，闲置 30 分钟或登录 8 小时后失效。后台状态轮询不延长闲置期限。登录失败限流持久化；退出登录、修改或重置密码撤销会话。

DNSPod 密钥只允许写入，GET 接口只返回是否已配置。浏览器不持久化密码或密钥。成功通知与失败通知可分别配置开关和邮箱，普通检查不发邮件。

管理 HTTPS 使用现有有效、可信且覆盖管理域名的证书；切换管理目标时也必须满足这些要求。新证书部署后，主机复制到私有版本目录，原子切换指针；容器检查证书与私钥匹配后重启 HTTPS worker。原始证书存储不直接挂载。

设计参考：[OWASP 会话管理](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)、[CSRF 防护](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)。

## 安装

要求已有原证书工具配置和固定任务 7、DSM 本机 Python 3.8+、Docker/Compose、iptables/ip6tables。先在实际 NAS 备份并验证原任务，不在没有预检的设备上直接套用示例地址。

在 NAS root 终端，从上传的 `web` 源码目录执行：

```sh
/usr/bin/python3 -I install-web.py prepare --bind 10.10.10.37 --network 10.10.10.0/24 --deny 10.10.10.1 --origin https://ttxli.cn:18443
/usr/bin/python3 -I /usr/local/share/synology-cert-web/code/install-web.py build
```

安装位置 `/usr/local/share/synology-cert-web`。安装器拒绝覆盖已有目录；原工具只新增受限桥接文件，不重装原脚本或重新初始化密钥、证书、恢复状态。

在同一私有交互终端初始化管理员。以下一次性容器只挂载登录数据库，通过 `-it` 接收两次隐藏的密码输入（至少 12 个字符），不要把密码写进命令参数：

```sh
/usr/local/bin/docker run --rm -it --network none --user 10100:10100 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env CERTWEB_DATA_DIR=/data \
  --mount type=bind,source=/usr/local/share/synology-cert-web/data,target=/data \
  --entrypoint python synology-cert-web:local -m web.backend init --username admin
/usr/bin/python3 -I /usr/local/share/synology-cert-web/code/install-web.py activate
```

启动注册 `/usr/local/etc/rc.d/S99synology-cert-web.sh`。监督进程先校验访问规则、证书副本和桥接，再启动容器；Docker 的 restart 设置为 no，由监督进程管理顺序。

## 配置保存与故障恢复

配置保存使用版本号与原任务互斥锁。先暂停任务并保存私有快照，完成输入校验、实际服务预检及配置写入后记录提交决策，再恢复任务计划。提交前失败回滚；提交后中断按已提交配置继续恢复任务，不用旧快照覆盖新通知或部署待办。409 冲突时页面保留草稿，要求重新读取确认。

原任务运行期间禁止并行保存或执行。手动运行触发原 DSM 任务，不强制向证书机构申请。未完成恢复或绑定变化时阻止不安全的目标切换。失败页面只读取已有脱敏归档，拒绝路径穿越和符号链接。

检查管理服务：

```sh
sudo /usr/local/etc/rc.d/S99synology-cert-web.sh status
sudo docker ps --filter name=synology-cert-web
```

停止或重新启动管理层不改变原续期任务：

```sh
sudo /usr/local/etc/rc.d/S99synology-cert-web.sh stop
sudo /usr/local/etc/rc.d/S99synology-cert-web.sh start
```

忘记密码时，在 root 私有终端运行与初始化相同的 `docker run` 命令，将 `init` 替换为 `reset-password`，账号保持为已有管理员。重置后原会话撤销，下次登录必须改密。不要重复执行 `prepare` 或删除登录数据来重置密码。

部署配置 `deployment.json`、`deployment.env` 以及 `data`、`tls` 只在 NAS 保存，不提交仓库。备份时需要保护登录数据库与 TLS 私钥。DSM 升级或网络地址变更后复查桥接、INPUT 规则、域名解析、原任务和内外网访问。不要仅以容器 Running 状态作为验收结论。

## 验证

完整后端与原执行器回归命令见 [根目录说明](../README.md#版本和来源)。前端在 `web/frontend` 中执行 `npm ci`、`npm test`、`npm run build`。

- 原脚本回归与固定 acme.sh 集成测试。
- API 未登录、首次改密、会话撤销/到期、限流、CSRF/Origin/Host、IPv4/IPv6/代理来源、路径限制和脱敏测试。
- 桥接配置冲突、事务前后恢复窗口、未完成任务保护、真实 socket 协议与父进程退出测试。
- TLS 权限、指针恢复、域名/链验证、worker 重载、专用防火墙规则及容器停止失败测试。
- 真实 HTTPS API + 浏览器登录/配置/失败详情/空态/移动布局验收。
- NAS 部署验收需要另外确认真实 task7、证书指纹、容器健康、启动恢复、LAN 正向访问及公网拒绝；本地测试不能替代这些步骤。

在 NAS 或允许的 LAN 客户端可先使用下面的命令验证 HTTPS 连通性、域名及证书链，无需先修改 DNS，也不要添加 `-k` 跳过验证：

```sh
curl --fail --silent --show-error \
  --resolve ttxli.cn:18443:10.10.10.37 \
  https://ttxli.cn:18443/healthz
```

健康接口预期返回 `{"ok":true}`；它不代表登录、群晖桥接或配置保存已经验证。真实验收还需登录改密、读取原证书和任务配置、执行预检、验证保存后的任务设置，以及确认管理层停止/启动不影响原任务。公网拒绝应在管理服务已经运行时从外部网络验证；路由器 DNS 与真实 LAN 浏览器访问尚待用户后续配置和确认。
