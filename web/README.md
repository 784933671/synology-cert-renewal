# 群晖证书管家 Docker 管理层

中文 Vue 3 + Ant Design Vue 4.2.6 页面，采用蓝白侧边导航、卡片、表单、表格与移动端抽屉导航，支持管理员密码与邮箱验证码登录、证书与 DNS 凭据配置、续期计划、立即申请新证书、成功/失败通知邮箱、访问模式切换、失败归档、操作审计和密码修改。

推荐从完整源码包的根目录运行 `sudo sh setup.sh`，首次安装与保留配置升级使用同一入口。详见下方[一键安装与升级](#一键安装与升级)；高级分步入口继续保留。

## 运行结构

```
浏览器 → HTTPS 管理容器（非 root） → 受限 Unix socket
                                      ↓
                    群晖本机桥接 → 已绑定 DSM 任务 / certctl
                                      ↓
                    DNSPod → Let's Encrypt → DSM → 校验/通知
```

Docker 运行前端和管理 API。证书签发、DSM 导入及通知继续使用本机执行器和已绑定 DSM 任务（当前 NAS 原任务 7），保持原任务的恢复机制；容器不再建立第二套续期定时器。新设备由 DSM 分配任务编号，编号存于私有部署配置；已有安装保留原绑定和检查时间。无需在网页保存 DSM 管理员密码，也不需要关闭 DSM 双重验证。

## 访问模式与边界

- 管理入口使用 `https://ttxli.cn:18443`，两种模式都只绑定 NAS 的 `10.10.10.37`，只监听 IPv4；IPv6 的管理端口始终拒绝。
- `lan` 模式仅允许 `10.10.10.0/24`，单独排除网关 `10.10.10.1`，避免公网转发经路由器 SNAT 后以网关来源进入。`public` 模式允许任意 IPv4 来源，包括网关。两种模式都要求登录。
- 容器使用 host 网络，不创建 Docker 发布端口；NAS 原生监督进程维护只针对管理端口的专用链。DSM 会把针对内置 `INPUT` 的写操作重定向到较晚执行的 `DEFAULT_INPUT`，因此本项目把专用跳转置于 `INPUT_FIREWALL` 首条，并核验真实 `INPUT` 的第一条规则无条件跳入 `INPUT_FIREWALL`。只修改本服务的链与跳转，保留其他 DSM/Docker 规则；无法确认顺序时停止管理服务。普通 Linux 则直接使用 `INPUT` 首条。IPv6 的该管理端口单独拒绝，服务本身只监听指定 IPv4。
- API 按访问模式校验实际 TCP 来源；`public` 只放开 IPv4 来源限制，不关闭 HTTPS、登录、精确 Host、Origin、CSRF、会话和登录限流。两种模式均拒绝 `Forwarded`、`X-Forwarded-*`、`X-Real-IP`，不采用 HTTP 反向代理或 QuickConnect 转发方案。
- `public` 模式不会创建路由器映射。需要公网访问时，将 TCP 18443 映射到 `10.10.10.37:18443`，并让公网域名解析到路由器的可达公网地址；`lan` 模式不提供公网来源访问。路由器、DNS 和客户端配置由用户管理。
- NAS 本机通过自身 LAN 地址访问始终允许；管理员 SSH 隧道也属于受信管理路径。`lan` 模式仅 `/healthz` 额外允许真实回环来源，业务 API 不允许回环来源。
- NAS 向 DNSPod、证书机构及邮件服务的出站连接不受这项管理入口模式切换影响。

host 网络共享 NAS 网络命名空间，因此不属于网络隔离；容器仍以非 root 身份运行，使用只读根文件系统、移除全部 capability，并启用 no-new-privileges。资源配置绑定一个逻辑 CPU（`cpuset: "0"`）、限制内存为 384 MiB；非 root 用户 UID 10100 的进程数软/硬上限均为 96，每个进程的打开文件数软/硬上限均为 1024。此 NAS 的 DSM 内核不支持 CFS CPU 配额和 PID cgroup 限制，进程上限使用 `ulimits.nproc`，不宣称启用了 PID cgroup 隔离。不挂载 Docker socket、NAS 根目录或完整续期配置。挂载仅包含登录数据库、受限 socket、只读访问策略和管理 HTTPS 所需的最小证书副本。

[Docker host 网络说明](https://docs.docker.com/engine/network/drivers/host/)与[防火墙说明](https://docs.docker.com/engine/network/packet-filtering-firewalls/)解释了此处选择 INPUT 规则而非依赖发布端口默认行为的原因。

在“访问安全”页面选择模式并保存。页面分别显示已保存模式和实际生效模式；两者不一致时显示待应用。监督进程每 10 秒读取策略并自动应用，期间可能短暂重启管理容器，无需手动重启。切回 `lan` 后，当前外网浏览器可能立即失去连接，后续需从允许的内网进入。

访问策略保存于 `/usr/local/share/synology-cert-web/access/access.json`，内容为 `{mode,revision}`，文件属主 `root:10100`、权限 `0640`，目录权限 `0750`；`applied.json` 记录实际防火墙模式。容器以只读方式挂载到 `/access`，只能通过受限桥接申请更新。策略缺失或损坏时禁止访问，不默认切到 `public`。切换仅修改管理入口策略，不改变原证书配置和任务计划。

若无法进入页面，可在 NAS root 终端恢复模式，监督进程会自动应用：

```sh
/usr/bin/python3 -I /usr/local/share/synology-cert-web/code/deployment.py set-access-mode --mode public
```

要恢复仅内网访问，将 `public` 改为 `lan`。用户本次选择 `public`，实际生效状态以页面和 [部署验收记录](DEPLOYMENT.md) 为准。

## 打开管理页面

浏览器入口为 `https://ttxli.cn:18443`。服务绑定 `10.10.10.37`，但不能改用 `https://10.10.10.37:18443`：证书验证和允许的 Host 都要求管理域名。不开 HTTP 端口，也不通过忽略证书错误完成验收。

公网访问使用 `public` 模式、可达的公网域名解析和上述 TCP 端口映射，浏览器仍打开同一个域名入口。内网直连时，可在路由器设置仅内网生效的域名映射，或只在一台内网电脑的 hosts 文件增加以下记录：

```text
10.10.10.37 ttxli.cn
```

macOS 的 hosts 文件是 `/etc/hosts`，Windows 为 `C:\Windows\System32\drivers\etc\hosts`，编辑需要系统管理员权限。此映射只适合能直接到达 NAS 的内网电脑，不用于公网客户端；它也会影响这台电脑通过 `ttxli.cn` 访问其他服务，不再需要时移除。采用路由器内网 DNS 时，客户端需使用该 DNS，并确认浏览器自定义 DNS/DoH 没有绕过它。

## 登录与凭据

无固定默认密码。管理员在私有终端初始化，并按下文启用邮箱验证；初始化本身不会自动绑定邮箱。启用后，密码正确只进入验证码步骤，不能访问业务接口；输入邮件中的 6 位数字验证码后才签发完整会话。第一次成功验证同时确认邮箱绑定，首次登录仍须改密。登录邮箱由主机管理员配置，账户页只显示脱敏地址；网页不能更换收件人，成功/失败通知邮箱的修改也不会改变登录邮箱。

验证码有效期 5 分钟，单次登录挑战最长 10 分钟且绑定实际来源 IPv4；换网后需重新登录。每次发送至少间隔 60 秒，单个挑战累计输错 5 次即失效，重发不重置错误次数并立即替换旧码。发送额度按账号、来源 IP 和全局持久限流，账号最多每 15 分钟 5 封、每小时 10 封、每天 20 封；失败发送也占用额度，重启、改密和重置密码不会清除发送记录。

发信复用 DSM 已启用的通知邮件配置和本机 `ssmtp`，不复制 SMTP 密码。发信失败或服务端请求取消时，本轮验证码失效，服务不会降级为仅密码登录。页面刷新可恢复未结束的挑战，不自动重发；网络中断或响应无法解析时，先点击“重新确认登录状态”，确认实际会话或挑战后再继续。“返回登录”会撤销当前挑战。

密码仅保存 scrypt 哈希，验证码保存消息认证码，挑战与会话令牌仅保存哈希。密码、验证码和原始请求正文不写入审计或错误响应。Cookie 使用 `__Host-` 前缀、HttpOnly、Secure、SameSite=Strict。完整会话闲置 30 分钟或登录 8 小时后失效，后台状态轮询不延长闲置期限；退出撤销当前会话，改密撤销全部旧会话和挑战并返回新会话，重置密码、启停邮箱验证或更换绑定策略撤销全部会话和挑战。

DNSPod 密钥只允许写入，GET 接口只返回是否已配置。浏览器不持久化密码、验证码或密钥。成功通知与失败通知可分别配置开关和邮箱，预检查不发邮件；原任务会按已有配置处理失败或待发送通知。

管理 HTTPS 使用现有有效、可信且覆盖管理域名的证书；切换管理目标时也必须满足这些要求。新证书部署后，主机复制到私有版本目录，原子切换指针；容器检查证书与私钥匹配后重启 HTTPS worker。原始证书存储不直接挂载。

设计参考：[OWASP 会话管理](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)、[CSRF 防护](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)。

## 一键安装与升级

一键入口支持 DSM 7 的 x86_64 群晖（例如 DS218+），要求 Python 3.8+、已运行的 Docker / Container Manager 与 Docker Compose、本机 iptables/ip6tables，以及已配置并测试成功的 DSM 通知邮件。准备好 DNSPod 子账号密钥，先在 DSM 中确认描述唯一的目标证书条目，其 DNS SAN 必须包含要管理的域名，并绑定到实际 HTTPS 验证服务。向导不会创建新的域名或扩展证书 SAN。

在浏览器登录 [GitHub 仓库](https://github.com/784933671/synology-cert-renewal)，使用“Code → Download ZIP”下载完整源码，再上传并解压到 NAS。在私有 SSH 终端进入项目根目录执行，以下路径按解压位置调整：

```sh
cd /volume1/docker/synology-cert-renewal-main
sudo sh setup.sh
```

按提示选择现有证书、输入密钥、确认 NAS 内网地址/网段/网关、管理域名/端口、访问模式和邮箱，再设置管理账号 `admin` 的密码。新安装默认 `lan`；本说明中的 `ttxli.cn`、`10.10.10.37` 是当前 NAS 示例，新设备填写自己的值。管理员密码和密钥不通过命令参数传递。已有原脚本配置会保留，不重新索取或覆盖原密钥。

安装器自动完成镜像构建、固定登录邮箱绑定、开机启动和服务检查。所选证书若过期或自签、不能通过可信 HTTPS 检查，只有在终端明确选择后才运行原任务申请或恢复证书；拒绝后保留安装进度。需先有正确域名的证书条目，不能从不含目标域名的默认设备证书推导新证书。

安装器只绑定精确指向当前原执行器 `run-task.sh` 的 root 脚本任务。没有时新建，先保持停用，待容器健康、真实 HTTPS 和证书桥接检查通过再启用；新任务默认每小时第 17 分钟。已有任务保留原编号、计划分钟、启停状态和通知设置；多个匹配或结果不明时停止，避免重复执行。任务编号由 DSM 分配，不能假定新设备仍为 7。

已有完整看板时，`setup.sh` 自动进入保留配置升级；未完成安装时，使用原源码包重新运行继续。安装日志绑定源码摘要，恢复安装时不要换包。已完成安装不重复走 `install`，避免重设登录或覆盖已修改的计划。需要明确操作时：

| 命令 | 行为 |
| --- | --- |
| `sudo sh setup.sh check` | 只读检查系统依赖及已有部署参数，不构建、启动或申请证书 |
| `sudo sh setup.sh upgrade` | 升级已完整部署的管理层，保留配置、登录、邮箱验证和原任务 |
| `sudo sh setup.sh recover` | 处理管理层升级中断的恢复记录，不自动宣称新版本已上线 |

升级先构建新镜像，切换前保存私有备份；切换失败按恢复记录回退。安装进度在 `/usr/local/share/synology-cert-setup`，管理层升级记录和备份在 `/usr/local/share/synology-cert-web`。不要删除进度、认证数据库或任务状态来重复安装。`recover` 不处理证书签发、DNS 清理或绑定变化，这些仍按原执行器的恢复步骤处理。

首次启动、升级切换或容器异常退出后，监督进程要求访问规则、HTTPS 材料、桥接等启动条件连续稳定 60 秒，才启动管理容器。升级切换后等待约 1～3 分钟属于正常过程，不包括镜像下载与构建；条件变化会重新计时，正常运行中的容器不会定期重启。持续失败时保持保护状态，查看下方启动阶段记录后处理，不要反复手动启动容器绕过监督进程。

完成后按终端给出的域名入口访问，首次登录输入刚设置的密码和邮箱验证码并修改初始密码。内网 DNS / hosts、路由器映射由用户自行配置；安装器不会修改路由器。实际邮件送达、登录和证书业务验收需在目标 NAS 完成，安装脚本测试通过不代表已完成新设备实装验收。

## 高级分步安装

以下方式要求已有配置正确的原证书执行器和唯一对应的 DSM 任务、DSM 本机 Python 3.8+、Docker/Compose、iptables/ip6tables。先备份并验证原任务，在 `--task-id` 填写其真实编号；示例 7 仅对应当前 NAS。首次安装推荐上面的向导自动发现或创建任务。

在 NAS root 终端，从上传的 `web` 源码目录执行：

```sh
/usr/bin/python3 -I install-web.py prepare --bind 10.10.10.37 --network 10.10.10.0/24 --deny 10.10.10.1 --origin https://ttxli.cn:18443 --access-mode lan --task-id 7
/usr/bin/python3 -I /usr/local/share/synology-cert-web/code/install-web.py build
```

`--access-mode` 支持 `lan` 和 `public`，省略时默认 `lan`；需要从首次启动就允许任意 IPv4 来源时使用 `--access-mode public`。内网白名单和网关配置仍保留，供之后切回 `lan` 使用。

安装位置 `/usr/local/share/synology-cert-web`。分步 `prepare` 不覆盖已存在的完整安装；原工具只新增受限桥接文件，不重新初始化密钥、证书或恢复状态。已有管理层使用源码根目录的 `setup.sh upgrade`。

在同一私有交互终端初始化管理员。以下一次性容器只挂载登录数据库，通过 `-it` 接收两次隐藏的密码输入（至少 12 个字符），不要把密码写进命令参数：

```sh
/usr/local/bin/docker run --rm -it --network none --user 10100:10100 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env CERTWEB_DATA_DIR=/data \
  --mount type=bind,source=/usr/local/share/synology-cert-web/data,target=/data \
  --entrypoint python synology-cert-web:local -m web.backend init --username admin
```

### 绑定登录邮箱

首次激活管理层前配置登录邮箱。已有安装更换邮箱或策略时先停止管理层，完成下列主机配置与认证数据库配置后再启动。这里的 `admin@example.com` 是示例，替换为管理员实际接收验证码的邮箱；不要把生成的策略文件加入源码仓库。

在 NAS root 私有终端中执行，邮箱策略保存于**原证书工具目录**的 `web/login-email.json`，不是管理层的 `access` 目录：

```sh
CERTWEB_LOGIN_EMAIL='admin@example.com'
CERTWEB_LOGIN_VERSION=$(/usr/bin/python3 -c 'import secrets; print(secrets.token_hex(16))')
/usr/bin/python3 - "$CERTWEB_LOGIN_EMAIL" "$CERTWEB_LOGIN_VERSION" <<'PY'
import json
import os
from pathlib import Path
import tempfile
import sys

root = Path('/usr/local/share/synology-cert-renewal/web')
info = root.lstat()
if root.is_symlink() or not root.is_dir() or info.st_uid != 0 or info.st_mode & 0o077:
    raise SystemExit('请检查原工具 web 目录的 root 属主与 0700 权限')
descriptor, temporary = tempfile.mkstemp(prefix='.login-email-', dir=str(root))
try:
    with os.fdopen(descriptor, 'w') as handle:
        json.dump({'recipient': sys.argv[1], 'policy_version': sys.argv[2]}, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, str(root / 'login-email.json'))
    directory = os.open(str(root), os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
/usr/local/bin/docker run --rm --network none --user 10100:10100 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env CERTWEB_DATA_DIR=/data \
  --mount type=bind,source=/usr/local/share/synology-cert-web/data,target=/data \
  --entrypoint python synology-cert-web:local -m web.backend enable-email-login \
  --username admin --email "$CERTWEB_LOGIN_EMAIL" --policy-version "$CERTWEB_LOGIN_VERSION"
unset CERTWEB_LOGIN_EMAIL CERTWEB_LOGIN_VERSION
```

主机文件须为 root 属主、0600 权限；上例通过 root 创建私有临时文件并原子替换。若安装时使用了其他原工具目录或管理员账号，相应替换路径和 `--username`。主机与后端必须使用**相同邮箱和同一随机 32 位小写十六进制 `policy_version`**；更换邮箱时生成新版本并同时更新两处。主机只按私有策略投递固定模板，版本不匹配、策略缺失或文件权限异常均拒绝发信。策略文件不挂载到管理容器。

确认 DSM 通知邮件已配置后激活管理层：

```sh
/usr/bin/python3 -I /usr/local/share/synology-cert-web/code/install-web.py activate
```

启动注册 `/usr/local/etc/rc.d/S99synology-cert-web.sh`。监督进程先校验访问规则、证书副本和桥接，等待启动条件连续稳定 60 秒后再启动容器；Docker 的 restart 设置为 no，由监督进程管理顺序。

## 配置保存与故障恢复

### 运行健康、独立预警与执行记录

“运行健康”显示容器、主机桥接、HTTPS 材料、访问规则及监测进程的状态，并提供最近服务事件和升级阶段。主机快照超过 45 秒、监测快照超过 180 秒或尚未应用最新预警设置时显示未知，不把旧数据继续当作正常。前端将请求耗时保守计入快照年龄；刷新等待期间，旧快照仍按原时刻继续过期。只有监督程序退出时同时存在有效升级事务和被占用的升级锁，才标记计划内维护；其他停止事件不会仅凭退出码 0 归类为维护。DSM 自身的容器提醒仍由 DSM 管理。

预警由主机监督程序管理的独立子进程每 60 秒检查，检查和发信不会阻塞访问规则监督。默认开启，连续漏跑 2 轮、宽限 15 分钟、证书临期 24 小时提醒；页面可配置漏跑 1～6 轮、宽限 5～120 分钟、临期 1～168 小时。这些阈值不修改提前续期天数。收件人沿用“邮件通知”的失败通知邮箱；失败通知关闭时只显示状态，不发送监测邮件。关闭独立预警不会停用原续期任务。正常检查保持静默，已确认提交邮件的同一故障不会每轮重复通知；仅已发出告警且确认恢复的事件发送一次恢复通知，暂停任务不当作漏跑故障恢复。发送失败按有界退避重试，最长等待 1 小时；时钟回拨或重启读取状态时会重新限制待发时间，保留已经通知的去重状态。SMTP 应答丢失等场景不能保证网络意义上的恰好一次投递。

按原任务受支持的小时/每日计划计算漏跑：应执行时刻经过宽限后仍没有新的完成记录，才计入漏跑次数。成功和失败结果都表示任务执行过；执行失败仍由原任务失败通知处理。例如最后完成记录在 10:00、计划每小时第 17 分钟执行，默认阈值下最早在 11:32 后的监测中报告连续漏跑两轮，不是固定等待两小时。任务暂停不再判断漏跑，证书临期告警仍独立判断。执行结果或运行锁不可读时，只要当前证书、系统时间和任务通知配置可核验，仍可发送临期提醒；无法读取通知配置时不猜测收件人，无法确认目标证书时不发送恢复通知。首次监测、重启、计划或设置变更有观察宽限，正在运行的任务也有宽限。检测到校时异常会先持久保存标记；观察期内重启监测，将按当前配置重新等待完整宽限（默认 15 分钟），正常轮次不会不断延长截止时间。关闭预警或采集失败不会清除这个安全标记，完成稳定观察前不发送恢复邮件。无法识别的 DSM 计划、来源不可读或时间异常显示未知，并保留不能确认恢复的故障。主机或网络整体离线仍需其他设备监测，本进程不能在 NAS 断电时发送邮件。

“执行记录”仅从启用本版本后开始记录，不补造历史。普通检查、立即换证、恢复及只读预检查均保留实际阶段和耗时；正常未到续期窗口显示跳过，不把没有执行的签发、替换显示成功。无法独立计时的 DNS 证据标为时间未知；进程或预检工作线程已结束但未记录最终结果时显示中断，不伪造完成时间或推断证书操作失败。记录按最多 500 条、30 天保留，在新一轮开始和最终结果写入时清理；停止执行期间不另设清理任务，超期文件可能暂留磁盘，但页面列表和详情始终按 30 天期限隐藏。页面分页查看详情，输出不包含私钥、凭据或原始命令日志。记录保存故障不改变证书动作的安全规则，页面会在可记录时提示历史可能不完整。

主机私有文件包括原执行器 `state/runs/`、`state/monitor-config.json`、`state/monitor-state.json`，以及管理目录的 `monitor-status.json`、`runtime-health.json`、`deployment-events.json`。这些运行数据不放入安装包或 Git。管理容器仍只通过受限桥接读取白名单字段，不挂载 Docker socket。

配置保存使用版本号与原任务互斥锁。先暂停任务并保存私有快照，完成输入校验、实际服务预检及配置写入后记录提交决策，再恢复任务计划。提交前失败回滚；提交后中断按已提交配置继续恢复任务，不用旧快照覆盖新通知或部署待办。409 冲突时页面保留草稿，要求重新读取确认。

恢复会核对任务最后确认的状态及待确认写入，检测到 DSM 中后续修改的启停、计划、通知或脚本时，保留 `state/web-transaction.json` 与快照并停止覆盖。DSM 接口没有本项目可用的原子版本比较参数，因此这不是跨 DSM 页面的全局锁；结果有歧义时需管理员核对，不会擅自重新启用任务。证书描述的脱敏只用于展示，保存使用按证书 ID 读取的原始描述。

修改密码遇到超时、连接中断或响应损坏时，页面先确认当前会话，期间禁止重复改密。读到原会话仍保持待确认，因为原请求可能尚在处理；可继续确认，或选择退出后重新登录。确认新会话后更新页面和请求令牌；会话失效则回到登录页。恢复失败保留明确的重试入口，已离开页面的旧请求不会覆盖新会话。

原任务运行期间禁止并行保存或执行。手动运行触发原 DSM 任务，按原续期策略决定是否申请；预检查只检查环境与 HTTPS 服务。两者都不会因点击而强制签发。

“立即申请并替换证书”需要二次确认，会创建持久的一次性请求，再触发原 DSM 任务；不会新增定时器或改变原任务的启用状态。请求 10 分钟内未消耗则过期，每次提交后有 1 小时冷却，重启不会绕过。排队或运行中的请求阻止重复提交、保存配置、预检查和再次手动运行。已有未部署候选、恢复、DNS 清理、通知或绑定待办时，需先完成恢复。

执行器在调用证书机构前持久记录请求已消耗；已有 ACME 材料时使用 `--renew --force`，首次申请或隔离损坏材料后使用 `--issue`。只有取得不同于提交时基线指纹的新证书，并完成证书校验、DSM 替换、实际 HTTPS 验证、DNS 清理及通知后，申请状态才显示成功；acme.sh 返回跳过、保留旧证书或只接受了请求都不代表成功。

调度结果不明确时请求仍保留，应刷新状态，不要重复点击。中断后的已消耗请求只恢复现有材料的部署、验证、清理和通知，不重复本次强制申请；候选缺失或损坏时也不会借恢复流程重新签发。该限制持续到下一正常续期窗口且至少覆盖 1 小时冷却；届时恢复原自动策略，不重放强制请求。没有自定义续期窗口的旧配置在冷却结束后恢复原策略。

如果手动申请失败且没有取得新材料，执行器仅在当前证书、候选指纹、绑定及清理/通知状态均能确认安全时，解除属于该请求的保护标记，允许修复凭据或在冷却后提交新的显式申请；原请求的防重放记录继续保留。已有新候选或其他待办时仍禁止解除保护和不安全的目标切换。不要手动删除状态文件来绕过冷却或恢复保护。失败页面只读取已有脱敏归档，拒绝路径穿越和符号链接。

检查管理服务：

```sh
sudo /usr/local/etc/rc.d/S99synology-cert-web.sh status
sudo docker ps --filter name=synology-cert-web
```

启动与安全停服的固定中文摘要写入 `/usr/local/share/synology-cert-web/supervisor.log`；同目录 `deployment-state.json` 保存最新 `status`、`stage`、`message`。`stage` 可定位 `policy`（访问策略/防火墙）、`tls`（HTTPS 材料）、`bridge`（群晖桥接）、`docker`、`stability`（稳定等待）或 `start`（容器启动）等环节。检查失败时会尝试停止管理容器；无法确认停止时记录相应提示，需要通过 NAS 检查，不把它视为已安全关闭。

```sh
sudo tail -n 30 /usr/local/share/synology-cert-web/supervisor.log
sudo cat /usr/local/share/synology-cert-web/deployment-state.json
```

停止或重新启动管理层不改变原续期任务：

```sh
sudo /usr/local/etc/rc.d/S99synology-cert-web.sh stop
sudo /usr/local/etc/rc.d/S99synology-cert-web.sh start
```

忘记密码时，在 root 私有终端运行与初始化相同的 `docker run` 命令，将 `init` 替换为 `reset-password`，账号保持为已有管理员。重置后原会话及挑战撤销，下次登录仍需邮箱验证码并必须改密；邮箱绑定不变。不要重复执行 `prepare` 或删除登录数据来重置密码。

邮箱不可用时先修复 DSM 发信配置；需要更换收件人时，按“绑定登录邮箱”重新生成版本并更新两处。必须临时停用邮箱验证时，仅可在私有终端使用同一隔离容器执行 `python -m web.backend disable-email-login --username admin`，不能通过网页停用。该命令会撤销旧会话及挑战并记录审计，此后账号恢复密码登录；完成恢复后重新执行 `enable-email-login`，确认密码步骤不签发完整会话及实际收信成功。

部署配置 `deployment.json`、`deployment.env`、主机 `web/login-email.json`、`state/login-mail-rate.json`、`state/manual-renewal.json` 以及 `data`、`tls`、`access` 只在 NAS 保存，不提交仓库。备份时需要保护登录数据库、邮箱绑定策略与 TLS 私钥，保留发送限流和手动申请记录。DSM 升级或网络地址变更后复查桥接、访问策略及实际生效模式、INPUT 规则、域名解析、原任务和内外网访问。不要仅以容器 Running 状态作为验收结论。

## 验证

完整后端与原执行器回归命令见 [根目录说明](../README.md#版本和来源)。前端在 `web/frontend` 中执行 `npm ci`、`npm test`、`npm run build`。

- 原脚本回归与固定 acme.sh 集成测试。
- API 密码与验证码两步隔离、一次性并发消费、过期/重发/跨 IP、发送失败与取消竞争、持久限流、策略和密码变更撤销、首次改密、会话到期、CSRF/Origin/Host、两种访问模式、路径限制和脱敏测试。
- 立即申请的排队/过期/冷却、不同指纹成功条件、强制请求不重放、无材料及损坏材料恢复、未来正常续期和配置修复测试。
- 桥接配置冲突、事务前后恢复窗口、未完成任务保护、真实 socket 协议与父进程退出测试。
- TLS 权限、指针恢复、域名/链验证、worker 重载、访问策略修订冲突与损坏后拒绝访问、专用防火墙规则及容器停止失败测试。
- 真实 HTTPS API + 浏览器登录/配置/失败详情/空态/移动布局验收。
- NAS 部署验收需要另外确认实际绑定的 DSM 任务、证书指纹、容器健康、启动恢复、验证码邮件实际到达，以及 `lan` 模式的公网拒绝和 `public` 模式的 IPv4 访问；本地模拟邮件和固定 acme.sh 测试不能替代真实收信及签发验收。

在 NAS 或允许的 LAN 客户端可先使用下面的命令验证 HTTPS 连通性、域名及证书链，无需先修改 DNS，也不要添加 `-k` 跳过验证：

```sh
curl --fail --silent --show-error \
  --resolve ttxli.cn:18443:10.10.10.37 \
  https://ttxli.cn:18443/healthz
```

健康接口预期返回 `{"ok":true}`；它不代表登录、群晖桥接或配置保存已经验证。真实验收还需登录改密、读取原证书和任务配置、执行预检、验证保存后的任务设置，以及确认管理层停止/启动不影响原任务。公网测试应在管理服务已运行、所选模式已实际应用时从外部网络执行：`lan` 应拒绝，`public` 在端口映射和 DNS 正确时应能打开登录页。实际结果单独记录在 [部署验收](DEPLOYMENT.md)。

### UI 组件与内容安全策略

页面使用 Ant Design Vue 和 Ant Design Icons Vue，本地打包，无 CDN 依赖。通用主题与中文语言由 ConfigProvider 统一配置；布局、配置表单、监控日志的样式分别保存在 `frontend/src/styles/`。业务请求、状态与配置校验继续复用现有 composables。

HTML 每次响应生成独立 CSP nonce，Ant 的动态样式必须携带该 nonce。固定版本组件库的主题和动画注入入口通过 `frontend/build/antd-csp.ts` 补充 nonce；入口发生变化时构建失败，升级组件库后需重新验证。保持 `script-src self`，不开放内联脚本、eval 或任意内联样式；API 与静态资源沿用原安全头。
