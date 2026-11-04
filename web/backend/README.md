# 管理 API

Python 3.12，单个 Uvicorn worker。依赖安装使用 `pip install --require-hashes -r web/requirements.txt`。此服务不安排证书续期、不执行 shell，也不读取群晖原始配置、日志或证书目录；仅通过固定 Unix socket 方法访问主机桥接器。

## 环境参数

| 参数 | 含义 / 默认值 |
| --- | --- |
| `CERTWEB_DATA_DIR` | 独立的 0700 认证数据目录，默认 `/data`，运行 UID 应有写权限 |
| `CERTWEB_STATIC_DIR` | Vue 构建产物目录，默认 `/app/static` |
| `CERTWEB_BRIDGE_SOCKET` | `/bridge/certweb.sock` |
| `CERTWEB_ALLOWED_NETWORKS` | 仅内网模式的精确 RFC1918 IPv4 CIDR，逗号分隔；内网模式未设置时拒绝所有业务访问 |
| `CERTWEB_DENIED_ADDRESSES` | 仅内网模式的局域网 IPv4 拒绝列表，应填写网关及转发代理地址；优先于允许网段 |
| `CERTWEB_ACCESS_POLICY_FILE` | 主机共享的只读策略文件，部署值 `/access/access.json`；未设置时沿用仅内网模式，设置后缺失或损坏会拒绝请求 |
| `CERTWEB_ALLOWED_HOSTS` | 精确的 HTTP Host authority，包含非标准端口；不支持通配符。默认 `localhost:18443,127.0.0.1:18443`；Compose 额外加入配置的 `CERTWEB_BIND:CERTWEB_PORT` 作为 IP 入口 |
| `CERTWEB_ORIGIN` | 规范 HTTPS 域名入口，必须对应 Host 白名单，用于部署证书验证和健康检查；默认 `https://localhost:18443`。写请求按当前已验证 Host 精确校验同源 |
| `CERTWEB_BIND` | 必填，明确的 NAS 局域网 IPv4；禁止绑定 `0.0.0.0`、公网、回环、IPv6或拒绝列表地址 |
| `CERTWEB_PORT` | 默认 `18443`，仅允许 1024–65535 |
| `CERTWEB_TLS_CERT` | 只读证书副本，默认 `/tls/current.cert` |
| `CERTWEB_TLS_KEY` | 只读私钥副本，默认 `/tls/current.key` |

生产环境应显式填写 `CERTWEB_ALLOWED_HOSTS`、`CERTWEB_ORIGIN`、网段、网关拒绝列表和绑定地址。启动命令：

```sh
python -m web.backend serve
```

服务仅使用连接的真实 IPv4 来源。任何 `Forwarded`、`X-Forwarded*`、`X-Real-IP` 请求头均被拒绝，Uvicorn 代理信任功能明确关闭。IPv6 被拒绝。仅内网模式下，唯一的回环例外是来源为 **127.0.0.1** 的 `/healthz`，仍须通过 Host 和 HTTPS 校验；回环来源不能访问静态页面、登录或业务 API。允许外网模式接收内外网 IPv4 来源，但仍要求登录、首次改密、精确 Host、HTTPS、同源与 CSRF 校验。监听地址保持明确的 NAS LAN IPv4；从公网访问仍需正确的端口映射。

访问安全页面支持 `lan` / `public` 模式，`GET /api/security` 返回配置模式、已应用模式、revision 与 pending；`PUT /api/security` 仅接受 `{access_mode,revision}`，通过固定 `security.update` 桥接方法进行 CAS 保存。策略文件只有主机可写，容器每次请求热读取；监督进程应用相同模式到端口规则后更新 applied.json。保存与网络规则应用之间页面显示应用中，恢复为仅内网可能立即断开当前外网用户后续请求。模式切换记录审计，不修改证书配置或任务。TLS 副本替换后的进程重启由外层 supervisor 处理。

管理服务只接受 HTTPS，但不发送 `Strict-Transport-Security`，也不发送 `max-age=0`。HSTS 会影响同一域名的其他端口；管理页与现有 DSM 共用域名时，不应替其他入口设置或清除浏览器的 HSTS 策略。Secure Cookie、HTTPS 校验和同源保护仍然生效。

## 管理员初始化与恢复

在私有终端、以容器运行 UID 执行下列命令，按隐藏提示输入两次密码：

```sh
python -m web.backend init --username admin
python -m web.backend reset-password --username admin
```

仅在可信的标准输入管道中使用 `--password-stdin`；不要把密码放入命令参数、环境变量、脚本或聊天。没有默认密码，也不输出密码。首次初始化和恢复后均要求网页再次改密；已有管理员不能被 `init` 覆盖。恢复会撤销全部旧会话。

密码长度 12–128 个字符，采用独立随机盐及 scrypt `N=32768,r=8,p=3`；密码运算串行执行以控制 NAS 内存。参数采用 [OWASP scrypt 的 32 MiB 配置](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt)。

会话闲置 30 分钟、绝对有效期 8 小时。`GET /api/status` 与 `GET /api/security` 定时轮询不刷新闲置时间；用户读取配置等操作会刷新。登出使当前服务器会话失效，改密撤销全部会话并签发新会话。Cookie 使用 `__Host-` 前缀、HttpOnly、Secure、SameSite=Strict。登录和改密分别使用持久的 15 分钟限流窗口：同 IP+账户 5 次、同 IP 15 次、全局 40 次；计数在尝试前预留，重启不清零，窗口到期自动恢复。

所有写请求要求 Origin 精确等于 `https://` 加当前已通过白名单验证的 Host，并要求 JSON；域名 Origin 与 IP Host 之间不能交叉使用。除登录外还要求 X-CSRF-Token。请求正文最多 128 KiB、读取最多 10 秒；桥接请求最多 64 KiB、响应最多 2 MiB、最多 60 秒。桥接错误只映射固定中文摘要。SQLite 审计仅保存固定动作及安全摘要，不保存参数、口令、密钥或请求正文。

## 本机验证

接口防刷策略使用管理层 `auth.sqlite3` 中独立的 `abuse_policy`、`abuse_buckets`、`abuse_blocks` 表；迁移不修改已有用户、会话、登录限流或主机续期状态。`SecurityBoundary` 完成来源、HTTPS、Host、Origin 和正文长度检查后，在读取正文前对 `/api/` 计数。`/healthz` 与静态资源不参与计数；Unix socket 和 DSM 任务不经过这层。

- `GET /api/abuse` 返回 `{revision,limits}`；`PUT /api/abuse` 使用相同结构进行版本校验。
- `GET /api/abuse/blocks` 返回临时封禁列表；`POST /api/abuse/unblock` 只接收 `{ip}`。
- 两个写接口的授权消费和数据库修改在同一事务中，要求邮箱二次验证，记录审计及安全配置提醒。所有读取仍要求完整登录；列表轮询不刷新闲置期限。
- 429 返回 `error.code`（`rate_limited` 或 `ip_temporarily_blocked`）、正整数 `error.retry_after` 以及相同的 `Retry-After` 响应头。封禁无法绕过现有来源或认证限制。
- 登录、会话、退出、改密、二次验证和接口防护路由保留独立恢复额度；固定列表见 `abuse.py`，未知路由不享受例外。普通计数桶最多 3072 个，恢复桶预留 1024 个，封禁最多 1024 个。

私有容器终端可运行 `python -m web.backend clear-abuse-blocks [--ip IPv4]`。它仅清除接口临时计数与封禁，不触及原登录、验证码和续期保护。完整使用说明及默认值见 [接口防护说明](../README.md#接口防护与临时解封)。

```sh
pip install --require-hashes -r web/requirements-test.txt
python -m unittest discover -s tests -p 'test_web_api*.py' -v
```

测试覆盖认证、首次改密、会话过期/撤销、持久限流、同源/CSRF、网络边界、代理头、静态路径、大小/超时、固定动作和真实 Unix socket 集成。测试使用合成凭据与本机临时数据库，不修改 NAS。容器启动、真实 LAN 可达性、主机网络规则及群晖执行器需由部署验收另行确认。

FastAPI 与 Uvicorn 版本通过 [PyPI FastAPI 元数据](https://pypi.org/project/fastapi/)、[PyPI Uvicorn 元数据](https://pypi.org/project/uvicorn/) 核验，并锁定所有间接依赖及发行包哈希；服务参数按 [Uvicorn 官方设置](https://uvicorn.dev/settings/) 配置。
