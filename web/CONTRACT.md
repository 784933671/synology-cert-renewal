# 证书管家接口契约

正式管理界面采用 Vue 3 + TypeScript。Docker 内运行 HTTPS 管理 API 与静态资源，群晖现有 root 执行器保持运行；通过受限 Unix socket 控制原任务，不在容器重复安排续期。

## 浏览器 API

成功返回 JSON 对象本身；错误 HTTP 400/401/403/409/410/428/429/502/503，格式 `{"error":{"code":"...","message":"中文安全摘要"}}`，不得携带原始异常、命令、密码、验证码或密钥。所有写请求要求精确同源 Origin 和 JSON；`/api/login` 及其子接口不要求业务 CSRF Token，其他写接口必须使用完整会话的 `X-CSRF-Token`。敏感写操作另外要求下述 `X-Step-Up-Token`；重复的敏感请求头一律拒绝。服务器不信任代理头。

- GET `/api/session` -> 下述 Session；未登录或仅密码通过时返回401。
- POST `/api/login` `{username,password}` -> 已启用邮箱验证时返回202和下述 Challenge，设置短期挑战 Cookie；尚未启用或私有终端明确停用时返回200和 Session。
- GET `/api/login/challenge` -> Challenge 或 `{verification_required:false}`；恢复步骤，不发邮件。挑战不存在、过期或来源 IP 不匹配时清除客户端挑战 Cookie。
- POST `/api/login/verify` `{code:"6位ASCII数字"}` -> Session；原子消费挑战，签发完整会话 Cookie，并清除挑战 Cookie。
- POST `/api/login/resend` `{}` -> Challenge；要求有效挑战，发送新码并使旧码失效，不延长挑战总期限或重置错误次数。
- POST `/api/login/cancel` `{}` -> `{ok:true}`；撤销当前来源 IP 对应的挑战并清除挑战 Cookie，不撤销其他完整会话。
- POST `/api/logout` `{}` -> `{ok:true}`
- POST `/api/password` `{current_password,new_password}` -> Session（撤销全部旧会话和挑战、返回新会话）。启用邮箱验证时必须持有匹配当前策略及认证版本的已验证会话。首次密码必须修改，修改前业务访问仅允许session/password/logout。
- GET `/api/status` -> 下述状态
- GET `/api/settings` -> 下述配置
- PUT `/api/settings` -> 提交完整可写配置含revision；返回更新后的配置
- POST `/api/actions/run` `{}` -> `{accepted:true,message}`：触发原 DSM 任务，包含失败邮件链路；不得强制申请证书
- POST `/api/actions/renew` `{}` -> `{accepted:true,message,request_id,manual_renewal}`：提交一次性立即申请请求并触发原任务；需要完整登录、完成首次改密、同源 JSON 和 CSRF，不接收客户端 `force`、目标域名或命令参数。接受请求不等于申请成功。
- POST `/api/actions/check` `{}` -> `{accepted:true,message}`：异步预检，不签发/部署
- GET `/api/failures` -> `{items:[{id,at,stage_label,summary,code}]}`
- GET `/api/failures/{id}` -> `{id,report,logs:[{name,text}]}`，仅脱敏归档
- GET `/api/audit` -> `{items:[{at,action,success,message}]}`，不含原始参数
- GET `/api/security` -> 下述访问安全结构；需要已完成首次改密的登录会话。
- PUT `/api/security` `{access_mode:"lan"|"public",revision:"32位十六进制"}` -> 更新后的访问安全结构；需要同源 JSON、登录及 CSRF 校验，版本冲突返回409。只允许切换预定义模式，不接收网段、端口或任意防火墙规则。
- GET `/healthz` -> `{ok:true}`，仅健康检查，不暴露业务信息

## 邮箱登录与会话

```text
Session = {
 username, csrf_token, must_change_password,
 email_verification_enabled,
 login_email_masked? // 仅启用邮箱验证时存在
}
Challenge = {
 verification_required:true,
 email_masked,
 expires_in,   // 当前验证码剩余秒数；发送中或发送失败时为0
 resend_after  // 本轮60秒发送间隔的剩余秒数，不代表其他额度已恢复
}
```

密码通过仅创建 `__Host-certweb_challenge`，不返回 Session、业务 CSRF Token、原始邮箱或验证码；初次发送成功返回202，失败返回503 `mail_unavailable`，仍设置挑战 Cookie以便恢复和重发。密码正确的新登录会撤销当前 Cookie 对应的旧会话，并替换该账号此前未完成的挑战。完整 Cookie 为 `__Host-certweb_session`；两种 Cookie 都为 Secure、HttpOnly、SameSite=Strict、Path=/，无 Domain。

验证码有效期300秒；挑战总有效期600秒，绑定实际 IPv4 来源，重发不延长期限。仅 `ready` 状态可验证，六位码以挑战随机令牌为密钥保存 HMAC，数据库不存明文码或明文挑战令牌。验证、累计错误计数、一次性消费及会话签发在同一数据库事务中完成；累计错误5次删除挑战。完成邮箱验证前不得访问业务接口，成功后再执行首次改密门控。

发送最少间隔60秒，所有发送额度在发信前原子预留，失败也计数。后端持久限制：单账号15分钟5次、1小时10次、24小时20次；单IP15分钟10次、24小时40次；全局15分钟40次、24小时200次。主机另有独立的持久60秒间隔与15分钟5次限制。重启、重置密码或重新启用邮箱验证不会清空发送记录。密码登录和改密仍分别使用15分钟窗口：同IP+账号5次、同IP15次、全局40次。

常见错误：密码不正确为401 `invalid_credentials`；验证码错误为400 `invalid_code`；验证码过期或未完成发送为400 `code_expired`；挑战过期、已消费、次数耗尽、来源IP或认证版本不匹配为410 `challenge_expired`；发送额度不足为429 `rate_limited`。429响应当前统一带 `Retry-After: 900`，实际小时/日额度仍以服务端记录为准。接口均拒绝额外收件人、邮件主题及正文参数。

发信失败使该轮验证码失效；服务端请求取消会按发送轮次撤销 `sending` 或 `ready` 状态，迟到的工作线程不能再次激活，旧轮次取消也不能撤销新轮次。用户“返回登录”删除整个挑战。网络断开不能证明服务端操作已取消：前端应先恢复状态；HTTP成功但JSON解析失败也视为结果未知，通过显式“重新确认登录状态”先读取 `/api/session`，401时再读取 `/api/login/challenge`，不得自动重发或重复提交验证码。

会话闲置30分钟、绝对8小时；状态和访问安全的后台轮询不刷新闲置时间。启用邮箱验证后，旧单因素会话以及认证级别、账号版本或邮箱策略版本不匹配的会话均失效。改密、密码重置、启停邮箱验证、邮箱策略变更会撤销全部旧会话和挑战；重置密码保留邮箱验证要求。邮箱策略缺失或损坏时已启用账号拒绝登录，不自动降级。

主机原工具目录的 `web/login-email.json` 为 root 私有0600文件，所在目录0700，结构为 `{recipient:"admin@example.com",policy_version:"随机32位小写十六进制"}`。后端通过私有终端执行 `python -m web.backend enable-email-login --username admin --email admin@example.com --policy-version <同一版本>` 配置；两处邮箱和版本必须一致，更换绑定时生成新版本。网页只展示脱敏地址，不提供绑定更换或停用接口；首次验证码通过后确认绑定已验证。紧急停用仅通过私有终端 `disable-email-login --username admin`，撤销会话并记录审计。主机策略和认证数据库不提交仓库，部署操作示例见 [README](README.md#绑定登录邮箱)。

## 状态结构

### 操作验证、会话与安全提醒

以下接口要求完整登录、已完成首次改密；写请求同时要求同源 JSON 和 CSRF。未完成登录邮箱启用与验证时，操作授权返回403 `email_security_required`，不回退到单因素授权。

- POST `/api/stepup/start` `{method,path,body}`：为固定操作和完整请求体创建验证挑战并发送固定模板邮件。响应为 `{verification_required:true,challenge_id,email_masked,operation,expires_in,resend_after}`。相同会话、来源和内容的有效挑战可以恢复，不自动再次发送。
- GET `/api/stepup/challenge`：读取本会话当前挑战或 `{verification_required:false}`，不发送邮件、不刷新会话闲置时间。
- POST `/api/stepup/resend` `{challenge_id}`：重发有效挑战的新码，不重置累计错误次数或延长总期限。
- POST `/api/stepup/verify` `{challenge_id,code}`：验证成功返回 `{token,expires_in}`，只在内存中用于接下来一次原操作；错误码400 `invalid_code`、410 `stepup_expired`，不能误当成401而注销有效会话。
- POST `/api/stepup/cancel` `{challenge_id}`：删除当前会话拥有的指定挑战与授权；不执行原操作。
- GET `/api/sessions` -> `{items:[{id,ip,device,created_at,last_seen,current}]}`。编号为独立随机值，不能使用会话 Cookie 或其哈希代替；旧会话来源可为空、设备可为unknown。不延长闲置时间。
- POST `/api/sessions/revoke` `{id}`、POST `/api/sessions/revoke-others` `{}` -> `{ok:true,current_revoked:boolean}`；验证和撤销在同一事务完成，只处理自己的会话。撤销当前会话清除 Cookie；其他浏览器下一次请求返回401。
- GET `/api/security-alerts` -> `{items:[{id,event_type,at,source_ip,device,status,attempts}],pending_count}`。状态为 `pending/sending/sent/failed`，最近50条；待处理计数覆盖该账号整个队列。不延长闲置时间。

保护范围为 `PUT /api/settings`、`PUT /api/security`、`PUT /api/monitor`、`POST /api/actions/renew`、会话撤销及普通改密。缺少授权、授权不匹配或已消费时返回428 `stepup_required`；提交格式正确的授权但挑战缺失、过期或来源不匹配时返回410 `stepup_expired`，两者均尚未调用宿主业务接口。首次改密沿用刚完成的登录邮箱验证与当前密码，不造成首次改密门控循环。普通检查 `/api/actions/run`、系统预检 `/api/actions/check` 和原生自动任务不要求操作授权。

操作标识固定为 `settings.update/security.update/monitor.update/renew/sessions.revoke/sessions.revoke_others/password.change`。挑战绑定会话、实际来源 IP、账号版本、邮箱策略和规范化方法/路径/请求体摘要，期限300秒，累计5次错误后失效。授权只保存哈希，最长120秒且不超过挑战期限，在事务中单次消费。变更内容不能复用授权，退出、改密、策略变化和会话撤销令旧授权失效。数据库不保存原始业务请求或验证码。

操作验证码采用独立于登录验证码的持久发送额度：同账号至少间隔60秒、15分钟5次、1小时10次、1天20次；同IP15分钟10次；全局15分钟40次、1天200次。发送失败也计数；取消和迟到的发送结果不能恢复已经撤销的挑战。前端只在明确428之后进入验证并提交一次原请求；65秒网络超时不包含人工输入验证码的等待，网络或结果不确定时不自动重放。

安全提醒类型为 `new_login/login_failures/security_change`，固定发至已验证登录邮箱。按实际IP与设备类型识别当前邮箱策略下30天内未见来源；同账号、邮箱策略、IP和类型15分钟内合并。队列在认证数据库持久化，使用租约串行投递，重启后继续；最多8次尝试、退避最高1小时，超过7天停止重试。保留上限200条、30天，无法匹配当前邮箱策略的旧提醒停止投递，不发送到新绑定邮箱。邮件失败不撤销已成功的业务操作，不占用原续期锁或复用证书通知待办。

### 运行健康与执行记录接口

- GET `/api/health`：返回 `server_time`、`timezone`、`runtime`、`supervisor`、`upgrade`、`events`、`monitor`。`runtime` 含 `checked_at`、`stale`、`stale_after_seconds:45`、固定 `components` 和容器安全指标；组件键为 `container/bridge/tls/access/monitor`，状态为 `ok/warning/error/unknown`。`monitor` 含独立检查时间、`stale_after_seconds:180`、任务启停、计划支持情况、最后完成时间、下次应执行时间、漏跑次数、证书剩余秒数、事件和脱敏投递状态。快照过期、来自未来或监测设置尚未应用时，不显示为健康；前端按服务器时刻、保守计入的本次请求耗时及接收后的单调经过时长判断过期；刷新等待期间不能重置旧快照年龄。
- GET `/api/monitor`：返回 `{revision,enabled,missed_runs,grace_minutes,expiry_hours,notification_enabled,recipient,interval_seconds:60}`。`recipient` 脱敏，发送开关和收件人来自原任务失败通知设置。
- PUT `/api/monitor`：只接受 `{revision,enabled,missed_runs,grace_minutes,expiry_hours}`；`revision` 为 64 位十六进制摘要，整数范围分别为 `1..6/5..120/1..168`。有独立配置锁、原子写入和冲突校验，不修改续期计划或证书。成功表示已保存，监测将在下一次检查应用；结果未知时必须重新读取确认。
- GET `/api/runs?offset=0&limit=20`：返回 `{items,total,offset,limit,warning}`；只允许这两个查询参数，不接受重复参数，`offset:0..500`、`limit:1..50`。列表为摘要，阶段详情由详情接口读取；保存记录故障时 `warning` 为固定中文提示，否则为 null。
- GET `/api/runs/{id}`：ID 格式为 `run-YYYYMMDDTHHMMSSZ-32位小写hex`；返回 `{id,kind,status,started_at,finished_at,duration_seconds,domains,certificate_id,summary,stages}`。`kind` 为 `routine/forced/recovery/check`，状态为 `running/succeeded/skipped/failed/interrupted`；`stages` 项包含 `stage,label,status,started_at,finished_at,duration_seconds,message`，额外允许 `unknown` 状态。同一阶段可能多次出现，时间未知字段为 null，不能把 null 显示成 0 秒。

预警默认 `{enabled:true,missed_runs:2,grace_minutes:15,expiry_hours:24}`。漏跑次数按受支持计划中超过宽限且未出现新完成记录的执行时刻计算；成功、失败结果均计为执行过。任务暂停取消漏跑判断，不取消证书临期判断；关闭原任务失败通知则不发送监测邮件。仅已发送告警且确认恢复的事件发送恢复邮件，不因暂停任务或状态不可读发送恢复邮件。预警配置不修改原续期窗口或任务计划。

运行记录在新一轮开始和最终结果写入时清理，限制 500 条、30 天；只读查询不触发删除，因此停止执行期间仍可能读到超期记录。进程或工作线程身份已失效且未保存终态的记录投影为 `interrupted`，未知结束时刻和耗时为 null，不将其推断为证书操作失败。

以上接口均需完整登录，写操作额外要求同源 JSON、CSRF 与审计。新观测 GET 请求不延长闲置会话。匿名 `/healthz` 仍只返回存活结果，不包含上述业务信息。新的固定 RPC 方法为 `health`、`monitor.get`、`monitor.update`、`runs.list`、`runs.get`，不接受任意路径、命令或 Docker 参数。

### 启动检查

主机监督程序取得独占锁后，以本次启动标识及开始时间异步调用固定 `startup_check.py`，不依赖管理页 HTTPS 健康。首个运行容器建立基线，不重复投递；后续容器 ID 或 `StartedAt` 变化触发新的启动检查。每次启动复用原 DSM 普通任务，不传强制续期参数、不创建第二套周期计划；暂停时延后，续期锁占用时延后，启动后已完成的普通执行覆盖该次检查。在最后一次 DSM 任务查询及命令定位通过后、真正调用运行命令前，将启动标识与状态写入 root 私有 `startup-check.json`。确定尚未投递的临时错误返回可重试状态；未知投递结果不重放。网页刷新、监督轮询、HTTPS 工作进程重载不构成容器新启动。新安装任务默认自适应模式，日常时间为 NAS 本地时间 03:18；已有任务升级时保留自定义计划。

### 原续期状态

```
{
 certificate:{id,description,domains:[...],not_after:"ISO8601",fingerprint,remaining_seconds,renew_at:"ISO8601"},
 renew_before_days:2,
 task:{enabled:true,running:false,schedule_text:"每天03:18",last_run:null},
 last_result:null,
 pending:{deployment:false,dns_cleanup:false,notification:false,interrupted:false},
 check:{running:false,last_result:null},
 manual_renewal?:{request_id,state,message,requested_at:"ISO8601",cooldown_until:"ISO8601",completed_at?:"ISO8601"},
 server_time:"ISO8601",timezone:"Asia/Shanghai"
}
```
`last_result` 与 `check.last_result` 如非null为 `{at,success,message,...}`；UI 使用缺省兜底，不显示原始未知对象。

### 一次性立即申请

`manual_renewal` 仅在存在请求记录时返回；`state` 为 `queued`、`running`、`succeeded`、`failed` 或 `expired`。页面以状态与实际证书指纹判断进展，不把动作响应中的 `accepted:true` 当作成功，也不把普通检查的成功结果替代申请结果。

请求固定作用于当前配置的证书和域名，主机记录基线指纹与绑定，10分钟内未消耗则过期；从提交时起冷却1小时，即使任务调度未确认、失败或服务重启也不重置。排队/运行中阻止重复申请、配置保存、预检和普通手动运行。未完成的部署、恢复、DNS清理、通知或新候选证书阻止新增申请；相关冲突返回409。

请求存于原工具 `state/manual-renewal.json`，通过共享任务锁协调，调用ACME前持久记录已消耗并同步文件及目录。原任务启用状态不改变；调度异常仍保留请求，返回安全提示，前端继续查询状态。有ACME材料时使用 `--renew --force`；没有材料或已隔离损坏材料时使用 `--issue`。客户端不传递命令或路径。

成功必须取得与基线不同指纹的新证书，完成域名、私钥、链验证、DSM替换、实际HTTPS验证、DNS清理和通知。acme.sh返回2、缺少新材料或只有原指纹均不能标记成功。签发结果未知、中断、部署或通知失败后，已消耗请求只继续使用现有材料恢复，不能重新执行该请求的强制签发；缺失/损坏材料也不得通过恢复或首次申请分支重复签发。

恢复门控在下一正常续期窗口且不早于1小时冷却后解除；之后沿用普通续期策略，不重放强制标志。无自定义续期窗口的旧配置在冷却后恢复原策略。没有取得新材料的失败请求，仅在原证书及绑定未变、候选仍为原指纹或不存在、无其他恢复/清理/通知待办，且保护标记归属于该请求时，允许安全释放该请求的保护；可修复配置或在冷却后提交新的显式请求，防重放记录保留。新候选或不明归属的标记不能据此清除。

## 配置结构

```
{
 revision:"sha256",
 certificate_id:"...",
 description:"...",
 domains:[...],
 certificates:[{id,description,domains:[...]}],
 email:"...",
 renew_before_days:2,
 secret_id_configured:true,secret_key_configured:true,
 probes:[{host:"127.0.0.1",port:5001,server_name:"ttxli.cn"}],
 schedule:{enabled:true,mode:"adaptive",interval_hours:1,hour:3,minute:18,active_mode:"daily",editable:true,message:"..."},
 notifications:{success_enabled:true,success_email:"...",failure_enabled:true,failure_email:"..."},
 deployment_method:"local_api",timezone:"Asia/Shanghai"
}
```
PUT 只接收 revision,certificate_id,email,renew_before_days,probes,schedule,notifications,secret_id,secret_key。描述和域名从群晖所选证书派生，不直接编辑。secret_id/secret_key 为write-only，可选空串或省略表示保留，两项更换须同时提供；绝不回显。服务端校验续期1..30天、端口1..65535、邮箱、域名/IP、目标证书、每小时频率1/2/3/4/6/8/12或每天固定时分、分钟0..59。

`schedule.mode` 支持 `adaptive/daily/hourly/unsupported`（最后一种只读）；PUT仍只发送 `enabled/mode/interval_hours/hour/minute` 五项，自适应 `interval_hours` 为 1，`active_mode`、`editable` 和 `message` 只用于展示。`adaptive` 日常采用指定时分，当前证书剩余不超过 48 小时或恢复未完成时改为每小时指定分钟；只有当前证书成功结果指纹吻合、已验证并无待办才允许降为每日。不改变 `read_schedule` 对物理 DSM 计划的解释，独立预警继续按实际计划计算漏跑。

配置偏好 `state/web-preferences.json` 可含 `adaptive_schedule:{version:1,hour,minute}`，缺省代表固定计划。自适应同步器每分钟读取此设置，在 `run.lock` 内确认任务身份与当前计划，只调整原任务的物理日/小时频率，不执行签发或建立新任务；暂停、未恢复配置事务及手工修改冲突均保留原状态。

配置更新需共享certctl互斥锁、revision冲突检测、对当前配置和DSM任务备份并可回滚；保留所有恢复与通知待办标记。检测到未完成恢复、绑定变化等会阻止不安全的目标切换。

## 访问安全结构

```
{
 lan_only:true,
 allowed_networks:["10.10.10.0/24"],
 https:true,
 session_idle_minutes:30,
 session_absolute_hours:8,
 access_mode:"lan",
 applied_mode:"lan",
 revision:"32位十六进制",
 pending:false
}
```

`access_mode` 是已保存的策略，`applied_mode` 是监督进程记录的实际防火墙模式，`pending` 表示策略尚待应用。策略版本独立于证书配置的 `revision`，写请求必须使用最新 GET 返回的32位十六进制版本。页面不得把“保存成功”直接当作防火墙已经生效，应按返回状态显示待应用并复查。

`lan` 仅允许配置的内网网段，并排除网关；`public` 允许任意 IPv4 来源，包括网关。两种模式都保持指定内网 IPv4 监听地址、IPv6 拒绝、HTTPS、登录、Host/Origin/CSRF 校验、限流及代理头拒绝。公网 TCP 端口映射由用户配置，不由此接口创建；此接口也不配置 HTTP 反向代理。

主机策略位于 `/usr/local/share/synology-cert-web/access/access.json`，格式 `{mode,revision}`；目录权限0750、属主root:10100，文件权限0640。`applied.json` 记录实际应用模式。该目录只读挂载到容器 `/access`，后端读取策略和实际模式，写入仅通过 `security.update` RPC。策略缺失、损坏或无效时禁止访问，不回退到 `public`。

监督进程每10秒读取并应用策略，可能短暂重启管理容器；切换不修改原证书配置或DSM任务。切回 `lan` 时当前公网浏览器可能失联，需从允许的内网重新进入。页面不可用时可通过 NAS root 命令 `deployment.py set-access-mode --mode public`（或 `lan`）恢复；不需手动重启。

## Unix socket

位置由 `CERTWEB_BRIDGE_SOCKET` 配置。每个连接一条 UTF-8 JSON + 换行，请求最大64KiB，响应上限2MiB，超时60秒。请求 `{"method":"settings.get","params":{}}`。响应 `{"ok":true,"data":...}` 或 `{"ok":false,"error":{"code":"...","message":"..."}}`。

固定方法：status、settings.get、settings.update（params直接为PUT对象）、security.update（params为`{access_mode,revision}`）、run、renew、check、failures.list、failures.get（params:{id}）、auth.code.send（params为`{code,policy_version}`）、auth.stepup.send、auth.security.send（两者参数见下文）、health、monitor.get、monitor.update（params为对应PUT对象）、runs.list（params为`{offset?,limit?}`）、runs.get（params为`{id}`）。除明确列出参数的方法外只接受空对象。`security.update` 仅写入访问策略，不修改证书配置、任务计划或立即执行任意防火墙命令。`renew` 提交上述一次性请求，不接收客户端强制参数。不得接收任意命令、任意路径或shell字符串。

`auth.code.send` 仅在密码验证通过或有效挑战重发时由后端调用。主机严格核验六位ASCII数字、策略版本和固定参数集合，收件人只能从root私有策略读取，主题和正文使用固定模板；复用DSM通知邮件配置，成功仅返回 `{accepted:true}`，不回显验证码、邮箱或邮件配置。策略不一致或邮件失败只返回固定错误。主机邮件配置读取超时10秒、SMTP发送超时25秒，输出和错误输出丢弃并回收超时进程；后端将发信等待限制在最多50秒并为请求总超时留出余量，不把登录邮件写入证书续期的待发通知状态。

`auth.stepup.send` 只接受 `{code,policy_version,operation}`，操作为上述固定枚举，主机有独立60秒间隔及15分钟5次额度。`auth.security.send` 只接受 `{event_id,event_type,policy_version,at,source_ip,device}`：ID与策略为32位小写hex、时间为UTC ISO格式、来源为合法IP，设备只允许 `desktop/mobile/tablet/other/unknown`。主机依固定模板构造邮件，不接受自定义收件人、主题、正文或原始 User-Agent。安全提醒使用独立锁，至少间隔15秒、每小时10次、每天40次，失败也计数；成功事件ID与载荷摘要保存30天用于重试去重，同ID不同载荷被拒绝。SMTP接受后若本地成功记录或响应丢失，仍可能再次发送。以上两类邮件均不获取证书执行锁或调用续期任务。

Bridge root运行，socket仅授权容器 UID/GID 10100 访问；部署目录root私有，socket专用目录root:10100 0750，socket0660。不把完整配置、原始日志、Docker socket或DSM证书目录挂载给容器；访问策略目录以只读方式单独挂载。

## 分工

host_bridge：web/host_bridge.py、web/host_service.py（如需）、tests/test_web_bridge*.py。
web_api：web/backend/、web/requirements*.txt、tests/test_web_api*.py。
web_frontend：web/frontend/。
root：web/CONTRACT.md、Docker/Compose/安装启动网络规则/部署文档与整体集成。
