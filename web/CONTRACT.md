# 证书管家接口契约

正式管理界面采用 Vue 3 + TypeScript。Docker 内运行 HTTPS 管理 API 与静态资源，群晖现有 root 执行器保持运行；通过受限 Unix socket 控制原任务，不在容器重复安排续期。

## 浏览器 API

成功返回 JSON 对象本身；错误 HTTP 400/401/403/409/429/502/503，格式 `{"error":{"code":"...","message":"中文安全摘要"}}`，不得携带原始异常/命令/密钥。

- GET `/api/session` -> `{username,csrf_token,must_change_password}`；未登录返回401。所有写请求使用 `X-CSRF-Token`；登录也要求同源JSON请求，服务器不信任代理头。
- POST `/api/login` `{username,password}` -> session；HttpOnly Secure SameSite=Strict cookie。
- POST `/api/logout` `{}` -> `{ok:true}`
- POST `/api/password` `{current_password,new_password}` -> session（撤销旧会话、返回新会话）。首次密码必须修改，修改前只允许session/password/logout。
- GET `/api/status` -> 下述状态
- GET `/api/settings` -> 下述配置
- PUT `/api/settings` -> 提交完整可写配置含revision；返回更新后的配置
- POST `/api/actions/run` `{}` -> `{accepted:true,message}`：触发原 DSM 任务，包含失败邮件链路；不得强制申请证书
- POST `/api/actions/check` `{}` -> `{accepted:true,message}`：异步预检，不签发/部署
- GET `/api/failures` -> `{items:[{id,at,stage_label,summary,code}]}`
- GET `/api/failures/{id}` -> `{id,report,logs:[{name,text}]}`，仅脱敏归档
- GET `/api/audit` -> `{items:[{at,action,success,message}]}`，不含原始参数
- GET `/api/security` -> 下述访问安全结构；需要已完成首次改密的登录会话。
- PUT `/api/security` `{access_mode:"lan"|"public",revision:"32位十六进制"}` -> 更新后的访问安全结构；需要同源 JSON、登录及 CSRF 校验，版本冲突返回409。只允许切换预定义模式，不接收网段、端口或任意防火墙规则。
- GET `/healthz` -> `{ok:true}`，仅健康检查，不暴露业务信息

## 状态结构

```
{
 certificate:{id,description,domains:[...],not_after:"ISO8601",fingerprint,remaining_seconds,renew_at:"ISO8601"},
 renew_before_days:2,
 task:{enabled:true,running:false,schedule_text:"每小时第17分钟",last_run:null},
 last_result:null,
 pending:{deployment:false,dns_cleanup:false,notification:false,interrupted:false},
 check:{running:false,last_result:null},
 server_time:"ISO8601",timezone:"Asia/Shanghai"
}
```
`last_result` 与 `check.last_result` 如非null为 `{at,success,message,...}`；UI 使用缺省兜底，不显示原始未知对象。

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
 schedule:{enabled:true,mode:"hourly",interval_hours:1,hour:0,minute:17},
 notifications:{success_enabled:true,success_email:"...",failure_enabled:true,failure_email:"..."},
 deployment_method:"local_api",timezone:"Asia/Shanghai"
}
```
PUT 只接收 revision,certificate_id,email,renew_before_days,probes,schedule,notifications,secret_id,secret_key。描述和域名从群晖所选证书派生，不直接编辑。secret_id/secret_key 为write-only，可选空串或省略表示保留，两项更换须同时提供；绝不回显。服务端校验续期1..30天、端口1..65535、邮箱、域名/IP、目标证书、每小时频率1/2/3/4/6/8/12或每天固定时分、分钟0..59。

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

固定方法：status、settings.get、settings.update（params直接为PUT对象）、security.update（params为`{access_mode,revision}`）、run、check、failures.list、failures.get（params:{id}）。`security.update` 仅写入访问策略，不修改证书配置、任务计划或立即执行任意防火墙命令。不得接收任意命令、任意路径或shell字符串。

Bridge root运行，socket仅授权容器 UID/GID 10100 访问；部署目录root私有，socket专用目录root:10100 0750，socket0660。不把完整配置、原始日志、Docker socket或DSM证书目录挂载给容器；访问策略目录以只读方式单独挂载。

## 分工

host_bridge：web/host_bridge.py、web/host_service.py（如需）、tests/test_web_bridge*.py。
web_api：web/backend/、web/requirements*.txt、tests/test_web_api*.py。
web_frontend：web/frontend/。
root：web/CONTRACT.md、Docker/Compose/安装启动网络规则/部署文档与整体集成。
