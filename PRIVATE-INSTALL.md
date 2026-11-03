# 私有仓库单命令安装

适用：自己使用、仓库保持私有，DSM 7 / x86_64 NAS。仅安装证书管理项目及其必需组件，不安装或升级 DSM。

以下在线命令从本私有仓库的 `main` 获取安装入口，需要该仓库的读取授权；无法下载时会停止，不继续安装。

## 首次准备

在 GitHub 创建短期有效的 fine-grained personal access token，仅选择 `784933671/synology-cert-renewal` 仓库，授予 **Contents: Read-only**；不要提供写权限。下载流程按 GitHub [Contents](https://docs.github.com/en/rest/repos/contents) 和 [Git trees](https://docs.github.com/en/rest/git/trees) API 使用此只读权限。

NAS 管理员通过 SSH 登录后，复制下面整行执行。`sudo` 先请求 NAS 密码，随后提示 GitHub 令牌；两者输入均不显示字符。令牌不要放进命令文本、截图或聊天。

```sh
sudo sh -c 'set -eu; set +x; umask 077; test -f /etc.defaults/VERSION || { echo "请在群晖 NAS 的 SSH 终端执行。" >&2; exit 1; }; d=$(mktemp -d /tmp/cert-bootstrap.XXXXXX); saved_tty=; trap '"'"'if [ -n "$saved_tty" ]; then stty "$saved_tty" </dev/tty; fi; rm -rf "$d"'"'"' EXIT; trap '"'"'exit 130'"'"' INT; trap '"'"'exit 143'"'"' TERM; saved_tty=$(stty -g </dev/tty); unset cert_install_token; printf "GitHub 只读令牌（隐藏输入，非 NAS 密码）: " >/dev/tty; stty -echo </dev/tty; IFS= read -r cert_install_token </dev/tty; stty "$saved_tty" </dev/tty; printf "\n" >/dev/tty; case "$cert_install_token" in ""|*[!A-Za-z0-9_]*) echo "令牌格式无效。" >&2; exit 1;; esac; printf '"'"'header = "Authorization: Bearer %s"\n'"'"' "$cert_install_token" | curl -qfsS --proto '"'"'=https'"'"' --tlsv1.2 --connect-timeout 20 --max-time 120 --max-filesize 1048576 -H '"'"'Accept: application/vnd.github.raw+json'"'"' -K - '"'"'https://api.github.com/repos/784933671/synology-cert-renewal/contents/bootstrap-private.sh?ref=main'"'"' -o "$d/bootstrap.sh"; printf '"'"'%s\n'"'"' "$cert_install_token" | sh "$d/bootstrap.sh" --token-stdin'
```

这仍是一条命令，后续首次安装按提示输入 DNSPod 密钥、目标证书、管理域名、邮箱和管理员密码。默认复用已有环境，已有安装进入原安装器的保留配置升级。GitHub 令牌只用于本次下载，保存在进程内存和管道中，不写入参数、环境变量、缓存清单或项目配置；下载后安装进程不会继承该令牌。初始脚本通过 HTTPS 从固定私有仓库读取，随后固定一次提交 SHA，并逐文件核对 Git blob 摘要。

## 自动处理范围

- 检测 DSM 7、x86_64 和 Python 3.8+。缺少 Python 时，若本机 `synopkg --help` 支持 `install_from_server`，尝试通过群晖套件中心安装 `Python3`，随后重新验证解释器；仍不满足则明确停止。
- 复用可用的 Docker/Compose，不重启已有正常服务。已有 Docker 套件未启动时启动对应套件；缺少时通过套件中心安装 DSM 对应的 `ContainerManager` 或 `Docker`，不下载第三方安装脚本、不卸载现有套件。官方包不可用或需要额外确认时，先按提示在套件中心完成，再重复本命令。
- 下载私有仓库源码并校验，调用原 `setup.sh` 完成 acme.sh、管理镜像构建、权限、认证、开机启动、任务和真实 HTTPS 检查。当前继续在 NAS 构建镜像，尚未提供预构建镜像发布流程。
- 中断或失败后，再次执行同一命令复用原提交缓存，避免新版源码与半完成安装混用。若发现其他入口留下的未完成安装，要求用原源码包恢复，不能用新版本覆盖进度。

域名注册、腾讯云子账号授权、DSM 通知邮箱配置、目标证书条目和路由器/DNS 设置仍需事先准备；安装器不会猜测这些账号及网络参数。首次安装和真实邮件/证书验收仍需在目标设备完成。

## 私有缓存与验证

下载缓存位于 `/usr/local/share/synology-cert-bootstrap`，目录仅 root 可访问。`pending.json` 只记录当前未完成安装的提交编号；安装成功后删除该记录。执行使用临时副本，原始校验缓存不受 Python 缓存文件影响。归档拒绝路径越界、符号链接、硬链接、额外/重复文件和超大内容；私有归档重定向只允许 GitHub 下载主机，并移除授权头。

本入口测试命令：

```sh
python3 -m unittest tests.test_private_bootstrap -q
```

自动化夹具测试验证授权边界、源码完整性、中断恢复及依赖分支；它们不代表全新 NAS 套件安装已验收。下载源码与缓存校验可单独只读验证，不应为了测试在已有生产 NAS 上重装环境。

## 本轮验证记录（2026-11-03）

- 30 项隔离测试通过，包含真实伪终端中的隐藏输入、令牌不进入参数/环境、下载失败与取消后终端恢复、安装向导交互及成功/失败退出、官方套件分支、归档校验及中断恢复；缓存源码和执行副本与原安装器的源码摘要一致。联合安装向导、升级和打包测试共 82 项通过。
- 通过已有 GitHub 授权实际只读下载私有仓库提交 `90d5d335501c3aff2d5c2c7de0371e92e8c9cd24`，162 个文件、2,336,765 字节逐项摘要一致；未调用任何安装命令。
- Shell 和 Python 3.8 语法检查通过。入口随本版本发布；尚未在全新 NAS 上验收自动补齐套件或执行完整安装。
