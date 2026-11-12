# ChatGPT 安全 MCP 隧道（Secure MCP Tunnel）

ReverseResearch 内嵌 OpenAI 官方的 `github.com/openai/tunnel-client` Go SDK。常规运行时仍然是单个进程：

```text
ReverseResearch.exe
  |- unified MCP server
  |- OpenAI Secure MCP Tunnel (in-process, optional)
  |- x32dbg module (lazy)
  |- Ghidra module (lazy)
  '- radare2 module (lazy)
```

不需要额外的 `tunnel-client.exe` 服务。

## OpenAI 侧一次性配置

1. 在 OpenAI Platform 的 tunnel 设置中创建一个 Secure MCP Tunnel。
2. 把该 tunnel 关联到将要使用 ReverseResearch 的 ChatGPT 工作区。
3. 确保操作者具备 Tunnels Read + Use；创建/编辑 tunnel 还需要 Tunnels Manage。
4. 为 tunnel 客户端创建一把 runtime API key。
5. 通过 ReverseResearch 已有的 tunnel 配置，或通过受支持的环境变量，配置 tunnel 身份与 API key。

不要把 API key 放进 Git、放进带真实值的 README 示例、命令历史或截图中。

## 运行时

使用以下命令启动生产 MCP 服务与 Secure MCP Tunnel：

```powershell
.\一键启动MCP.bat --tunnel
```

本机的 RR 专用连接通过 ChatGPT Secure MCP Tunnel 接入，工作区与 tunnel ID 属于本机私有配置，不随仓库分发。复制 `config/tunnel.example.json` 为 `config/tunnel.json`，填入自己的 tunnel ID；运行密钥保存在仓库外的 `$USERPROFILE/.reverseresearch/tunnel-runtime-api-key.txt`，并只授予 Tunnels Read + Use。其他本地服务的 tunnel 属于各自连接，不能作为 RR 的工具目录证据。

启动 BAT 会使用本机已有的 MCP 可执行文件；需要直接启动时运行 `ReverseResearch-MCP.exe serve --tunnel`。双击 MCP exe 的默认行为是启动本地服务，启用网页隧道仍需 `--tunnel`。

该进程通过两种传输暴露同一个 MCP 服务：

- 本地回环 HTTP `http://127.0.0.1:19100/mcp`，用于诊断；
- 到内嵌 Secure MCP Tunnel 的内存传输，供 ChatGPT 使用。

x32dbg、Ghidra 与 radare2 后端仍然是惰性的。连接 ChatGPT 或扫描工具都不会启动它们；只有某个后端工具真正被调用时，对应后端才启动。一个完成升级发布的 ReverseResearch 进程可以对已有的回环 Ghidra daemon 认证并接管它，因此升级不需要关闭其已打开的分析数据库。

Windows 上的隧道按每次请求的当前网络配置选路：显式 `HTTPS_PROXY`、`HTTP_PROXY`、`ALL_PROXY` 和 `NO_PROXY` 优先；未设置显式代理时读取当前用户的手动系统代理和 bypass。代理关闭后使用 Windows 路由表，虚拟网卡由操作系统处理。运行期间切换模式或代理地址无需重新编译或重启 MCP，也无需配置 VPN 厂商、网卡名或固定端口。

自动系统代理发生传输失败后，SDK 的后续尝试可在15秒内改走系统路由，随后重新尝试当前代理；显式环境代理保持用户指定的路径。认证和业务 HTTP 错误不会触发换路。代理与系统路由有各自的 HTTP/2 连接池；正在执行的请求按原期限结束，后续请求读取新设置。适配器不重放请求，轮询、MCP 转发和重试仍由固定 SDK 负责。日志只显示代理协议/主机/端口，隐藏凭据；本地监听就绪和首次云端轮询成功分别报告。

## Windows 本地安装加固

ReverseResearch 的持久状态与本地后端 bearer/配置文件属于机器私有的本地数据。在 Windows 上，生产文件不应继承给其他普通本地账户的写权限。

审计当前安装：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\harden-local-install.ps1 -Action Audit
```

需要时施加私有 DACL 到本地安装目录：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\harden-local-install.ps1 -Action Apply
```

加固后的边界只授予当前用户、SYSTEM 与 Builtin Administrators 完全控制权限。运行时还会在上述路径被打开或创建时，重新对 `state`、`evidence`、本地 MCP bearer、Ghidra daemon 状态以及 xdbg MCP token 配置施加私有 ACL。

全树 Apply 始终保留 Root 的 protected private DACL，只重置子项；链接通过 `/L` 处理链接自身。发布和回滚先在停服前完成全树准备，替换后仅沿原权限 owner 修复/审计关键路径，避免在服务已停止时重复扫描全部资料。`-Action Repair` 只恢复 Root 与重要运行路径的私有权限，不执行递归 reset；它不代替首次安装或全面维护时的 Apply。

中断恢复时先核对 `.tmp/promotion/promotion.json` 的状态、准确目的路径和当前 EXE SHA。已 applied 的产物在完成权限 Repair/Audit 后，可沿原 `manage-autostart.ps1 -Action Restart` 恢复任务，不重新 publication；prepared 或 SHA 不匹配时必须先复查，不以启动服务绕过 receipt。

## Windows 登录自启动

安装按用户的 Scheduled Task：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-autostart.ps1 -Action Install
```

查看、优雅重启、停止或移除它：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-autostart.ps1 -Action Status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-autostart.ps1 -Action Restart
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-autostart.ps1 -Action Stop
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-autostart.ps1 -Action Remove
```

`Restart` 与 `Stop` 使用私有的本地 bearer 调用 `POST /control/shutdown`；服务端随后会在进程退出前关闭自己的 MCP/后端会话。Restart 会等待干净退出，再重新拉起规范的任务。这是必需的生产重启路径；正常升级时不要使用强制杀进程。
规范任务为当前交互式用户，从仓库根目录运行现有 MCP 可执行文件的 `serve --tunnel`，并在瞬时失败后重启。可执行文件选择与 `一键启动MCP.bat` 一致：依次使用 `dist/ReverseResearch-MCP.exe`、根目录 `ReverseResearch.exe`、根目录 `ReverseResearch-MCP.exe`。编译产物移动后，先用 Install 更新同名任务，再用 Restart 优雅重启；Status 会核对任务是否仍指向当前选中的产物。

## ChatGPT 应用

在 ChatGPT 开发者模式中：

1. 打开 Apps -> Create。
2. 选择 `Tunnel` 作为连接类型。
3. 选择与该工作区关联的 tunnel，或填入其 `tunnel_id`。
4. 每次服务端 schema 升级发布后都重新扫描/扫描工具。
5. 确认已连接的目录与当前的生产服务端目录一致。
6. 创建或刷新该应用连接。

2026-10-12 的源码 Runtime 与本机现役服务经 MCP `initialize` / `tools/list` 均返回 270 个工具，名称、输入 schema、描述一致，证据在 `evidence/mcp-coverage-20261012`。该日期之前名为 RR 的网页连接向本会话提供的是另一个本地服务的 22 个 workspace 工具；不能将其解释成 RR 的 270 个工具中只开放了 22 个。新建 RR 专用 tunnel 后，本轮已直接读取 ChatGPT 网页中的新 RR 目录：270 个名称逐一与源码一致，最近 27 个新增查询均包含；网页逐项 schema 和实际远程工具执行不由名称核对代替。238 / 124 等历史工具计数保留在历史证据中，不代表当前生产目录。

ChatGPT 新管理后台仍可能显示该 RR 的“不可用的应用”。本轮实际重试响应为 HTTP 200，但管理解析返回 `apps=[]` / `canonicalAppId=null` / `appAccessState=unknown`，同时插件设置为 enabled、用户侧 RR 已连接并列出 270。该结果定位到云端管理应用记录解析，不能仅凭 DEVELOPMENT 标记认定未发布，也不能由重编译本机 EXE 解决；相关管理权限当前不可用，保留 EXTERNAL_PENDING，等待管理端记录/解析恢复。

ChatGPT 应用指向的是 OpenAI 托管的 tunnel 身份，而不是 `127.0.0.1:19100`。

## 失败行为

- 没有 `--tunnel` 时，ReverseResearch 可以只作为本地回环 MCP 服务端运行。
- 如果请求了 tunnel 模式但无法解析 tunnel 身份/API key，启动会失败，而不是静默暴露一个误导性的部分远程状态。
- Tunnel 凭据不会被写入日志。
- 本地 MCP 仍然只是回环且受 bearer 保护；`/healthz` 是只读的。

### 轮询断连与恢复

从 0.4.1 起，官方 SDK 的 `level=WARN` 即使携带 `error=` 原因，也显示为黄色“警告”；真正的 `level=ERROR` 仍显示为红色“错误”。`poll timed out; backing off` / `poll failed; backing off` 表示客户端轮询没有成功，SDK 会沿同一个 tunnel 身份自动退避重试。`poller recovered; polling operational` 是 SDK 确认轮询恢复的事件，会标为绿色。不要把连续 network_error 当成正常空闲轮询，也不要靠提高超时隐藏网络故障。

30 秒摘要中的“协议成功/错误/取消”只统计 MCP 工具调用，隧道另外显示“最近观测”、事件时间和累计轮询失败次数。首次 Ready 只表示至少一次控制面轮询成功；观测是 SDK 日志的只读投影，既不持续探活，也不承担连接/重试 authority。`/healthz` 仍只证明本地服务可达，不能单独证明网页隧道畅通。

2026-10-13 用户报告的 03:08–03:10 故障只有 timeout/network_error 和缺失请求 ID，历史具体网络环节未确定；随后原 RR 原生 reverse_status 实际远程调用成功。故障再次出现时应同时核对到 `api.openai.com:443` 的出站 HTTPS、代理/VPN 连通性和 RR 原生只读调用；浏览器可访问网页不能替代服务进程的网络证据。官方说明：[Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)。
