# P4 产品化

本文档记录本地源码的 P4 增量。它并不声称线上 RR/RT 部署已经完成升级。

## P4-01 Remote Agent 只读强类型能力

状态：本地源码已闭环。

Remote Agent 保持 P3 的安全模型：强制 mTLS、签名清单、目标允许清单（allowlist）、持久化的操作收据（receipt）、签名结果、有界（bounded）的请求体、不自动重试不确定的副作用，以及不提供任意 shell。

P4-01 新增以下内置只读强类型能力：

- `artifact.metadata`
- `directory.snapshot`
- `tool.inventory`
- `process.inventory`
- `environment.fingerprint`
- `file.read_excerpt`
- `case.evidence.capture`

现有的 `artifact.inspect` 与 `artifact.hash` 能力，现在也通过同一个内置只读能力目录完成注册（registration）。

### 边界与失败即关闭（fail-closed）行为

- `directory.snapshot`：`max_entries` 默认值为 256，硬上限 4096；`max_depth` 默认值为 1，硬上限 8。
- `process.inventory`：`max_entries` 默认值为 256，硬上限 2048。
- `tool.inventory`：仅接受工具的 basename；不会执行任何路径或命令字符串；处理函数只做 PATH 查找。
- `file.read_excerpt`：`max_bytes` 默认值为 4096，硬上限 64 KiB；在有界读取之前和之后，都会针对目标身份进行当前性（currentness）校验。
- `case.evidence.capture`：生成一个可直接用于签名结果的投影，包含目标身份加一段有界摘录；它不会写入中心 Case，因此不会创建第二个 Case/Evidence 权威源。
- 每个能力都有显式的参数允许清单。未知参数一律失败即关闭。
- Remote Agent 清单现在会在清单校验/签名阶段就拒绝 PowerShell、cmd、generic exec、shell、command 以及 remote-shell 类能力，而不仅仅是在作业执行阶段才拒绝。

`process.inventory` 在 Windows 上使用 Windows Toolhelp 进程快照 API，在 Linux 上使用有界的 `/proc` 读取。其他平台在拥有平台专属的强类型实现之前一律失败即关闭。

### 校验

重点测试：

- `go test ./internal/remoteagent -count=1` PASS
- `go test ./cmd/reverseagent -count=1` PASS

竞态检测：

- `go test -race ./internal/remoteagent -count=1` PASS
- `go test -race ./cmd/reverseagent -count=1` PASS

静态门禁：

- `go vet ./internal/remoteagent ./cmd/reverseagent` PASS
- `staticcheck ./internal/remoteagent ./cmd/reverseagent` PASS
- `gofmt` PASS
- `git diff --check` PASS

候选二进制构建：

- `%TEMP%\ReverseResearch-Agent-P4-01.exe`
- 大小：11,905,024 bytes
- SHA-256: `b4f4e3ba7811c06bd634d122029e9d24258b93d843f308b62c11583ec3badd82`

候选二进制预期失败的冒烟测试：

在不提供必需的签名清单、Ed25519 私钥、TLS 服务端证书/私钥、受信客户端 CA 以及任务独占状态目录的情况下运行候选二进制，进程以退出码 1 退出并拒绝启动。这是预期的安全行为。

生产环境防护：

- 未替换任何生产环境的 `ReverseResearch.exe`。
- 未停止、重启或附加任何现有的 Ghidra/调试器进程。
- 候选二进制的输出写入到系统 TEMP 目录。
- 生产环境的状态根目录仍然不在 P4-01 的测试路径之内。


## P4-02 Remote Agent 集群（fleet）/状态

状态：本地源码已闭环。

P4-02 新增一条经过鉴权的状态通道，且不引入第二个执行权威源。

- Agent 仅通过现有的强制 mTLS 监听器暴露 `GET /v1/status`。
- 状态信封由 Agent 身份密钥以 Ed25519 签名，并绑定：Agent ID、清单 SHA-256、平台/架构、Agent 构建版本、已声明与已注册的能力、队列/结果计数器、服务端证书过期时间，以及 Agent 所观察到的 mTLS 客户端证书的 SHA-256。
- 中心侧会发起真实的 HTTPS+mTLS 请求，依据显式 CA 校验服务端证书，记录所观察到的服务端证书 SHA-256 与过期时间，并拒绝未与同一客户端证书绑定的状态响应。
- 持久化状态的替换需要 `expected_revision`；较早的/非单调递增的签名时间戳会被拒绝。
- `recent / stale / offline` 由最近一次经过鉴权的观测时间推导得出。它们是投影，而不是由 Agent 控制的标志位。
- 已过期的已注册清单仍可为集群/历史投影而读取，并被标记为 `manifest_state=expired`；在清单过期的情况下，注册、作业校验/执行以及状态刷新仍然失败即关闭。
- CLI：`agent status`、`agent fleet`、`agent refresh-status`。
- 现有 MCP 拥有者 `remote_agent_manage` 新增了 `status`、`fleet` 和 `refresh_status`；未新增第二个 Remote Agent 权威源。

安全测试包含一个进程内的 CA/服务端/客户端证书链，以及一次真实的 mTLS 状态往返，用以证明签名的状态确实绑定到经过鉴权的客户端证书。

## P4-03 统一 Dashboard 运维投影

状态：本地源码已闭环。

现有的 Case Dashboard 现在只投影已有的拥有者，而不是创建它自己的运维数据库：

- 来自现有 Job Store 的 Generic Job。
- 来自 ToolIndex 的工具清单。
- 来自 `state/remote-agents` 的 Remote Agent 注册记录与经过鉴权的集群/状态记录。
- 来自 `state/pack-registry` 的签名 Pack 信任/校验状态。

如果 Remote Agent 或 Pack Registry 状态不存在，Dashboard 渲染时会报告一个空分区，而不会仅仅为了查看就初始化一个新的权威源。

Dashboard 展示 Agent 状态、最近一次经过鉴权的观测、Agent 版本、注册修订号、清单状态、能力、队列/结果计数以及 TLS 证书状态/过期时间。签名 Pack Registry 投影展示注册表修订号、受信发布者数量与校验收据。

## P4-02/03 校验

重点测试已通过：

- `go test ./internal/remoteagent -count=1`
- `go test ./internal/dashboard -count=1`
- `go test ./internal/core -run TestP4 -count=1`
- `go test ./internal/server -run TestP3ProductToolsEnforceVerificationAndCurrentness -count=1`
- `go test ./cmd/reverseresearch -run TestP3CLIProductFlows -count=1`

针对 mTLS 状态/集群路径与 Dashboard 的竞态检查已通过；Core 的 P4 竞态校验也在隔离环境下执行过。

静态门禁：

- `go vet ./internal/remoteagent ./internal/dashboard ./internal/core ./internal/server ./cmd/reverseresearch ./cmd/reverseagent` PASS
- `staticcheck ./internal/remoteagent ./internal/dashboard ./internal/core ./internal/server ./cmd/reverseresearch ./cmd/reverseagent` PASS
- `gofmt` PASS
- `git diff --check` PASS

候选二进制构建/冒烟测试：

- %TEMP%\ReverseResearch-P4-03.exe：34,722,304 bytes，SHA-256 92fa1a8f64e034e884ded02f5ed8982fefaba45db07644c20b67eb7e6ae6032d。
- %TEMP%\ReverseResearch-Agent-P4-03.exe：11,926,528 bytes，SHA-256 6e80421922064ba3fef86ce93cc86e8a6109f21920eb48e3c09db8cd3f76fcda。
- Agent 在缺少必需的清单/密钥/TLS/状态参数时的预期失败冒烟测试以退出码 1 退出。

生产环境防护保持不变：不替换任何生产可执行文件，不触碰任何现有的 Ghidra/调试器进程，校验用状态与生产状态保持隔离。


## P4-04 协作生命周期、历史与评审队列

状态：本地源码已闭环。

协作仍然是权威 Case 的 sidecar；它不会复制 Case/Evidence 状态。

- 评审请求按类型区分为 case、finding、evidence 或 report，且其对象必须存在于当前 Case 中。
- 每个评审请求都固定绑定到当前权威的 Case 修订。
- 评审决策复用现有的审批路径，并绑定到当前 Case 修订。
- 派生出的评审队列会在权威 Case 修订发生变化时，把旧的请求/审批标记为过期。因此，针对旧 Case 修订的审批绝不会悄无声息地授权新修订。
- 当前处于 approved/cancelled 状态的评审会离开活动队列；rejected 的评审仍然可见；过期的评审仍然可见以便后续跟进。
- 协作变更现在会把审计历史持久化在协作工作区内部。评审请求与评审决策会记录显式的类型化审计事件，包含操作者、对象与来源修订。
- 现有的乐观协作修订校验仍然是强制性的。
- 扩展的是现有拥有者，而不是新增并行权威源：
  - CLI：collab review-request、collab review-queue、collab history。
  - MCP：collaboration_apply 新增 review_request；collaboration_get 新增 workspace、review_queue 与 history 视图。
- 当提供了经过授权的协作操作者时，Case Dashboard 会展示派生出的评审队列。

Core 测试证明：评审在其来源修订上处于待处理状态，审批后离开队列，并在 Case 发生变化后重新变为过期。

## P4-05 报告模板与确定性投影标识

状态：本地源码已闭环。

报告现在携带显式的渲染标识：

- template_id (builtin/<profile>)
- template_version
- renderer_version
- projection_sha256

projection_sha256 由结构化报告投影计算得到，并有意识地排除 generated_utc 以及该标识字段本身。因此，同一 Case 修订/profile/分级/章节选择，即使在不同的墙上时间生成，也会得到相同的投影标识。改变所选择的报告章节会改变投影标识。

Markdown 输出同样会呈现模板、渲染器与投影标识元数据。JSON/HTML/SARIF/STIX 继续从同一结构化报告投影派生，且现有的 Case 修订绑定/当前性规则保持不变。

## P4-04/05 校验

重点测试已通过：

- go test ./internal/collaboration -count=1
- go test ./internal/reporting -count=1
- go test ./internal/core -run TestP4|TestP3ReportCurrentnessAndCollaborationRBAC -count=1
- go test ./internal/dashboard -count=1
- go test ./internal/server -run TestP3ProductToolsEnforceVerificationAndCurrentness -count=1
- go test ./cmd/reverseresearch -run TestP3CLIProductFlows -count=1

针对协作、报告以及绑定修订的 Core 评审生命周期的竞态检查已通过。

静态门禁：

- go vet ./internal/collaboration ./internal/reporting ./internal/dashboard ./internal/core ./internal/server ./cmd/reverseresearch PASS
- staticcheck ./internal/collaboration ./internal/reporting ./internal/dashboard ./internal/core ./internal/server ./cmd/reverseresearch PASS
- gofmt PASS
- git diff --check PASS

候选二进制构建/冒烟测试：

- %TEMP%\ReverseResearch-P4-05.exe
- 大小：34,771,968 bytes
- SHA-256: 9547034f2410768e77e25fdf7255cbd9ef1e0893933f4b956b4c0f6fd512bfb6
- CLI help 冒烟测试：PASS

生产环境防护保持不变：不触碰任何正在运行的 Ghidra/调试器，不替换任何生产可执行文件，测试也不使用任何生产状态。


## P4-06 签名数据包生态

状态：本地源码已闭环。

P4-06 扩展 P3 的签名包注册表，而不是取代它。

清单/模式：

- 签名的规范化标识现在除版本、发布者、能力以及逐文件的 SHA-256 之外，还包含精确的依赖关系和强类型入口点。
- 依赖是精确的 pack ID + 版本绑定。
- 入口点具有名称和类型：data、knowledge、protocols、rules、skill、symbols、types 或 mcp-adapter。
- 入口点必须引用已被签名文件清单覆盖的文件。

加载策略：

- Core 加载器仅加载数据。
- 仅数据的 Rule/Symbol/Type/Protocol/Knowledge/Skill 内容可以被激活，并通过有界的活动入口点读取。
- 包含可执行/脚本内容、带副作用的能力或 mcp-adapter 入口点的包，可以完成签名校验并被记录，但不能在进程内激活。它们需要一个单独管控的外部适配器。
- 未新增动态库加载、任意进程执行、shell、PowerShell 或 generic exec 路径。

生命周期：

- verify：校验签名、发布者信任、模式、文件大小/哈希，并记录一条持久化收据以及已校验的包记录。
- activate：需要 registry.manage、乐观的注册表修订、当前的发布者信任、当前的文件哈希、加载策略批准以及精确的活动依赖。
- update：校验新版本并显式激活其收据；先前版本仍保持已校验状态以便回滚。
- rollback：显式指定 pack ID + 目标已校验收据；在激活之前会重新校验目标。
- quarantine：将某条收据标记为已隔离，并在其当前处于活动状态时将其停用。
- active：以只读方式解析活动版本，并重新校验签名/信任/文件/依赖。
- read-entrypoint：只有在完成活动解析之后才返回有界的字节，并会针对签名清单再次校验入口点哈希。
- verify/activate/rollback/quarantine 都会持久化审计事件。

接口：

- CLI：pack activate、pack quarantine、pack rollback、pack active、pack read-entrypoint。
- MCP：现有 pack_registry 拥有者新增 activate、quarantine、rollback、active 与 read_entrypoint。
- Dashboard 的签名 Pack Registry 现在会展示包的生命周期状态与加载策略状态。

校验：

- go test ./internal/packregistry -count=1 PASS。
- 生命周期测试覆盖 v1 激活、v2 更新、显式回滚、隔离、精确依赖激活、活动文件篡改拒绝，以及可执行插件激活拒绝。
- 经由 TestP3CLIProductFlows 的 CLI 生命周期路径 PASS。
- 经由 TestP3ProductToolsEnforceVerificationAndCurrentness 的 MCP 生命周期路径 PASS。
- Dashboard/Core 相关测试 PASS。
- go test -race ./internal/packregistry -count=1 PASS。
- go vet ./internal/packregistry ./internal/dashboard ./internal/core ./internal/server ./cmd/reverseresearch PASS。
- staticcheck ./internal/packregistry ./internal/dashboard ./internal/core ./internal/server ./cmd/reverseresearch PASS。
- gofmt 与 git diff --check PASS。

候选二进制构建/冒烟测试：

- %TEMP%\ReverseResearch-P4-06.exe
- 大小：34,868,224 bytes
- SHA-256: 76a90fb98804e68d31e3f67d163147cfb4909d8fbe5375cfa7d8c6f13d666075
- CLI help 冒烟测试：PASS。

生产环境防护保持不变：不替换任何生产环境的 ReverseResearch.exe，不停止或附加任何现有的 Ghidra/调试器进程，这些测试也不使用生产持久化状态。

## 生产环境升级状态

本地源码的 P4 产品化已闭环至 P4-06。随后生产 RR/RT 在保留现有 Ghidra 守护进程与已打开数据库的前提下，完成了带有健康度/当前性/回滚检查的升级。生产可执行文件与服务运行时均为当前版本。

与 ChatGPT 相连的 RR/RT 工具目录新鲜度边界现已闭环：RR 与 RT 均暴露 238 个工具，且二者归一化后的工具名集合完全一致。所保留的 124 工具快照仍只是 2026-10-01 的历史契约证据，而不是当前的客户端元数据。

## 收尾之后的全量审计

P4 收尾之后对仓库/运行时进行的全量复核发现并修正了以下额外的生产环境卫生缺口：

- Windows 上 POSIX 风格的 0600 权限位本身并不足够。敏感记录现在会获得一个受保护的 Windows DACL，仅限当前用户、SYSTEM 与本地 Administrators。
- 私有边界覆盖 state、evidence、本地 MCP bearer 状态、Ghidra 守护进程身份/token 状态，以及 x32/x64dbg MCP token 配置。
- tools/ops/harden-local-install.ps1 为生产可执行文件、config/runtime、state/evidence、回滚产物以及所配置的隧道 API key 提供可重复执行的 Apply/Audit 处理。
- tools/ops/manage-autostart.ps1 负责按用户的 AtLogOn 计划任务，校验可执行文件/参数/工作目录/触发器标识/Limited 运行级别/重启策略，并通过回环控制端点执行经 bearer 鉴权的优雅 Stop/Restart。
- gopkg.in/yaml.v3 的直接使用现在已作为直接 Go 模块依赖加以体现。
- 历史遗留的 .tmp 收尾/构建残留已删除，仅保留当前升级所用的回滚二进制。
- 修复之后的全量回归：54 个 Go 包 PASS；被改动到的安全/运行时包在竞态检测器下 PASS；go vet ./...、staticcheck ./...、go mod verify、go mod tidy -diff、gofmt 与 git diff --check 均 PASS。

ChatGPT 连接器的新鲜度边界已闭环。RR 与 RT 均已刷新为 238 个工具，与已升级的本地服务器面一致。历史的 124 工具快照仅作为带日期的兼容性证据保留。

## 全面审计收尾 - 2026-10-03

被审计的生产二进制就是已提交并经过正式校验的候选版本：SHA-256 `350a0646d4e67075dcd5a04b469d3409d7d3c0aa7f476473e59f782dc3caf802`，大小 `35,233,280` bytes，由 commit `c5037b2` 构建。该候选版本的精确字节同时通过了 `verify-p2-security.ps1` 与 `verify-research-records.ps1`。

升级后检查已通过：本地 `/healthz`；Windows 私有安装 ACL 审计（`unsafe_count=0`）；canonical logon 计划任务的精确定义校验；RR 与 RT 重连；Ghidra 守护进程 PID 13804 在交接后仍然存活；以及三个既有数据库均保留了各自的路径与函数计数。

新的生产重启路径是优雅的：`manage-autostart.ps1 -Action Restart` 发送了经过鉴权的回环关机请求，重启了 canonical 计划任务，并恢复了健康状态。在重启之前，活动的 RR 会话把每个 Ghidra worker 的 session_count 从 1 提升到 2；优雅重启之后，三个 worker 全部回到 session_count 0，数据库仍处于打开状态，这证明陈旧的 MCP 会话挂载不再累积。

客户端元数据新鲜度现已闭环：本会话暴露 238 个 RR 工具和 238 个 RT 工具，归一化后的工具名集合完全一致，并且可以看到 Core/host/Web/Android 的新增项，例如 process_debug_route、web_backend_status、android_runtime_status 与 attack_graph_import。
