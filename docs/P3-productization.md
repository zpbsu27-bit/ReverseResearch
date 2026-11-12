# P3 产品化基线

本文档记录 ReverseResearch / Seep-Reverse-Lab 的本地源码树 P3 产品化基线。

本文件记录的是历史性的本地源码 P3 基线。当前的生产发布推进与已连接客户端目录新鲜度在 `P4-productization.md` 与实施清单中跟踪；当前的部署事实请以上述文档为准。

## 已闭环的 P3 责任主体（owner）

### 以 Case 为中心的报告投影

internal/reporting 从规范化的 Case 存储构建以修订号（revision）固着的投影。

支持的 profile：general、reverse、vulnerability、red-team、blue-detection、malware、dfir。

支持的输出格式：JSON、Markdown、HTML、SARIF 2.1，以及 STIX 风格的 bundle 导出。

报告会绑定确切的 Case SHA-256。最终报告要求一次严格的 Case 评审，并且被评审的 Case 修订号必须仍然处于当前状态。

报告投影刻意不包含原始证据摘录。证据在 Case 存储中保持权威，而不是被复制成第二个事实来源。

通过 CLI 和 MCP 渲染报告支持显式的章节选择。未知章节会失败即关闭（fail-closed）。支持的章节为 summary、targets、artifacts、observations、hypotheses、findings、paths、vulnerabilities、evidence、iocs、ttps、detections、mitigations、retests、reports、roles、workitems 和 timeline。

若不携带当前的输出 SHA-256，则无法覆盖已有的报告输出。

### 以 Case 为中心的本地 Dashboard

internal/dashboard 渲染的是围绕 Case 的本地只读 HTML 投影，而不是一份按钮目录。

当前视图包含 Targets、Artifacts、Observations、Hypotheses、Findings、Evidence、研究/攻击路径、ATT&CK/TTP 映射、Detections、Mitigations、Retests、Reports、Case 工作项、Timeline、协作状态、来自既有 Job 责任主体的 Generic Jobs，以及来自既有 ToolIndex 责任主体的工具事实。

HTML 内容会被转义。替换 Dashboard 输出同样需要当前的文件 SHA-256。

这是一个本地静态 Case Dashboard。它并未被表述为一个已完成的多用户 Web 应用或账号系统。

### 协作与 RBAC

internal/collaboration 是产品工作流状态的、具备当前性（currentness）安全性的旁车（sidecar）：case owner、participants、finding owner、task、comment、approval、evidence lock。

变更操作必须携带当前的协作修订号。协作授权的来源是参与者角色，而不是每次请求随附传入的任意角色字符串。

internal/rbac 定义 owner、lead、analyst、reviewer、viewer、agent 角色。其策略将读取、研究变更、审批、作业执行、Remote Agent 管理、Pack Registry 管理相互分离。未知的角色/动作会失败即关闭。

### Remote Agent

internal/remoteagent 与 cmd/reverseagent 提供了有界的 Remote Agent 基础设施。

安全属性：
- 经 Ed25519 签名的 agent 清单
- 强制 mTLS
- 显式的目标允许清单
- 显式的、经签名的能力清单
- 持久的操作台账（ledger）
- 重复的 operation_id 不会执行两次
- 经签名的结果信封
- 工件/结果的 SHA-256 身份
- 请求大小上限
- 拒绝未知 JSON 字段
- 拒绝多个 JSON 值
- 不对不确定的效果进行隐式重试
- 禁止任意远程 shell、exec、PowerShell 能力

> 译注：后续能力清单见 `P4-productization.md` 的 P4-01，本节保留为 P3 当时的历史基线。

初始的可执行文件只注册显式声明的强类型 handler。P3 当时内置的只读 handler 为 artifact.inspect 和 artifact.hash。

中央 MCP 责任主体可以注册/列出/获取经签名的 agent 清单、校验有界的作业契约，并验证经签名的结果。它刻意不暴露远程 shell，也不提供通用命令执行器。

启动 ReverseResearch-Agent.exe 需要经签名的清单、Ed25519 私钥、服务端 TLS 证书/密钥、受信任的客户端 CA，以及任务独占的持久状态目录。不会启用任何隐式信任或默认的远程执行。

### 经签名的 Pack Registry

internal/packregistry 提供确定性的 pack 清单、精确的文件大小/SHA-256、Ed25519 签名、显式的受信任发布者密钥、拒绝路径穿越、强制常规文件、持久的验证收据（receipt）、乐观的注册表修订号与乐观当前性校验（optimistic registry revision/currentness）、信任的添加/移除，以及 registry.read 与 registry.manage 之间的 RBAC 分离。

一次成功的验证收据会绑定 pack 身份/版本、manifest SHA-256、发布者、文件数量，以及用于授权的注册表修订号。

Pack 验证不会自动加载或执行插件代码。

### Generic Job 的可移植性

Generic Job 仍然是 effect 的责任主体。

一个 Windows 兼容性问题已闭环：合法的 operation ID 可以包含冒号字符，但 Windows 文件名不可以。既有的简单 operation ID 保留其传统的收据文件名，而含冒号的 ID 使用确定性的、基于哈希的文件名。操作身份与幂等语义保持不变。

新增了 Job.List，使 Dashboard 消费既有的 Job 责任主体，而不是另外创建一个作业数据库。

## 本地 CLI 能力面

P3 新增稳定的顶层责任主体，而不是为每个第三方工具各建一个 CLI 命令：
- report
- dashboard
- collab
- rbac
- agent
- pack

代表性流程：
- report render，携带 profile、格式、章节选择与当前输出 SHA
- dashboard render，可选携带协作 actor
- RBAC 策略检查
- 经签名的 agent 注册、有界作业校验、经签名结果验证
- pack 信任添加/移除、注册表读取，以及由注册表背书的验证

## 本地 MCP 能力面

本地源码树的 MCP 目录当前为 238 个工具。

P3 新增八个稳定的责任主体：
- report_render
- dashboard_render
- collaboration_get
- collaboration_apply
- rbac_check
- remote_agent_manage
- pack_verify
- pack_registry

这一数量描述的是本源码树及其本地 MCP 运行时。它并不声称线上 RR/RT 实例已经被提升到该修订版本。

## 已执行的验证

由于连接器宿主对单进程观察施加 60 秒上限，即便各包仍在通过，整体式的 go test ./... -count=1 也可能被外部超时。因此仓库的包集合被划分为包覆盖率等效的有界分组。

所有 Go 包分组均通过。

额外的 P3 门禁全部通过：
- 聚焦的 P3 单元/集成测试
- CLI 产品流程测试
- MCP 产品流程/目录测试
- 对所有 P3 涉及的包分组执行 go vet
- 对所有 P3 涉及的包分组执行 staticcheck
- 对 RBAC/collaboration/remoteagent/packregistry/reporting/dashboard 执行竞态测试
- 对 Generic Job 执行竞态测试
- 对 Core 的 P3 测试执行聚焦竞态测试
- 对 CLI/MCP 服务端与 ReverseResearch-Agent 执行竞态测试
- 为两个可执行文件进行隔离的候选构建
- 候选 CLI 冒烟测试
- 预期为负的 Agent 冒烟测试，证明必须显式提供 TLS/状态配置
- 生产状态 Git 污染检查

候选二进制在系统临时目录下构建，未覆盖已安装的可执行文件。

没有任何验证步骤会刻意重置、清理、停止或接管既有的 Ghidra/分析运行时状态。

## 明确的非声明

P3 并不意味着：
- 线上 RR/RT 已经带着这些变更完成部署
- Remote Agent 是一个通用远程 shell
- 经验证的 pack 被自动信任用于执行
- 静态 Dashboard 是一个已完成的企业级多用户 Web 产品
- 协作旁车可以替代未来的身份/账号提供方
- 生成的 SARIF/STIX 被每一个下游消费者独立认证
- 报告投影可以替代原始的 Case/Evidence 数据

这些仍属于独立的部署、集成，或后续的产品工作。
