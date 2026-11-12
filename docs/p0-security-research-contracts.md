# P0 安全研究契约

本文档记录第一批已集成的平台结构。它是一份契约参考，并不声称每个未来的安全领域都已实现。

## 归属矩阵

| 归属方 | 负责 | 明确不负责 |
| --- | --- | --- |
| Router v4 | 规范路由 ID 以及领域/意图/平台/工件/效果元数据 | Skill 选择逻辑、目标执行 |
| Engagement/Scope | 授权、精确的目标/动作、显式排除（exclusion）、网络/数据/时间/清理约束 | 执行效果 |
| Generic Job | 效果生命周期、操作身份、当前范围闸门、结果/清理/证据收据（receipt） | 工具专属实现 |
| Case v2 | 持久（durable）研究对象与关系 | 在缺少 Evidence 的情况下证明结论 |
| Domain Pack | 路由到专项/剧本/能力包的捆绑契约 | 任务分类 |
| ToolIndex v2 | 本机发现、可执行文件身份、来源、能力、信任/健康元数据 | 把发现到的路径当作已验证的身份 |
| Tool Recipe v2 | 获取计划的溯源、验证、平台/架构与生命周期元数据 | 任意 Web 安装或隐式 apply |
| Knowledge/Standards Pack | 经评审的标准 + 绑定到路由/领域的不可变知识 | 任务分类或替代 Case Evidence |
| Canonical Report | 经评审 Case 的版本化投影（projection），带有冻结的 Case 修订版本与对象链接 | 成为第二个研究事实来源 |
| MCP/CLI | 面向 Core 各归属方的适配器 | 成为唯一的平台入口 |

## Engagement/Scope

可产生效果的作业需要一个持久 Engagement，其中包含：

- 组织与操作者；
- 目标允许清单（allowlist）以及显式排除；
- 允许的活动与被排除的活动；
- 授权状态、授权依据以及可选的证据引用；
- 网络 profile：`offline`、`lab_only`、`authorized_target_only` 或 `unrestricted_lab`；
- 可选的目标面、速率限制、凭据引用、数据敏感性/处置方式、隐蔽性约束、交付物、清理以及报告分类；
- 可选的 RFC3339 起止时间窗口。

授权采用 deny-by-default（默认拒绝）。`pending` 与 `denied` 一律不视为许可。offline profile 会阻断主动网络效果类。

## Generic Job

状态为 `planned -> prepared -> running -> applied|failed|uncertain`，并在有效之处提供显式的取消/回滚路径。

规则：

1. `operation_id` 是重放（replay）身份标识，而不是标签。
2. 以不同的请求复用同一个操作 ID 会失败即关闭（fail-closed）。
3. `prepared` 只能通过感知范围的 Prepare 操作进入。
4. 进入 `running` 之前会再次校验范围。
5. `uncertain` 不能自动推进，也不能自动重放。
6. 结果身份、清理状态与 Evidence ID 始终附着在持久收据之上。

## Case v2 研究链

规范 Case 可以持久保存：

`Target -> Artifact -> Observation -> Evidence -> Hypothesis -> Finding -> Path -> Vulnerability/IOC/TTP -> Detection -> Mitigation -> Retest -> Report`

操作上下文是一等公民：

`Role -> WorkItem -> Timeline -> Evidence/Job`

Hypothesis 会保留支持它的以及与之冲突的 Evidence。被拒绝/被撤回的 Hypothesis 必须给出原因，并可以指向一个替代 Hypothesis；它们绝不会被静默删除。

Evidence 可以绑定确切的源字节、观察时间、复现命令/流程、一段简短的原始摘录、一个 WorkItem 以及一个被替代的 Evidence 修订版本。

Finding 把证据强度（`observed|inferred|unverified`）与主观置信度区分开，并可以记录严重性、类别/状态、位置、影响、复现方式、修复建议、CWE/CAPEC/CVE 以及 ATT&CK 关系。

Path 可以描述类型/起点/目标、带有 Evidence/Finding/Job 链接的有序步骤，以及残余风险。

## Detection 验证

只有当 Detection 记录了下列全部信息时，才接受 `validated=true`：

- Evidence ID；
- 遥测（telemetry）需求与可用性；
- 规则修订版本；
- 语法校验；
- 模式校验；
- 正向 fixture 身份与通过结果；
- 负向 fixture 身份与通过结果；
- 预期命中；
- 误报说明。

Case 严格评审还要求已验证的 Detection 具备有证据支撑的复测（retest）。

## Case 严格评审

`case verify` 审计持久结构与当前性（currentness）。`case review` 是更严格的交接/报告闸门。对于一个 professional Case，除其他适用检查之外，它要求：

- Case v2 与 Engagement 绑定；
- 至少一个 Target 或 Artifact；
- 处于活动状态的 lead 角色；
- Timeline；
- WorkItem 都已解决为 done/cancelled；
- 有证据支撑且明确标注强度的 Finding；
- 引用有效的 Evidence/Path/IOC/TTP/mitigation 关系；
- 完整的 Detection 验证与复测 Evidence。

对于较弱但并非无效的溯源，警告仍然保持可见，例如某个 Evidence 项既没有绑定源字节也没有复现命令。

## 专项 Domain Pack

首批 Domain Pack 为：

- Malware Analysis: identity -> triage -> static -> isolated behavior -> config/protocol -> IOC/TTP -> detection -> report/retest.
- Blue Detection: behavior/evidence -> telemetry contract -> rule -> syntax/schema + positive/negative fixtures -> coverage -> retest.
- Purple Validation: ATT&CK behavior -> scoped emulation Job -> telemetry -> Detection -> gap -> mitigation/countermeasure -> retest.

`config/routes.json` 仍然是唯一的路由归属方。

## 供应链边界

每个 Domain Pack 都会记录来源、许可证与信任状态。静态审计会计算逐文件与聚合的 SHA-256 身份，并标记可执行/脚本面、符号链接/非普通文件、动态下载/exec 模式、敏感本地路径以及 MCP/bootstrap 指标。

审计刻意保持保守，并且不证明安全性。存在审计发现的外部 pack 需要人工/来源评审；任何审计结果都不授权执行、安装、凭据访问或主动网络行为。


## ToolIndex v2

现在每个目录条目都把**发现**与**身份验证**分离开。索引记录：

- 名称、发现到的路径与发现来源；
- 已知时的版本/架构；
- 提供方、规范来源、许可证、安装范围与信任状态；
- 在路径可读时的可执行文件 SHA-256、字节大小与修改时间；
- 能力标签，以及 admin/网络/目标变更/商用/再分发标志；
- 健康状态。

Windows 的 App Execution Alias 可能被发现，但无法作为普通文件读取。这会被记为 `identity-unverified`，并在该单个工具上附带一个显式错误；索引的其余部分仍然有效。

## Tool Recipe v2

`config/tool-recipes.json` 为版本 2。一份完整的 v2 recipe 会记录别名、提供方/包、版本约束、规范来源、校验和/签名策略、许可证与再分发策略、安装范围、预期可执行文件、安装后冒烟检查、升级/卸载路径、平台/架构支持以及商用/可再分发策略。

当前的 planner 仍然只做规划。未来的 apply 归属方必须在报告成功之前验证该 recipe，并重新扫描预期可执行文件。

## Knowledge/Standards Packs

`config/knowledge-packs.json` 把经评审的外部标准与不可变的内置知识分组归置。初始的 pack 覆盖：

- ATT&CK 行为/TTP 映射；
- CWE/CAPEC 弱点与攻击模式分类；
- Sigma/YARA/Suricata Detection 验证；
- SARIF/STIX 报告/情报交换。

pack 注册表会把每个被引用的内置 note 校验为经评审的溯源。pack 可以按 ID 或规范路由查询；它们绝不创建第二个路由分类器。

## Canonical Report 模型

Report 是带版本的 Case 投影，包含：

- 模式版本、类别、格式与报告修订版本；
- profile、分类、draft/final 状态与摘要；
- 可选的 Artifact 以及关联的 Finding/Evidence ID；
- 规范章节列表与被替代报告的链接；
- 确切的来源 `case_sha256`。

`status=final` 会在发布之前运行 Case 严格评审，然后在报告被追加之前重新校验 Case 修订版本没有发生变动。最终报告要求 profile、分类、章节以及至少一个 Finding 或 Evidence 链接。JSON/SARIF/STIX/Markdown/HTML 仍然是导出格式；Case 对象图仍然是规范来源。
