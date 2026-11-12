# Seep-Reverse-Lab / ReverseResearch Core 平台范围

Seep-Reverse-Lab 是 Windows + Android + Web 的工作台层；ReverseResearch 是与之向后兼容的本地执行 Core/CLI/MCP 运行时。老游戏 Mod 制作是一个重要的验证试验场，而不是产品边界。

## 产品原则

1. **Core 优先，适配器其次。** 分析、路由（route）、证据、工具发现与工作流都属于与协议无关的 Core 包。MCP、ChatGPT、Codex 及其他客户端都是适配器。
2. **默认本地。** 本地的 Codex、脚本与用户可以直接调用 CLI。运行 ReverseResearch MCP HTTP 服务是可选的。
3. **单一工具清单。** Agent 在下载或安装替代物之前，先查询已生成的本机工具索引。
4. **结构化路由与工作手册（playbook）。** `config/routes.json` 是任务到能力路由的唯一事实来源；`config/playbooks.json` 承载机器可读的平台关卡/完成标准，且不重复路由决策。回归基准守护路由行为。
5. **可复现的研究。** 目标、工具版本、证据、发现、研究路径、补丁与跨版本映射都可以通过本地 Case/Journal 层记录。
6. **惰性能力。** 重型后端与可选的安全工具链只在需要它们的任务上启动。
7. **显式的高影响动作。** 发现与分析可以自动进行；安装、目标变更、主动网络交互以及其他高影响动作都是带当前性（currentness）/授权检查的显式操作。

## 能力域

路由目录的覆盖面有意比老游戏逆向工程更广。

### 原生逆向工程

- 目标身份 / PE 元数据
- Ghidra 静态分析
- radare2 分析
- x32/x64dbg 动态调试
- 运行时内存发现与精炼
- 二进制/版本差异与符号迁移
- 受守护的补丁生命周期
- 加壳 / 混淆研究
- 游戏归档包与专有资源格式

### CTF 与漏洞利用开发研究

- 隔离的 CTF 工作区
- Pwn 工作流路由
- 崩溃/缓解措施/原语分析
- 调试器与模拟器集成
- 可复现的赛题产物

### 授权渗透与 Web 安全研究

- 网络/服务发现路由
- Nmap/SQLMap 工具发现
- Burp/mitmproxy/浏览器工作流路由
- API/Web 请求捕获与重放工作流
- 协议/PCAP 研究

### 终端与漏洞研究

- 终端安全兼容性与检测研究
- 受控的绕过韧性测试
- 已知漏洞/N-day 复现
- 补丁差异比对
- 防御性恶意软件/样本分析

### 移动、托管运行时与固件

- Android APK/DEX/Smali/原生库
- iOS IPA/Mach-O/Swift/Objective-C
- .NET/CLR/IL
- JavaScript/Electron/WASM
- 固件 / IoT / 嵌入式镜像

### P0–P2 之后已具名落地的领域

上面的目录不再是仅有名字的覆盖面：每一个领域现在都同时具备 `config/routes.json` v4 的路由、一份专项 Skill 和一个 Domain Pack。

已存在的 15 个专项 Skill（除主控 `seep-reverse-lab` 之外）：`seep-native-reverse`、`seep-vuln-research`、`seep-code-audit`、`seep-dfir`、`seep-malware`、`seep-protocol`、`seep-redteam`、`seep-identity`、`seep-cloud`、`seep-mobile`、`seep-firmware`、`seep-cti`、`seep-threat-hunting`、`seep-blueteam`、`seep-purple-team`。

`config/domain-packs.json` 当前的 16 个包 ID：`malware`、`blue-detection`、`purple-validation`、`linux-native`、`vuln-research`、`dfir`、`protocol`、`code-audit`、`redteam`、`identity-ad`、`cloud`、`container-k8s`、`ios`、`firmware`、`cti-hunting`、`adversary-emulation`。

当前机器可读的规模：`config/routes.json` v4 = 36 条路由，覆盖 18 个 `domain`（native、network、defense、cloud、vulnerability、web、code、mobile、threat-intel、identity、dfir、malware、firmware、game、crypto、lab、security、unknown）；`config/playbooks.json` = 20 份工作手册，承接 32 条路由映射；`config/knowledge-packs.json` = 6 个标准/知识包（threat-ttp、vulnerability-taxonomy、detection-engineering、report-interchange、telemetry-normalization、software-supply-chain）。

专项 Skill 一律 `owns_routing=false`：路由的唯一归属方仍然只有 `config/routes.json`，领域包与知识包都不得成为第二个分类器。

## 工具获取

ReverseResearch 现在具备针对缺失工具的版本化获取规划层。自动应用可以按提供方逐个加入，但不得执行任意网页代码片段。

安装子系统必须使用带版本化的配方清单，包含：

- 规范工具名；
- 提供方与包身份；
- 固定的或有界（bounded）的版本；
- 预期的可执行文件；
- 安装范围；
- 来源 URL 或包管理器权威；
- 可选的校验和/签名验证；
- 安装后的发现与冒烟检查；
- 在可行时的卸载/回滚元数据。

默认的 `tools scan` 命令从不安装任何内容。`tools ensure` 现在只产出获取计划。后续一个显式的 apply 操作将执行受支持的配方，并且必须在报告成功之前重新扫描/验证预期的可执行文件。

## 路由架构

`config/routes.json` 是规范的路由来源。当前的路由族包括：

- memory-search
- dynamic-debug
- binary-diff
- patch
- pe-static
- native-static
- pwn-exploit
- ctf-sandbox
- pentest-network
- web-security
- endpoint-defense-research
- nday-research
- malware-analysis
- dotnet
- android
- ios
- js-web
- firmware-iot
- game-resource
- crypto-obfuscation
- traffic-protocol

路由只推荐能力/工具；它们不拥有 Skill/工作手册路径，也不执行目标动作。`prepare` 可以附加来自 `config/playbooks.json` 的、经过验证的路由所属工作手册，但绝不把未映射的路由强行套用。

## 当前 Android 与 Web 运行时边界

第一层有界的 Android/Web 运行时层在实现时没有创建并行的进程控制栈：

- **Web：** 对已安装 Chrome/Edge 的发现以路径/SHA-256/大小绑定身份；准备自有 `state/web-profiles/<id>`，不会启动/接管日常浏览器。CDP 发现只读显式 loopback HTTP `/json/version`、`/json/list`。SourceMap 支持 classic/embedded indexed、VLQ 定位及内嵌源码分页，不加载 section URL/源声明路径。历史 HAR 支持摘要、API 汇总、显式 producer body 字节读取和摘要比较，保留 ordinal/JSON pointer、哈希栅栏与 coverage；不重放请求、不证明原始 wire bytes 或当前服务器身份。原 WASM 入口默认是部分结构检查，可选 WABT 1.0.42 --enable-all 完整静态模块验证与分页 WAT/objdump；输入/输出/工具 SHA、版本和参数可核对。只用 ToolIndex 已供给工具，不下载安装或实例化 WASM。Windows 真实 producer 已验证，其他 host 运行事实仍 UNVERIFIED。
- **静态应用：** ASAR inventory/entry/integrity、JavaScript AST/多模块候选关系、PE/CLI metadata/selected CIL、静态版本比较、Go build-info、显式 raw/hex EVM 与 ZIP inventory/CRC entry 已通过同一 Core 接入 CLI/MCP；不执行目标。PE/ELF/Mach-O layout 复用 targetidentity，不新增第二套解析。文件快照 currentness 共用 `targetidentity.CaptureFile`；Case 研究视图只派生现有记录，最终核销仍属于 Case review。
- **离线序列化与历史崩溃：** TAR/gzip TAR inventory/member read、Apple XML/bplist00 typed object table/data read、NSKeyedArchiver graph、compiled NIBArchive v1、Linux ELF64 amd64 LE recorded core segments/notes/27-register PRSTATUS/SIGINFO 已进入同一 Core/CLI/MCP；JavaScript AST 新增 import/export/CommonJS shape 声明。它们可在当前 Windows 主机上读取离线字节，不等同于 macOS/Linux/Android 运行时或 UI/执行验收。输入、计数、深度、解压和输出都有硬上限，分页绑定 SHA；未知语义/截断字段明确保留。
- **包装与原始 Go 元数据：** Apple/Harmony ZIP package path/component/bundle projections 和 Go inline/historical-pointer raw ranges/base64 可在 Windows 离线查询；CLI/MCP/Core 共用原 snapshot/ZIP/native owner。Stage/FA/framework hints 只属于路径约定，Go 原始数据不认证编译器/模块；manifest、签名、Ark/CoreUI、runtime reconciliation 与完整 semantic reconstruction 继续保留未实现边界。
- **离线流式协议：** SSE body 检查支持多行 data、CR/LF/CRLF、id 继承/重置、原始字节/行位置、数据摘要/按需有界前缀及 SHA 分页栅栏；UTF-8 和大小限额属于显式 summary profile。EOF 尾帧与 `[DONE]` 的历史观测不证明业务完成；不提供 provider 翻译、账号/凭证池、代理服务、重连或请求重放。
- **Android：** adb 设备枚举从不自动授权设备。Probe 要求 state=`device`，记录 root 与非 root shell 状态，并在 SHA-256 序列号键下持久化设备工作区，证据/证书/操作目录彼此分离。UI 捕获存储可复核的 XML + 截图哈希。选择器点击要求一个全新的、相匹配的 UI SHA-256，以及一份在生效之前写入的持久一次性操作收据（receipt）；已存在的 prepared/failed/applied 收据会在不触碰 adb 的情况下被返回，因此重连不会重放一个结果不确定的动作。证书安装与设备授权仍然是外部的显式步骤。

## 长期形态

```text
                         ReverseResearch Core
                                  |
       +--------------------------+--------------------------+
       |                          |                          |
   Router/Planner        Case/Evidence/Path/Journal       Tool Index
       |                          |                          |
       +------------+-------------+-------------+------------+
                    |                           |
             Local capability runtime      Tool acquisition
                    |
       +------------+------------+--------------------------+
       |            |            |                          |
   Native RE      Mobile      Web/Network             CTF/Pwn/etc.
       |
       +---------------- optional adapters ------------------+
                               |
                       CLI / MCP / client plugins
```

平台应当通过在这些共享边界上增加能力模块与配方来成长，而不是把客户端专属的工作流嵌入 MCP 服务端。

## P0 平台结构基线

首个 P0 垂直线把规范的路由契约升级为 Route v4，且不创建第二个路由器，同时引入独立的 Engagement/Scope 归属方。Route v4 在保持旧路由 ID 稳定的前提下，增加结构化的 `domain`、`intent`、`platform`、`artifact` 与 `effect_class` 元数据。Engagement 范围为后续的 effect 作业提供持久的目标/动作/时间窗边界。既有的 Case、当前性、调试器、补丁、Android 收据与 ToolIndex 归属方仍然是权威的，不会被复制。


## P0 安全研究归属方闭环

P0 结构有意面向归属方而非面向工具：

- **Route v4** 保留 `config/routes.json` 作为唯一的分类器，并增加结构化的 domain/intent/platform/artifact/effect 元数据，而不替换遗留的路由 ID。
- **Engagement/Scope** 拥有授权状态/依据/证据、精确的纳入范围与显式排除（exclusion）的目标/动作、网络配置、数据处理、隐蔽性约束、交付物、时间窗、凭据引用、清理与报告分类。除非当前已授予授权，effect 作业一律失败即关闭（fail-closed）。
- **Generic Job** 把 `engagement_id + target + action + effect_class + operation_id` 绑定到一个持久状态机。准备阶段以及向 running 的转换都会重新检查当前范围。结果不确定的 effect 绝不自动重放。
- **Case v2** 拥有 Targets、Artifacts、Observations、Evidence、Hypotheses、Findings、Paths、Vulnerabilities、IOCs、TTPs、Detections、Mitigations、Retests、Reports、逻辑 Roles、WorkItems 与 Timeline 条目。已被撤回的假设仍然持久保留。
- **Case review** 比结构校验更严格：它是面向 engagement 绑定、主导归属、timeline/workitem 收口、有证据支撑的发现、验证关卡与检测复测的报告/交接就绪关卡。
- **Domain Packs** 把规范路由绑定到专项 Skill、工作手册、能力与知识引用。专项 Skill 在契约上被禁止拥有路由。
- **Domain Pack audit** 对本地 Skill 树计算哈希，并静态标记脚本/可执行文件面、符号链接、动态下载/exec 模式、敏感路径引用以及 MCP/bootstrap 供应链指标。它不执行包内容，也不自动安装依赖。
- **First specialist workflows** 是 Malware Analysis、Blue Detection Engineering 与 Purple Validation。
- **ToolIndex v2** 把发现与身份信任分离：路径/来源，加上版本、架构、提供方、规范来源、许可证、安装范围、信任状态、可读时的可执行文件 SHA-256/大小/mtime、能力/风险标记以及健康度。一个不可读的操作系统别名只会把该工具降级为 `identity-unverified`；它绝不会破坏全局索引。
- **Tool Recipe v2** 记录别名、提供方/包/版本约束、规范来源、校验和/签名策略、许可/再分发、安装范围、预期可执行文件、冒烟检查、升级/卸载路径、平台/架构支持以及商业/可再分发策略。规划阶段仍然不执行安装。
- **Knowledge/Standards Packs** 把已评审的标准（初期为 ATT&CK、CWE/CAPEC、Sigma/YARA/Suricata 与 SARIF/STIX）绑定到规范路由与不可变的已评审内置知识。它们不分类任务。
- **Canonical Report** 是 Case 的一个投影。草稿/最终报告版本固定住来源 Case 的 SHA-256 与所链接的 Findings/Evidence；最终报告在 Case 未通过严格复核、或必需的 profile/classification/章节缺失时失败即关闭。

本地源码 MCP 目录现在包含这些 P0 归属方。这只是一份源码树层面的能力声明；在部署与远程验证真正发生之前，不得把它表述为已部署到独立运行的 RR/RT 端点。

### 外部逆向 Skill 采纳边界

公开的 `reverse-skill` 项目已作为上游设计输入经过评审。ReverseResearch 采纳了那些能够改进持久研究契约的部分：显式的授权/网络范围、Evidence/Finding/Path 溯源、逻辑 role/workitem/timeline 交接、严格的 Case review，以及静态的 Skill/MCP 供应链评审。

ReverseResearch 有意**没有**把第二个路由器、庞大的全局 prompt/RULES 层、反惰性/人格化行为、默认自动安装、隐式授权、对既有会话的自动接管，或攻击性的工作手册文本作为 Core 归属方引入。上游示例仍然只是灵感来源；规范的 ReverseResearch 模型与证据规则保持权威。
