# Seep-Reverse-Lab

Seep-Reverse-Lab 是 Windows + Android + Web 的自动化逆向工程工作台。现有的 `ReverseResearch.exe` 名称仍然是向后兼容的本地执行核心，因此稳定的 CLI/MCP 契约与正在运行的部署不需要做破坏性的改名。

## 产品形态

工作台包含三条一等的过程性工作道（lane）：

1. **Windows 原生** — PE 身份、DiE、Ghidra/radare2、x32/x64 调试、内存/指针研究、受守护的补丁/Hook 生命周期、版本迁移、.NET、混淆与游戏资源。
2. **Android** — APK/分包 APK/App Bundle 分类、DEX/Smali/原生/Flutter 分析、受控的重打包验证，以及显式选定的设备/运行时工作。
3. **Web/JS/协议** — JavaScript/Electron/SourceMap/WASM、隔离的浏览器运行时采样、请求复现与协议/服务器边界分析。

所谓一等，指的是路由（route）/工作手册（playbook）/证据的方法论是一等的，并且首批有界的 Android/Web 运行时归属方如今已经存在。重型工具保持惰性，也不会仅仅因为某条工作道存在就安装可选依赖。Web 浏览器生命周期仍然是显式/外部的，以避免出现第二个原生进程控制桥；Android 设备授权与证书信任也仍然是设备侧的显式步骤。

### 三条工作道不等于平台的全部

`seep-reverse-lab` 是**逆向工程主控层**，上面三条工作道描述的是它自身的编排面。P0–P2 之后，平台在主控 Skill 之外已经有 15 个专项 Skill 与 16 个 Domain Pack，覆盖红队、蓝队检测工程、紫队验证、威胁狩猎、CTI、身份/AD、云与 Kubernetes、漏洞研究与模糊测试、源码/供应链审计、DFIR、恶意软件、协议、Linux/ELF 原生逆向、固件/IoT，以及 iOS/Android 移动。完整清单与当前路由/工作手册规模见 `platform-scope.md`；本文其余章节只描述主控工作台的契约。

不变的是归属边界：专项 Skill 只拥有领域方法，一律 `owns_routing=false`，`config/routes.json` 仍是唯一的任务分类来源。

## 单一归属方的 Skill + MCP 架构

工作台有意区分三类事实：

- `config/routes.json` 是唯一的**任务分类**来源。它把文本映射到一个能力路由与工具。未知任务回退到 `unclassified`；不会被强行套进 Windows/Android/Web。
- `config/playbooks.json` 是唯一的**路由到工作流**来源。它把被选中的路由映射到一个工作手册、`skills/seep-reverse-lab/SKILL.md`、一个平台 `reference_path`、G1-G4 通过标准、一份共享的失败参考，以及完成标准。Core 会拒绝未知的路由 ID、重复的路由归属、缺失的 Skill/参考文件，以及不完整的关卡。
- `skills/seep-reverse-lab/` 是唯一可安装的 **Agent Skill**。入口保持简短；Windows/Android/Web 的细节从 `references/` 渐进式加载（progressive loading）。

控制面的 MCP 工具是：

- `task_route` — 仅做分类；
- `task_prepare` — 路由 + 经过验证的工作手册 + 能力/工具事实 + 供给/沙箱建议；
- `playbook_get` — 按 ID 或路由取回一个经过验证的工作流；
- `tool_index_scan` — 刷新本地工具事实，不安装、也不启动后端。

CLI 的 `route`、`prepare`、`playbook` 与 `tools` 调用的是同一批 Core 归属方。

## 从公开项目吸收的经验

公开仓库为方法论与经过裁决的能力模式提供来源：

- `zhaoxuya520/reverse-skill`：单一路由来源、路由回归、工具索引优先的行为、客户端中立的 Skill、案例/证据交接、渐进式加载，以及一致性与供应链纪律。
- `newliver666/apk-reverse`：面向决策的入口、可执行的关卡、环境诊断、症状/失败目录、有界的重复失败规则、显式的完成定义，以及实用的 APK 失败教训。
- `morluto/rea`：围绕单一功能追踪入口/计算/结果、静态与历史/运行观测归属、有界输出与覆盖、SourceMap 内嵌源码以及历史 HAR producer 行号。HAR/SourceMap 由既有 `webinspect` 在 Go 中独立实现，CLI/MCP 仍经同一 Core；Case/Path 与原生后端继续保持原有归属。
- `reverse-skill` 二次复核与历史 PawanOsman/acheong08、所选 codex-proxy 样本：补入合同重建、snapshot/delta、会话/请求/call identity、原始留证与 EOF/业务终止分层方法。离线 SSE framing 由 RR 按公开 WHATWG 规则原创实现；固定对象、许可及重定向记录在 upstream references，不复制代理、账号或认证实现。

经评审的确切修订版本与采纳边界记录在 `skills/seep-reverse-lab/references/upstream.md`。

Seep-Reverse-Lab 保留其更强的本地归属方：目标/进程当前性（currentness）、受守护的最终效果变更、持久的操作身份、案例/证据完整性、隔离的后端验证、Ghidra Unicode 处理，以及版本绑定的兼容性记录。

## 核心工作流

1. **G1 分类** — 对任务做路由，并指明具体的交付物。
2. **G2 环境事实** — 刷新工具可用性，并识别既有的端口/进程/会话，但不接管它们。
3. **G3 控制基线** — 冻结目标身份与一次可复现的变更前观察。
4. **G4 最窄动作** — 只加载 `playbook.reference_path`，并使用最小的可逆层级。

两次同形的失败就会停止调参：记录死路，更换假设或测量层级，并使用失败目录。

完成需要身份、路由/工具链、基线、已复现或经独立交叉核验的效果，Evidence -> Finding -> Path 的支撑，以及不触碰无关用户会话的清理。

## 非目标

- 不要整体照搬外部项目的目录布局。
- 不要默认安装所有 Android/Web 依赖。
- 不要把 Skill/工作手册当作某项能力已成功运行的证明。
- 不要让 MCP 成为使用本地 Core 的唯一途径。
- 不要静默复用个人的浏览器/设备/调试器会话。
- 不要夸大 Android/Web 运行时范围：当前的 Web 支持只是已安装浏览器身份 + 隔离配置档规划 + 只读回环 CDP + classic SourceMap/内嵌源码读取、离线 HAR/SSE 摘要与静态 WASM；当前的 Android 支持只是已授权的 adb probe + 隔离的证据/工作区 + 绑定当前性的一次性 UI 点击。浏览器生命周期归属、证书自动安装与设备授权有意处于这一层之外。
