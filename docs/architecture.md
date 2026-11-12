# 架构

ReverseResearch 是**本地优先**的。研究 Core、结构化路由器、工具索引与本地能力运行时就是产品本身；MCP 是一个可选适配器。该平台的设计目标是超越原生/游戏逆向工程，扩展到 CTF/Pwn、Web/网络、移动、固件以及其他获授权的安全研究领域。

```text
                     ReverseResearch Core
                            |
          +-----------------+-----------------+
          |                                   |
     Local CLI                         Local module runtime
 target / patch                 x32dbg / Ghidra / radare2
          |                                   |
          +-----------------+-----------------+
                            |
                     optional MCP adapter
                            |
                 +----------+----------+
                 |                     |
            Server URL          Secure MCP Tunnel
               (RR)                    (RT)
```

## Core 边界

`internal/core` 拥有与协议无关的目标标识以及带防护的补丁操作。CLI 与 MCP 适配器都调用同一个服务。MCP 处理器必须保持为薄适配器，且不得成为某项能力的唯一实现。

### 目标文件标识

`internal/targetidentity` 通过同一个保持打开的常规文件句柄对目标进行哈希与解析，而不是对一个路径实例做哈希、再重新打开另一个句柄以读取 PE 元数据。它在哈希之后以及 PE 解析之后都会重新检查打开的句柄与当前路径，包括同一文件标识、大小与修改时间。因此，普通的替换/编辑漂移会失败即关闭（fail-closed），而不会产生这样一个记录：其 SHA-256 来自一个文件实例、其 PE 架构却来自另一个文件实例。回归矩阵覆盖保留的 32 位测试夹具、当前的 64 位 Windows 测试可执行文件、被截断的 MZ 数据、无效的 PE 偏移以及错误的 PE 签名。

### Detect It Easy 静态检查

`internal/die` 拥有有界（bounded）的本地 Detect It Easy 适配器。项目锁定 MIT 许可证下的官方 DiE 3.21、保留的 Windows x64 压缩包摘要 `078f2934f267392247f9c7b759a1c2457a48bc2000b25b80c2f129955ee4a3b9` 以及 `diec.exe` 摘要 `dda171a904f6dc3a2c414e99e9d718c8d7500bc26c3dcdc1a72ec0e7d718cfe7`。每次扫描都会校验运行时文件标识与精确的 `die 3.21` 版本，以 JSON 模式调用（默认 15 秒、最长 2 分钟超时且有界输出），解析结构化检测结果，然后重新检查目标。运行时缺失、版本/哈希不匹配、超时、异常退出、输出超限或目标漂移都会失败即关闭。Core、CLI 与 MCP 都调用这个所有者；它不是长驻后端。

### 活动进程标识与协作控制

`internal/processcontrol` 是活动进程实例标识的规范本地所有者。在 Windows 上，它将 PID、内核创建时间、主模块基址、可执行文件标识与 PE 架构绑定为一个派生的进程键，并在返回前重新检查该进程。从而拒绝普通的 PID 复用、可执行文件替换与模块基址漂移，而不是仅把 PID 当作标识。

控制租约（lease）通过稳定的 `recordio` 旁车锁文件（sidecar lock）在协作的 CLI/MCP 进程之间串行化，并存储在 `state/process-control` 下。对相同所有者与进程键的获取是幂等（idempotent）的，对其他所有者则是互斥的，并且过期的租约不会阻塞复用了该 PID 的新进程实例。释放要求携带当前的 `lease_id` 作为代次栅栏，因此来自同一所有者旧租约的延迟释放无法删除同一进程的更新租约。`process inspect/acquire/get/release` 及其对应的 MCP 等价工具都使用该所有者。

### 动态 x86/x64 调试器路由

公开的调试器命名空间保持为 `x32dbg_*`，以免冻结的 124 工具后端契约再多出第二个重复的 x64 工具族。在内部，`internal/debugroute` 仅依据刚检查过的进程镜像派生路由（route）：i386/32 选择现有的 x32dbg 运行时，amd64/64 选择现有的 x64dbg 运行时；ARM/ARM64、非 PE 镜像以及机器/位宽不匹配都会失败即关闭。`process debug-route <pid>` 与 `process_debug_route` 以只读预览的形式暴露同一决策，带有 `attach_performed=false`，且绝不会启动调试器后端。

模块运行时拥有彼此分离的惰性 32 位与 64 位调试器后端，同时对外呈现一个历史上的 x32dbg 模块表面。x64 运行时使用 `runtime/x32dbg/release/x64`、其专属的状态/日志目录以及一个独立的回环 MCP 配置。如果缺少 x64 配置，则从 x32 回环配置派生出使用不同端口、并独立派生 bearer 令牌的配置；x32/x64 共用同一端口的情况会被拒绝。带防护的 AttachProcess 会在后端启动前从当前的进程控制租约解析目标架构，且后续的变更必须保持在绑定的架构上。

最终效果防护除了由假后端测试覆盖之外，还由一个隔离的真实 32 位冒烟测试覆盖。除非端口 19095 空闲且不存在任何 x32dbg/x64dbg/headless 进程，否则 `tools/smoke/x32-effect` 拒绝运行；随后它会构建自己的 32 位测试夹具、获取一个进程控制租约、附加自带的 x32 后端、使其暂停、执行一次带防护的 `WriteMemToAddress`、在外部恢复测试夹具的值，并重放同一个已完成的操作。重放会返回同一份缓存结果而不重新施加写入；将该操作 ID 复用于不同的字节会被拒绝。清理阶段会验证任务所属的会话绑定已消失且端口 19095 重新空闲。保留的证据摘要为 `testdata/x32-effect-evidence-20261002.json`；这是隔离的运行时验证，而非生产部署证据。

### 版本化的只读活动内存扫描

`internal/memscan` 独立于 x32dbg/x64dbg 实现候选扫描。在 Windows 上，它仅以查询/读取权限打开目标，用 `VirtualQueryEx` 遍历已提交的可读区域，并用 `ReadProcessMemory` 读取有界的块。它从不附加调试器，从不使用调试器 MCP 运行时，也从不授予进程写入权限。

启动请求必须携带由 `internal/processcontrol` 生成的新鲜 `process_key`；在候选记录发布之前，会在扫描之后重新验证进程实例。初始模式要么是精确值，要么是不定值，支持 u8/i8/u16/i16/u32/i32/u64/i64/f32/f64 解码以及可配置的对齐地址范围。每个候选都会存储地址、原始字节、解码值，以及捕获时观察到的精确区域标识（分配基址/保护、基址、大小、状态、保护与类型）。

候选集合以单调版本号持久化在 `state/memory-scans` 下。收窄需要 `expected_version` 栅栏，支持等于、改变、未变、增大与减小。在收窄前后都会验证进程实例，并重新查询每个候选所在的区域；区域漂移或不可读会移除该候选，而不是假定旧地址仍然有意义。初始覆盖受超时、字节与候选数量上限约束而有界。查询/读取失败与触及限制会明确体现在步骤统计与 `coverage_complete/partial_reason` 中；被中断的收窄会被标记为未完成，且不能被静默地链接到另一次收窄。

### 指针映射与跨进程验证

`internal/pointermap` 复用同一套只读进程内存接口，发现有界的、指针大小的反向引用加正偏移。搜索深度、偏移、字节预算、节点数、链数、对齐、地址范围与超时都设有上限。只有根槽位位于已加载模块内的链才会被持久化；根以模块文件 SHA-256/大小加 RVA 的形式存储，而不是绝对地址。

验证总是从一个新的 `process_key` 开始。系统会重新快照当前模块列表、重新检查锚点模块文件标识、把保存的 RVA 重新基址到当前模块基址，并逐级重新解引用每一层指针。因此，PID/进程代次发生变化时，只有搭配新的密钥才被允许；模块重定位与堆/分配重定位仍然可以通过验证，而模块文件漂移、模块缺失、某层不可读、指针漂移或不匹配的期望目标，都会使受影响的链失效。Build/get/verify 均保持只读，且不会启动调试器后端。

### 有界写入观测

`internal/modules` 在普通 x32dbg 工具调用之上拥有一个高层写监视工作流。它使用 xdbg 工作流锁序列化整个观测过程，并要求一条空闲的本地 xdbg 路由加上一个活动的进程控制租约。该工作流附加到被租约持有的进程，检查现有断点，拒绝同地址冲突，安装一个对齐的硬件写入断点，在有时限/事件数上限内运行，并记录指令指针、已加载模块/基址/RVA、当前线程、寄存器、线程列表、调用栈、事件日志，以及被监视字节的前/后值。

该观测只拥有它自己创建的调试器资源。正常清理时用 x64dbg 的规范命令 `bphc <address>` 移除其自身的那个精确硬件断点，然后停止其任务所属的会话；从不使用全局断点删除，且进程控制租约仍归调用方所有。如果超时或取消导致后端传输被重置，绝不会仅仅为了执行清理而启动一个新的调试器会话：监视会清除其自身的本地会话绑定并记录 `backend_reset/resources_released`。确定性的内存后端测试覆盖写入证据、同地址冲突保留、单地址清理以及传输重置导致的超时清理；发布冒烟测试刻意不会附加到无关的活动调试器会话上。

### 带防护的 PE Hook 规划与回滚

`internal/hookplan` 独立于调试器状态拥有基于文件的 PE detour 计划。规划接受位于可执行节内的 i386/amd64 PE 源 RVA 与目标 RVA。项目自带的 radare2 6.2.2 CLI 会在有界的时间/输出内被调用，以证明源地址恰好位于指令边界上；覆盖范围只会跨越连续完整指令扩展，直到至少有五个字节可用为止，并且报告出的指令字节必须与从目标文件读取的字节一致。可选的 `expected_hex` 增加了一道由调用方显式提供的原始字节栅栏。

活动计划会在 `state/hooks` 下登记其源 RVA 区间；与之重叠的处于 planned/applying/applied/rolling-back 状态的区间会被拒绝。当前的重定位模型有意限定为从源/目标 RVA 计算出的同模块 `E9 rel32` detour，并用 NOP 填充至已证明的完整指令跨度。两个端点都必须位于可执行的 PE 节内，且位移必须能放进带符号的 rel32。在本 D05 范围内，ReverseResearch 并不声称具备自动 trampoline 分配、向 trampoline 改写指令或代码洞选择能力。

应用要求精确的 hook 版本、持久的操作标识以及显式的原地确认。写入之前会重新验证 PE 结构与冻结的原始字节；回滚同样要求与记录完全一致的 detour 字节。applying/rolling-back 状态加上操作标识，使重试能够在不盲目重复写入的情况下，对已测试的“效果之后/记录之前”窗口进行分类并终结。错误的原始字节、错误的已写入字节、结构漂移、版本漂移以及未知的字节状态都会失败即关闭。Core、CLI 与 MCP 共享这个所有者，且候选冒烟测试在保留的 32 位 PE 测试夹具上验证了 plan/get/list/verify、重叠与原始字节错误的拒绝、apply 重放、回滚重放以及精确的 SHA 恢复。

### 版本绑定的游戏 DLL / Hook 兼容性记录

`internal/compatibility` 是游戏构建/模块/Hook 兼容性观察的唯一记录所有者。每条记录都冻结精确的目标模块标识（规范路径、SHA-256、大小与 PE 元数据），并可额外按 ID、基线 SHA、源/目标 RVA 以及冻结的原始/detour 字节绑定一个 D05 hook。记录可以引用已有的 casebook 证据，而不必复制研究证据存储。

结果与验证有意分离。遗留/手工笔记可以以 `unknown` 或 `candidate` 加 `record-only` 的形式存储；静态证据可以是 `static-verified`，但 `compatible` 的结果只有在具备 `runtime-verified` 验证，外加当前有效的 Case、显式证据 ID，以及至少一条 kind 为 `runtime` 或 `runtime-verification` 的被引用证据项时才会被接受。清单导入会解析相对模块路径并对清单生成指纹，但会保留所声明的验证级别；导入绝不会静默升级历史材料。

`compat add/import/get/list/verify` 及对应的 MCP 工具不会启动 Ghidra 或调试器。验证会重新检查当前模块标识、可选的 hook 绑定，以及所链接 Case/证据的完整性。它有意报告 `compatibility_revalidated=false`：审计一条兼容性记录并不等同于重新运行游戏。候选冒烟测试在所有后端保持空闲的情况下演练 add/get/list/verify。

### 带防护的 x32dbg 变更边界

`internal/modules` 在惰性后端启动之前对每个 x32dbg 工具进行分类。显式只读工具原样透传。类型化的状态变更工具要求携带 `_rr_guard` 元数据，其中包含 PID、进程键、所有者、租约 ID 与显式的操作 ID。CLI 的防护参数会注入同样的结构；MCP 则在工具 schema 中公布它。`AttachProcess` 必须与受防护的 PID 匹配，并创建一个同时携带随机 ReverseResearch 运行时代次的会话绑定。后续的内存/寄存器/断点/执行变更必须匹配同一运行时代次、活动租约与会话绑定。因此，一张已完成的历史 AttachProcess 收据（receipt）并不能证明新启动的后端已经附加。`StopDebug` 与正常的 Runtime 关闭会清除当前代次绑定。如果控制器崩溃，旧代次会阻止接管，直到其目标租约被显式释放/重新获取，从而保持失败即关闭的恢复方式。

每次类型化变更都由操作锁与会话锁串行化，并在后端执行之前写入一张持久的 `prepared` 收据。成功的结果被缓存在一张 `completed` 收据中，因此相同的重试会返回缓存结果而不重新执行。传输失败、结果缺失或后端工具错误会使操作保持在 prepared 状态；使用该操作 ID 的重复请求会以“结果不确定”失败，而不是去猜测调试器侧的效果是否已经发生。将同一操作 ID 复用于不同的工具/请求/租约会遭到拒绝。

`ExecuteDebuggerCommand`、`LoadBinary` 与 `RestartDebug` 被有意屏蔽，因为它们能够在类型化所有权模型之外创建、重定向或变更调试器会话。未知的未来 x32dbg 工具默认按带防护处理，而非只读。这一边界协调的是 ReverseResearch 的调用方；它并不能排除无关的调试器或恶意写入者。针对用户现有 x32dbg 会话的实际效果测试，有意不被用作发布证据。

### 补丁操作恢复

`internal/patchplan` 在一个计划可被应用之前，会同时计算冻结的源标识与预期的补丁后 SHA-256。计划支持单条编辑，或一组互不重叠、长度相同的编辑经规范化后的复合体。复合输入在持久化之前会先被解码、规范化、按偏移排序，并检查重叠、偏移溢出、空操作替换、4096 条编辑上限以及合计 1 MiB 的字节上限。计划 ID 与摘要使用规范化的编辑顺序，因此输入顺序不会产生重复的变更标识。在对精确的源数据流做哈希的同时会校验全部预期字节，且试运行只报告复合的编辑/字节计数而不写入。计划携带一个覆盖其变更关键字段的不可变摘要。apply 与 rollback 在触碰目标之前会先持久化每操作的 prepared 收据，而稳定的旁车 OS 锁会在 CLI 与 MCP 实例之间串行化协作进程。

在被中断的变更之后，重试不会盲目再次执行。管理器会把当前文件分类为原始源、精确的计划后置状态，或未知。只有在处于前两种状态时它才能终结一张 prepared 收据；未知的字节状态会失败即关闭。显式的 `operation_id` 会绑定到计划摘要、模式/输出与请求摘要，因此同一 ID 无法被复用于不同的变更。遗留计划记录只有在仍能证明其当前源/后置条件时才会被升级。这些保证并不声称能排除恶意写入者、提供断电持久性、符合网络文件系统锁语义或支持多文件原子事务。

## 路由与工具索引

### 路由 v4 结构化分类

`config/routes.json` 仍然是唯一的路由所有者。v4 为 `domain`、`intents`、`platforms`、`artifacts` 与 `effect_class` 增加了路由元数据，同时保留现有的路由 ID 与关键词匹配器。`internal/router` 把这些维度作为结构化的 `classification` 返回；遗留的 v1-v3 测试夹具保持可读，而 v4 配置在缺失 `domain` 或 `effect_class` 时失败即关闭。Mode/Skill 层是叠加层，不得引入第二个任务分类器。

### 授权范围（Engagement）/ 作用域所有者

`internal/engagement` 独立于 Router 与 Case 拥有持久化的研究授权范围记录。一个授权范围记录组织、操作者、目标白名单、显式排除项、允许的操作、可选的时间窗口、速率限制元数据、凭据引用、数据敏感度、清理要求以及报告分类。授权默认拒绝：目标、操作、活动状态与时间窗口必须全部匹配，具备效果的任务才可继续。该所有者不执行针对目标的动作；Generic Job 将在下一个 P0 垂直链路中把 `engagement_id + target + action + operation_id` 绑定到一个效果所有者。


`config/routes.json` 是版本化的路由事实来源。`internal/router` 执行确定性的任务分类，`testdata/routing-benchmark.json` 守护路由行为。

`internal/toolindex` 发现项目自有以及 PATH 可见的工具，并把机器本地结果持久化在 `state/tool-index.json` 下。路由可以推荐尚未安装的工具；缺失被显式呈现，而不会静默触发安装。

`internal/capability` 将路由目录、当前机器的工具索引以及供给配方联接为路由级别的就绪状态。每条路由会报告 available/installable/no-recipe 工具、覆盖百分比、是否至少有一个工具使该能力可运行，以及是否完全就绪。这只是咨询性状态；它既不安装也不执行工具。

`config/routes.json` 只拥有任务分类。`config/playbooks.json` 单独把选定的路由映射到一份经过校验的 Seep-Reverse-Lab 工作手册（playbook）契约：主 Skill 路径、平台 `reference_path`、G1-G4 关卡、失败参考以及完成标准。`internal/playbook` 校验每条被映射的路由都存在于规范路由器中，防止路由所有权重复，并要求所有被引用的文件保持在项目根目录之内。路由器自身从不加载 Skill、启动后端或执行针对目标的活动。

MCP 宿主把 `task_route`、`task_prepare`、`playbook_get` 与 `tool_index_scan` 作为同一批 Core 所有者之上的薄适配器发布出来。`task_prepare` 组合路由、能力/供给真实状态、沙箱推荐以及经过校验的路由所属工作手册；`playbook_get` 在并不加载后端的情况下暴露该机器可读契约。这让 AI 客户端的编排保持客户端中立：路由决策与工具发现既不驻留在提示文本中，也不驻留在第二套 MCP 专属的路由表里。

### Seep-Reverse-Lab 渐进式 Skill 层

`skills/seep-reverse-lab/SKILL.md` 有意保持简短且面向决策。详细的 Windows、Android、Web、证据与失败目录材料只在所选路由需要时才加载。控制回路要求分类、环境真实状态、一个对照基线以及范围最窄的可逆动作；同一形态的两次连续失败会强制改变假设，而不是第三次微调参数。完成要求标识、工具链、基线、可复现/交叉核对的效果、证据（Evidence）→ 结论（Finding）→ 研究路径（Path）的可追溯性，以及清理。

Android 工作手册吸纳了来自真实 APK 工作的泛化经验，例如功能重打包之前先做对照构建、结构感知的 DEX 编辑、分包标识、客户端/服务器边界分类，以及识别挂起/崩溃式回归。Web 工作手册要求一个隔离的浏览器配置文件，并把 JS/WASM/客户端计算与协议/服务器状态分离开来。有界的 Android/Web 运行时所有者现已与那些编排契约并存：Android 上为显式授权的 adb 探测/证据/一次性 UI 动作，Web 上为已安装浏览器标识、隔离配置文件规划、只读回环 CDP、classic SourceMap/内嵌源码读取、离线 HAR 摘要与静态 WASM。浏览器生命周期所有权、证书安装与设备授权仍然是显式的外部边界。

REA 吸收沿用 `webinspect -> Core -> CLI/MCP`：SourceMap 支持 classic/embedded indexed、VLQ 与 UTF-16 坐标；不执行源码/加载远程 section。HAR 的摘要、API/正文读取、比较保留历史 producer 归属和原始 ordinal/JSON pointer，不接受当前浏览器/服务器证明或请求重放。`appinspect` 拥有独立静态应用格式的有界解析；PE/ELF/Mach-O layout 仍由 targetidentity 唯一提供。Web/应用共用 `targetidentity.CaptureFile` 的同句柄有界读、重读摘要与路径/size/mtime 栅栏；原生 bounded identity 同时限制哈希增长与容器分配计数。

`iosinspect` 复用该 snapshot 读取 XML/bplist00 对象表，NSKeyedArchiver 与 compiled NIBArchive 只派生原序列化对象身份与声明，不实例化 Foundation/UIKit。`dfir` 复用 canonical ELF budget/标准库和该 snapshot，读取受限 Linux amd64 recorded core；PID/寄存器只属于历史记录，不能进入 live process identity/lease。未知 note 原始字节通过显式查询保留。`appinspect` 的 TAR/ZIP/ASAR 共用 archive entry read options 与安全路径校验；JavaScript import/export/CommonJS vocabulary 扩展同一 AST visitor。MCP app/Apple/core 解析复用既有 weighted resourceGate，每次占 8/16 权重，避免大对象解析并发绕过原闸门。

Apple/Harmony package projection 复用同一 ZIP directory admission 与 `readZIPContent`，按 archive-relative path 声明 bundle/component，不创建第二个 IPA reader 或持久 graph。Go raw metadata 的 byte/virtual mapping 仍放在 targetidentity：同一 snapshot 与 native table budget 下拒绝歧义、overflow 和部分 file-backed overlap，把 file range 与 zero-fill 空 module anchor 分开。appinspect 只解读 Go 记录格式和有界原始 bytes，不承担新的 native identity、加载状态或供应链认证。

`casebook.ResearchView` 从 canonical Snapshot 派生 declared links、精确 Finding dossier 与记录状态计数。它不持久化 graph、不按名称推断函数/目标 identity、不接受完成度；Verify 检查源文件，前后 Case revision 栅栏阻断混合快照。原 strict review/report、Target、Router、process-control/backend 与 Cloud/Tunnel owner 保持各自关闭权。具体支持/未知字段和独立夹具由唯一实施清单的 REA04–REA18 记录。

WABT 是原 WASM 查询的可选静态 producer profile。ToolIndex 负责唯一发现/身份，targetidentity 负责输入/工具/私有副本快照与 SHA 栅栏，securefile 负责本机 ACL；从 DiE 抽取的 toolprocess 唯一负责此类有界直接子进程输出、等待与取消。它没有 job/lease/installer writer，也不声称管理任意进程树。webinspect 只解释已批准的 WABT 版本/参数与返回语义；MCP 使用原重型资源准入。invalid-module 返回选定输入身份/工具 provenance/诊断并明确失败，timeout/truncation/drift/cleanup 失败不核销 validated acceptance。WAT/details 按原始输出 SHA 分页，目标永不实例化。

UP01–UP03 继续在该 owner 中提供离线 SSE body 检查与协议重建方法。SSE 按 CR/LF/CRLF、空行分帧和多行 data 还原，保留原始 ordinal/byte/line 范围及 data/ID 哈希；全文检查后才返回有界页，可选正文前缀另报截断。EOF 未完成 data 不分发，`[DONE]` 只计数且不停止扫描；application completion 固定为 unverified。解析器不模拟重连，不解读 provider JSON，也不承担账号、代理服务或工具执行事实。

Core 的 `prepare` 工作流把路由、能力就绪状态、供给计划、与路由相适配的沙箱计划，以及一份可选的经过校验的平台工作手册组合成一份只读的启动计划。没有工作手册的路由保持未映射状态，而不会被强行套用。它不会创建沙箱、安装工具、启动 MCP 或修改目标。

## 二进制/版本差异比对

`internal/bindiff` 在一个类型化的 Core API 之后包装了项目自有的 `radiff2` 可执行文件。快速差异比对会冻结双方的目标标识并报告文件级变化。函数差异比对执行有分析支撑的匹配，并利用各 PE 镜像基址把 radiff2 虚拟地址规范化为每次构建的 RVA。每条函数映射都携带原始匹配状态、相似度以及一个确定性的置信标签（`exact`、`high`、`medium`、`low`）。这一层是本地优先的，不需要 ReverseResearch MCP 服务器。

两种差异比对模式都会在外部分析器返回之后重新检查目标内容；发生变化的目标会使结果失效，而不是保留过期的分析前标识。这是一道前后内容栅栏，而不是针对恶意写入者的快照保证。

`internal/migration` 针对符合条件的函数匹配解析带标签的旧 RVA / 区分大小写的旧名称锚点。无效得分、`UNMATCH` 行以及低于阈值的候选会被排除。歧义被显式呈现，而不是静默选择第一个匹配。类型化的 Core 与 `diff migrate` CLI 共享这个所有者。结果始终声明 `candidate-only` 与 `runtime_verified=false`；符号与字节都不会被应用。

独立的语义佐证使用 `NewGhidraIsolated` 与 `tools/smoke/ghidra-isolated`，而不是已在运行的 Ghidra 守护进程。该冒烟测试分配独立的 localhost 端口、状态根、证据根与项目根，独立分析新/旧测试夹具，把每个数据库绑定回源文件路径，并比较函数名称/地址/大小。这在不改变 `candidate-only` / `runtime_verified=false` 契约的前提下强化了候选证据。规范化后保留的证据为 `testdata/ghidra-isolated-semantic-evidence-20261002.json`。

同一所有者还提供语义同步预览。`sync preview` / `semantic_sync_preview` 接受一份显式的旧/新语义快照和一份经过评审的迁移结果；它不会查询或启动 Ghidra。已映射的函数名称/注释以及结构/成员元数据被归约为确定性的 `suggest/preserve/conflict/same/skip` 动作。目标中由用户亲自命名的名称优先于迁移来的名称，存在差异的既有注释/类型算作冲突而不是替换，而歧义/未映射的函数绝不会收到语义建议。结构键允许目标结构保留手工重命名的显示名，同时仍按偏移比较成员。预览输出明确为 `preview-only`、`runtime_verified=false`、`writes_performed=false`。

## 研究记录与田野日志

`internal/casebook` 将机器本地的研究 Case 持久化在 `state/research/cases` 下。一个 Case 链接四个显式层级：

```text
Evidence -> Finding -> Research Path
```

证据可以按绝对路径、大小与 SHA-256 绑定一个源文件。源哈希与大小取自同一个保持打开的常规文件，并在哈希前后进行标识/大小/时间检查。所提供的结论引用必须指向同一 Case 内的证据，所提供的路径引用必须指向已存在的结论。无链接的观察与假设仍然被允许，但验证会显式把它们计为未绑定，而不是声称它们已被证明。

`case verify` 在 Case 锁之下快照精确的已持久化 JSON 字节，校验 ID、源绑定与引用，然后重新检查该 Case 的修订版本。源哈希在记录锁之外执行。并发的 Case 变化会使审计失效；验证绝不会修复或改写记录。即使 CLI 返回非零退出状态，JSON 也会报告完整性检查失败。有效的结果并不是语义或运行时验证的定论。

`internal/recordio` 拥有稳定的旁车 OS 锁以及同目录临时文件发布机制。整个 Case 的读-改-写事务在独立进程之间被锁定。替换失败不会删除最后一条已提交的记录。锁旁车文件会被保留，而 OS 会在进程退出时释放锁。所有并发写入者都必须使用该协议；较旧的、不参与协作的可执行文件不得写入同一状态。这些保证覆盖协作的本地进程，不覆盖恶意的文件系统篡改、网络文件系统锁语义或断电恢复。

`internal/knowledge` 在 `state/knowledge` 下存储不可变的田野日志笔记，并在 `internal/knowledge/builtins` 下存储独立的编译期内置语料。日志 ID 采用 `note_...`；经过评审的内置 ID 采用 `builtin_...`。内置项是只读、修订版本钉定的记录，带有显式的来源信息，不能被日志写入遮蔽或覆盖。遗留的 Search API 出于兼容性仍然只面向日志；`SearchFiltered` 可以组合日志与内置来源。

Search 与 show 会返回精确 JSON 记录的 SHA-256 修订版本以及来源信息（参考、许可证、上游修订/日期、适用的引擎/版本、作者提供的证据状态）。修订版本钉定的 `journal read` 返回有界的行范围，并拒绝过期修订或不安全的 ID。笔记可以携带领域、架构与工具适用性；过滤搜索也接受路由与来源。作用域令牌会被规范化，架构别名（`x64`/`amd64`/`x86_64`、i386 家族、`aarch64`）在持久化/过滤之前映射为规范值。新的本地笔记默认为未验证的来源；遗留笔记在读取时被标注为未指定，且不会发生迁移写入。内置条目在加载之前必须声明 `evidence_status=reviewed` 与显式的来源元数据。元数据只是研究数据，绝不是指令权威或自动的验证批准。

## 沙箱与供给

`internal/sandbox` 在 `state/sandboxes` 下创建项目自有的研究工作区。filesystem 配置档始终可用；当 WSL 与 Docker 配置档所需的本地后端缺失时，会失败即关闭。规划与创建是两个独立的概念，且沙箱根/布局是规范化的，因此调用方无法把创建重定向到项目自有状态树之外。

`internal/provision` 读取版本化的 `config/tool-recipes.json` 清单，并与机器本地的工具索引相结合。`tools ensure` 目前只产出一份可审计的计划：工具被报告为 `available`、`installable` 或 `no_recipe`。安装不会被路由或发现静默触发。

## 本地模块运行时

`internal/modules` 拥有按架构路由的惰性 x32dbg/x64dbg、Ghidra 与 radare2 模块生命周期。

- 所有模块初始均为空闲。
- 直接的 CLI 模块调用只启动所请求的后端。
- `module batch` 在一串本地调用之间保持后端状态存活，而无需运行 ReverseResearch MCP 服务器。
- 可选的 MCP 适配器使用同一个模块运行时，而不是拥有独立的后端生命周期。
- 失败的调用不会被自动重放，因为它们可能已经变更了调试器或分析状态。

底层被吸收的后端自身可能在内部使用本地 MCP 传输。那是实现细节，并不要求暴露或运行 ReverseResearch MCP HTTP 服务。

## MCP 适配器

internal/contractaudit 在不启动后端的情况下保持已部署入口的兼容性可审计。保留的 testdata/online-rr-rt-contract-20261001.json 快照是针对 124 工具后端/状态契约（33 个 Ghidra、10 个 radare2、80 个 x32dbg，外加 reverse_status）的、日期为 2026-10-01 的证据。2026-10-03 曾核对 ChatGPT RR/RT 的完整 238 工具表面与规范化名称集合。2026-10-09 REA 轮候选目录经 MCP 测试为 242 个工具；追加 UP01 后当前 243 个工具已通过 SDK 内存 transport 目录/调用验证与 Server 全包回归，其中新增 `web_source_map_read`、`web_har_inspect`、`web_sse_inspect`，旧后端契约没有扩建。候选目录只代表本地源码/运行证据；已安装服务、隧道与外部客户端 schema 的发布/刷新仍需另行核对。历史 124/238/242 记录均不能当作当前外部连接元数据。

`ReverseResearch.exe serve` 启动回环 HTTP MCP 适配器。监听器会拒绝通配、局域网以及其他非回环地址。`/mcp` 需要来自 `state/auth/local-mcp.token` 的、已持久化的 32 字节随机 bearer 令牌；令牌创建在跨进程层面被串行化，且格式错误的既有令牌会失败即关闭。`/healthz` 有意保持只读，且不要求 bearer 令牌。

`ReverseResearch.exe serve --tunnel` 会额外启动 OpenAI Secure MCP Tunnel。隧道认证仍然走隧道 ID/控制平面 API 密钥路径并使用内存内 MCP 传输，因此本地 bearer 令牌既不会被复用，也不会经由隧道传输。除非显式请求 `--tunnel`，否则在普通 CLI 工作期间以及仅本地的 `serve` 期间都会忽略隧道配置。

远程访问受限于运行 ReverseResearch 的那台机器可见的文件系统与进程。MCP 不会把另一台计算机上未传输的文件或活动进程神奇地变为本地资源。

## 生产运行时

三个模块使用 `runtime/` 之下的依赖：

- `runtime/x32dbg`
- `runtime/ghidra`
- `runtime/radare2`

Ghidra 锁定到本机的 MSYS2 UCRT64 CPython 3.14 运行时。启动时会同时校验 Python 版本与 UCRT64 SOABI，然后对 JPype 这类 ABI 敏感的原生依赖使用 UCRT64 系统 site-packages，同时追加保留的 `runtime/ghidra/python-packages` 捆绑包以提供 `mcp`、`re_mcp`、`re_mcp_ghidra` 以及 Python 侧的 Ghidra 适配器。工作子进程继承同一“系统站点优先 / 捆绑包次之”的搜索路径，因此父进程与工作进程使用同一个解释器家族，而不是第二套独立的 Python 3.12 安装。带版本的 ReverseResearch 覆盖层位于 `patches/ghidra` 之下，并在 Ghidra 启动之前同步进被忽略的运行时目录。

Ghidra 12.1.4 的本地项目文件系统把内部条目名称的字符限制在 U+0020..U+00FF 之内，并排除保留标点，因此外部中文文件名无法被安全地复用为项目条目名。Python 会话适配器把规范的外部路径保留为源标识，把不支持的基名映射为稳定的、内容寻址的 ASCII 名称 `rr_<sha24>`，只在导入期间暴露一个临时的硬链接/复制别名，并在其后移除该别名。中文的状态、证据、项目、缓存与源目录都受支持，并已在隔离的 headless/MCP 运行中得到验证。以点开头的路径会被尽早拒绝，因为 Ghidra 本身就拒绝这样的项目路径元素。Ghidra 12.1.4 的分析重置使用 `resetAnalysisFlags`，同时保留较旧的 setter 作为兼容性回退。隔离冒烟测试会归一化就绪竞争，把 `Program.getExecutablePath()` 恢复为调用方可见的 Unicode 源路径，断言导入别名已被清理，并在每次运行之后拆除其备用端口。

## 迁移收尾

在 x32dbg、Ghidra 与 radare2 仅使用生产运行时依赖完成独立复验之后，此前的 `tmp/legacy-input` 目录树已被移除。上游源码修订记录在 `docs/upstream-snapshots.md` 中，保留的冒烟测试夹具位于 `testdata/` 之下。
