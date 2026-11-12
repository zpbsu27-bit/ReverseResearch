# 常用研究流程与 Android 静态分析增强

ReverseResearch 的 CLI 与 MCP 共用 Core。0.4.0 补齐此前审计出的十项 CLI-only 操作，0.5.0 源码目录扩展至 281：新增 app_dex_inspect，并增强原 app_package_inspect 的 Android family；实际已发布版本以 installed EXE 与运行验收回执为准。Case、Evidence、Review、Report、知识笔记、沙箱、Router 和工具运行 owner 继续负责各自事实。工具数量表示入口覆盖，真实环境、分析范围和未验证语义仍按结果与实施清单判断。

2026-10-13 已发布 0.7.0：MCP 与 ChatGPT 网页均为 282 个入口，新增唯一 `app_android_recover`，并在原 `app_dex_inspect` 中增加指令/CFG/边；Windows五条研究链和Linux两条研究链分别留有实际运行证据。完整REA能力、DEX 041/CompactDex、ART类型验证及设备结论仍按唯一实施清单核销。

随后已发布 0.8.0：原 Go 工具增加无损记录、解码字段字节页和独立完整性标志，总数仍为282。Windows六条、Linux三条实际研究链与正式服务查询通过，ChatGPT 网页全部名称和更新的Go说明已核对；证据 `evidence/go-records-20261013/release-receipt-26.json`。这些静态声明不构成目标运行或供应链认证。

## 编译、验证与发布

在项目根目录运行：

```powershell
.\一键编译MCP.bat --no-pause
.\dist\candidate\ReverseResearch-MCP.exe --version
```

候选位于 `dist/candidate`，启动 BAT 与计划任务继续选择 installed。默认安装优先级是 `dist/ReverseResearch-MCP.exe`、根目录 `ReverseResearch.exe`、根目录 `ReverseResearch-MCP.exe`；首次安装发布到第一个位置。编译、启动、自启、发布与 ACL 使用同一个路径解析模块。

候选验证后，可以通过现有发布 owner 发布这份确切文件：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-promotion.ps1 -Action Promote -Candidate .\dist\candidate\ReverseResearch-MCP.exe
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-promotion.ps1 -Action Status
```

`.\一键编译MCP.bat --promote --no-pause` 合并编译与发布入口。发布回执保留在 `.tmp/promotion/promotion.json`，回滚副本同目录保存；同字节的重复发布保留原回滚来源。回滚用同一脚本的 `-Action Rollback`。prepared 回执、目的路径变化、安装字节与回执不符或旧程序不支持当前 state layout 时均拒绝，先核对原回执与实际文件再处理。进程级 ExecutionPolicy 参数沿用项目脚本入口，发布不改变系统策略。

已有自启任务时，发布通过认证 `/control/shutdown` 等待原服务结束，再启动同名 `ReverseResearch Server` 任务。`--version`、`/healthz.version` 和 MCP 握手共用一个版本标识；交付还需核对 installed SHA、任务的路径/参数、实际 `tools/list` 和网页刷新后的名称集合。

## Windows PE 静态研究

自然任务示例：**分析这个 Windows PE 程序的结构和导入，保留静态证据并生成研究报告。**

1. `task_prepare` 准备 `native-static` 路由、当前工具能力、工作手册与目录计划；需要目录时，把完整 `sandbox` 计划交给 `sandbox_create`。
2. `target_identify` 固定输入身份，`die_scan` 获取实际 DiE producer 结果；需要进一步反汇编/反编译时，沿已有 Ghidra/radare2 工具及 owner 继续。
3. 用已有 Case/Evidence/Finding/Path/WorkItem/Timeline 记录输入与结果；`case_review` 核对引用和 currentness，`report_render` 生成报告。

静态格式或 DiE 识别支持静态结论；运行行为需要另行取得运行证据。`sandbox_create` 只准备目录，返回 `isolation_started=false`、`target_execution_performed=false`，WSL/Docker kind 也保留这一边界。同一完整计划和 ID 可重试；不同计划、残缺目录、改动的布局会被拒绝，不删除已有研究内容。

## 跨版本函数候选迁移

自然任务示例：**比较两个版本的 Windows PE 程序，找出变化函数，生成迁移候选，并将证据关联到研究案例后输出报告。**

```json
{"left_path":"D:\\research\\old.exe","right_path":"D:\\research\\new.exe","limit":50}
```

这组参数可交给 `binary_diff_quick` 或 `binary_diff_functions`。后一工具支持 `threshold`，默认 70。输入 SHA 可通过 `expected_left_sha256` / `expected_right_sha256` 固定。每次页面查询经原 Analyzer 重新观察；有 `next_offset` 时，下一页同时提供第一页的 `expected_result_sha256`。完整结果或输入发生变化会拒绝，重新取得第一页。

`function_migration_plan` 使用同一对输入，附上 1–32 个 anchor：

```json
{"left_path":"D:\\research\\old.exe","right_path":"D:\\research\\new.exe","anchors":[{"label":"known-function","old_rva":4144,"old_name":"sym.KnownFunction"}]}
```

名称与 RVA 都提供时必须同时匹配。返回 mapped/unmapped/ambiguous 和 `candidate-only/runtime_verified=false`。完整收集迁移页面后，可交给既有 `semantic_sync_preview`，保留目标侧用户命名和冲突信息；没有符号或字节写入。结果页上限 48 KiB，直接 producer 输出和时间也有硬上限，截断会报错，不能当作完整分析。

## JS / SourceMap / HAR 离线研究

自然任务示例：**检查离线 JavaScript、SourceMap 和 HAR，定位源代码及历史 API 并整理证据报告。**

使用已有 `app_javascript_inspect`、`web_source_map_locate`、`web_har_api`，按工具的 artifact SHA 分页；需要正文时使用显式 body/source 读取入口。AST 声明、SourceMap 映射和 HAR 留存的历史捕获分别作为证据，不自动关联为同一运行链，也不访问捕获中的 URL。Case 的结构性 Review 与报告不升级这些语义边界。

## Android APK / Manifest / ARSC / DEX 离线研究

自然任务示例：**安卓离线 APK Manifest 和 resources.arsc 声明研究，查看 DEX 方法元数据并保留静态证据。** 原 Router 选择 `android-static`，原 Playbook 提供四个静态 gates；内置读取器无需 ADB、Frida、设备或额外反编译器。`capability_status` 的 readiness 只表示这个静态 profile 已具备；签名、安装、资源有效值、native binding、完整反编译和设备行为仍须各自验收。

`app_package_inspect` 的 `family=android` 复用原 ZIP/snapshot/CRC owner，支持 `components`、`manifest`、`resources`、`resource-values`。后者用 `resource_index` 选择当前构建中的一条配置，再以 offset/limit 读取 bag mappings。`app_dex_inspect` 支持独立 DEX 或 APK 中的精确 `entry`，区分方法引用、定义和 native 声明；classes/methods/strings 为 metadata 页，string-bytes 用明确 string_index 读取原始 MUTF-8 item 字节。

后续页传原 artifact 的 `expected_sha256`；成员哈希、编码字节范围、resource configuration SHA 和 index 只在该构建中有效。Manifest 权限/组件和 ARSC typed raw values 是声明；不把无设备静态观察写成有效权限、胜出配置、调用或签名认证。DEX 035/037/038/039/040 LE 可读取；041 container/CompactDex 显式拒绝。`instructions`、`cfg`、`edges` 用明确的 `method_index` 选择定义，先校验完整方法后分页。指令包含原字节哈希和偏移，`literal` 是精确 signed-decimal JSON 字符串；payload 行是数据。CFG 保留不可达代码与保守 possible exception 边，结构检查不等于 ART 类型验证或实际调用。

`app_android_recover` / `app android-recover` 在同一个原 backend owner 中使用固定 JADX headless 0.7.1、项目 metadata bridge 和原完整 JDK21。`classes` 可用 case-sensitive query 过滤 top-level 名称；`class` 用精确 `class_name`，`method` 还用 `method_name`，重载必须显式 `overload_index`。`references` 查询类或唯一方法的静态入站引用，位置与运行调用未知。每次请求复制不可变 target/engine/bridge，返回前关闭 worker 并清理私有目录；不确定的 startup cleanup 会失败并保留证据。native 无代码体、`<clinit>` 的 smali fallback 与普通 Java 文本分开。恢复文本最多1MiB，完整性未知；原 DEX index/descriptor/字节始终由 `app_dex_inspect` 负责。

恢复结果是 canonical JSON 字节的 base64 页，limit=1..16384；第二页起同时传 `expected_sha256` 和 `expected_result_sha256`。例如 `ReverseResearch app android-recover sample.dex --view method --class-name demo.OfflineCodeProbe --method-name dense`。`android-code` 是观察路由，原 `android-static` 保留内置声明/原字节读取，设备修改仍走 `android`。ToolIndex 的 `jadx-headless` 是 interpreted profile，公开 interpreter 与 Jar/bridge/java/compiler 身份，不把 Jar 当 native executable。`runtime-profile-present`、runnable/full_ready 是当前文件组合可发现的事实，实际进程树支持、分析结果和完整重构分别验收。

把原 APK 与对应成员查询结果交给原 Case → Evidence → Finding → Path → strict Review → Report → Journal 链，验证输入 SHA 未变并保留 runtime gaps。设备任务仍使用原 `android` 路由和设备 Playbook。

## Go 构建元数据与无损记录

`app_go_inspect` / `app go` 的摘要来自原始字节定位器与同一个记录模型。`app_go_metadata_read` / `app go-read` 的 `part=records` 保留每行的原文件范围、哈希、状态和 replacement 对应的记录索引。未知、重复、坏编码及未终止行保留为 unparsed，不覆盖已经取得的有效声明。

`part=record-field` 必须同时指定 `record_index` 与 `field=path|version|sum|key|value`，分页返回解码后的 base64 字节，可精确读取空值、引号转义和非 UTF8 值。这些字节是语义派生值；原始行的位置由 `source_range` 给出，原文件字节用 `part=module-body` 读取。records 默认50条、最多200条；字节页默认8192、最多16384字节。后续语义页须携带原 artifact 的 `expected_sha256`。

`grammar_complete` 表示所有行已按当前支持语法识别，`text_summary_complete` 表示文本摘要能够保留全部记录语义，`coverage_complete` 只表示当前页覆盖了查询对象。三者独立；编译器、模块和设置仍是未经认证的嵌入声明，不构成运行或供应链完整性结论。

同一研究验收入口可加 `-go-metadata-target <owned Go binary>`：以标准库作为独立验收对照，核对所有记录与字段分页、原始范围及 SHA，再复用 Case/Review/Report/Journal 交付。自有源码在 `tools/fixtures/go-records`，含本地模块替换；样本须由现有 Go 编译器预先生成，验收入口不编译或执行该目标。检验带引号的 `-ldflags` 时不能使用 `-trimpath`，Go 编译器会有意省略该项设置。

## 知识复用和能力发现

`journal_add` 必须带稳定 `operation_id`，例如 `case-20261013-note-01`。同一规范化请求返回原 ID/revision/time；重复 ID 的不同请求被拒绝。正文最多 65536 UTF-8 bytes，来源/许可证/证据标签为作者提供的研究数据。

`journal_search` / `journal_get` 返回 metadata 与 revision，正文用 `journal_read` 的 revision-pinned 行分页读取。搜索的 `has_more` 表示仅返回排名前缀，可缩小 route/domain/architecture/tool/origin 条件。CLI 的 `journal add --operation-id ...` 使用同一 store；旧 CLI 不提供 operation-id 时保留独立新增行为。

`capability_status` 查询一个 route 或完整能力列表；`playbook_list` 列出原 registry 的路由、Skill/reference、gates 和 done criteria。列表用相同的结果 SHA 分页，能力探测更新原 ToolIndex，不安装或启动外部工具。`runnable` 与 `full_ready` 保持原 Core 定义。

## 可复现验收

要求已有 Windows GCC、DiE 3.21 与 radiff2；运行入口不会获取或安装工具。每次提供**新的** evidence 目录：

```powershell
go run -buildvcs=false ./tools/smoke/research-workflows `
  -root . `
  -executable .\dist\candidate\ReverseResearch-MCP.exe `
  -compiler C:\msys64\ucrt64\bin\gcc.exe `
  -work-dir .\evidence\research-workflows-my-run
```

验收会复制指定候选与隔离配置、编译两份自有 PE 样本，在独立 loopback MCP 上运行三条流程，留下 `receipt.json`、`candidate-catalog.json`、逐次调用结果、canonical Case/Journal/Sandbox 状态与三份 Markdown 报告。被分析的 PE/JS 不执行。认证 shutdown 及进程退出成功后才把 receipt 写为 PASS；结果不明时读取已有 receipt 和日志，不重跑同一 evidence 目录中的写入。

要加入第四条 Android 离线链，在同一个入口额外传 `-android-aapt2 <exact aapt2.exe>`、`-android-r8 <exact r8.jar>`、`-android-jdk <existing JDK directory>`。三项必须齐备；入口不会下载工具。自有 `tools/fixtures/android` 源码经真实 javac/D8/AAPT2 产生无 main、unsigned 的 APK；source/compiler hashes 在生产前后核对。通过真实 MCP 查询 manifest、八条资源配置、分两页的 array mappings 与 DEX definitions/references，随后通过同一 Case/Review/Report/Journal 链。编译器执行与目标执行分别记账，APK 不安装、不加载或运行。

同一入口加 `-android-code-recovery` 会用自有 OfflineCodeProbe 经真实 javac/D8 生成另一份无 main 的 DEX，验证全方法指令/CFG/边、Java/smali/native/overload/reference、双 SHA 字节页和失败/取消清理，再完成第五条研究交付。Linux 同一入口用 `-android-code-dex <owned producer DEX>` 与已有完整 Java21 profile；不新建 supervisor 或复制生产 state/tunnel 凭据。

`-go-metadata-target <owned Go binary>` 验证 lossless records、replacement、quoted settings 与 decoded-field 原字节页，并沿同一研究链交付。Go 标准库只在验收器中作独立 oracle，产品继续使用唯一原 locator/frame/snapshot。

`-evm-target <owned compiler-produced hex>` 与 `-evm-receipt <producer receipt>` 增加 EVM 接口推断研究。自有 `tools/fixtures/evm/InterfaceProbe.sol` 由固定官方 solc 0.8.28 编译；完整编译器 ABI/selector 声明与 EVMole 推断分别保存。普通 ABI/fallback dispatch、参数与可变性、终端 CBOR、完整 engine JSON 双 SHA 分页通过实际 MCP 取得；编译样本中的两处 pure 声明被原引擎保守推断为 view，验收会记录差异，不把推断当作已验证 ABI。另一独立 published vector 真实返回 pure。Windows/Linux 使用同一原 harness 和研究 owner，均不部署或执行合约。

原 `app_evm_inspect` / `app evm` 默认 `view=instructions`；`view=interface` 查询函数页，`view=interface-bytes` 读取精确 engine JSON 字节页。后续 interface 页同时提供 `expected_sha256` 和 `expected_result_sha256`。内置 EVMole 0.9.3 引擎不需要 Node 或外部服务；每次调用的 WASM 实例有 256 MiB 线性内存上限、30秒 deadline、context cancellation，并在成功返回前关闭。这些推断不证明部署真实性、发现完整性、hardfork 或运行可达性。

本地候选 PASS、正式 installed/运行 PASS、网页目录刷新是独立证据。Android 设备、其他 native host、浏览器运行、完整 REA 语义和云端应用管理解析继续按实施清单保留未验收项。

Linux 原生验收复用同一个入口和 Case/Review/Report/Journal。提供精确的 Linux 候选、由前述 producer 生成的自有 APK，以及全新的私有目录；已有 runtime profile 可选开启真实引擎验收：

```sh
research-workflows -root /path/to/ReverseResearch \
  -executable /path/to/linux/ReverseResearch \
  -android-apk /path/to/producer/offline.apk \
  -work-dir /var/tmp/rr-native-fresh \
  -radare-profile /path/to/native-profile \
  -ghidra-profile /path/to/native-profile
```

profile 中的 runtime/radare2、runtime/ghidra 必须已准备好；入口不会安装依赖。配置复制排除 tunnel.json 和生产 state/凭证，Ghidra 使用原 patches/ghidra overlay。验收包含 native CLI/MCP、完整目录、APK 研究链、实际 ELF 信息/函数/反编译返回、输入哈希及受支持 backend scope 的关闭。Ghidra 的 opening 必须经 wait_for_analysis 达到 ready；stdio text 与 structuredContent 都保留，协议成功不能替代这些语义断言。receipt 的 verified_external_engines 明确列出本轮实际通过的引擎，shutdown_verified 只在原服务真正退出后置为 true。cgroup/proc 观察是本轮验收数据，不是新的产品进程状态库或关闭 authority。
