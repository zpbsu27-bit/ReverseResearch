# ReverseResearch 第二轮极限审计与系统性修复报告

> 基线：c099cea + 工作区未提交的 Family 1~8 整改代码（57 文件 / +1948 行）
> 日期：2026-10-03
> 上一轮报告：`BUG_AUDIT_7x24_CONCURRENCY_20261003.md`（24 条，仅报告不修改）
> 本轮目标：以高并发、7x24 无人值守、内存/磁盘极限压榨视角，**逐字 + 跨行语义**复核整改代码，
> 找出“整改本身引入的新 BUG”与“整改没覆盖到的同类代码”，按类别横扫并直接修复。

---

## 一、结论摘要

| 分类 | 本轮新发现 | 本轮已修复 | 判定需产品决策后施工 |
| --- | ---: | ---: | ---: |
| A 补偿事务 / 回滚后置条件 | 4 | 3 | 1 |
| B 锁作用域（去掉全局锁之后） | 5 | 3 | 2 |
| C shutdown 与生命周期预算 | 2 | 1 | 1 |
| D 进程所有权与日志（举一反三） | 3 | 2 | 1 |
| E 有界 I/O 与内存放大 | 4 | 3 | 1 |
| F 持久化状态生命周期（新增 retention 代码） | 10 | 6 | 4 |
| G 测试有效性 / 验证可信度 | 3 | 2 | 1 |
| **合计** | **31** | **20** | **11** |

同时复核上一轮 24 条：**P0-01 只修了一半**（本轮补完），
P1-01/02/03/04/06/07/08/10、P2-01/02/03/04/05/07/08 的整改方向正确且已落地，
P1-09（进程树）漏了 radare2，P2-04（锁轮询）在 `WriteFileShardQuota` 上仍有残留。

本轮最重要的发现不是“又找到一个空指针”，而是三条**跨行语义级**问题：

1. 去掉 `patchplan` 全局互斥锁后，**同一目标文件的两个不同 plan 可以并发原地改写并互相污染 hash 判定**，
   失败后既不回滚也不落状态，plan 永久卡在“已计划但文件已改”的死区。
2. 新加的 quota / index / archive 代码把**廉价 size gate 放在了错误的一侧**：
   扫描跑完 1 GiB 才发现配额满；写路径按“估算值”放行、读路径按“实际字节”拒读，
   于是产生**永远打不开的持久化状态**；一条坏记录能让整个 List / Stats / Begin 永久失败。
3. `go test ./...` 在管道里永远返回 0，掩盖了 `internal/backend` 一个**在 Windows 上不可能通过**的
   Ghidra worker 断言测试 —— 也就是这条 Python 导入顺序护栏实际上一直没有在被验证。

---

## 二、A 类：补偿事务 / 回滚后置条件

### A1【P0 残留 → 已修复】“已恢复原字节”仍然没有可验证后置条件

上一轮 P0-01 只把被吞掉的 `WriteAt`/`Sync` 错误接上了，但结论语句依旧是
`patch byte verification failed; original bytes were restored` —— **没有任何读回校验**。
磁盘满、设备错误、写缓存丢失时，`WriteAt`+`Sync` 都可能“成功”，文件却仍是半改状态。

- 证据：`internal/patchplan/patchplan.go:374` `restoreSingleEdit`
- 修复：写回后强制 `ReadAt` 重读并逐字节比对，不一致返回
  `recovery postcondition failed at 0x%x: restored bytes do not read back`；
  只有真正读回一致，才允许输出“restored / were restored”。
- 同类横扫：`rollbackInPlaceEffect`（`operations.go:694`）的镜像路径同样调用该原语，一并覆盖；
  composite 路径 `multi.go:450 restoreOpenFileEdits` 原本就返回 restoreErr，本轮统一到同一后置条件语义。

### A2【P1 新发现 → 已修复】apply 成功后整文件 hash 不符 → 文件已改、状态未落、且无恢复入口

跨行推断链：`patchInPlace` 只校验“自己那段字节写对了”（`patchplan.go:360`），
随后 `applyLocked` 比较整文件 hash（`operations.go:438`）。
若期间有任何其他写入者改了文件的别处，`appliedHash != ExpectedAppliedSHA256`，
代码只 `return errors.New("applied target hash does not match the planned postcondition")`：

- 文件**已经被写了**；
- plan **没有**被记成 applied（仍是 planned）；
- 下一次调用走到 `classifyApplyState` → `"other"` → `patch operation outcome is unknown`；
- 于是这个 plan 在这个文件上**既不能 apply 也不能 rollback**，只能人工删状态。

修复（两处配合）：

1. 根因由 B1 的 target 级锁消除（同文件不再并发）；
2. 该分支错误信息改为携带**实际观测 hash + 计划 hash + 明确“文件已写入但未按 applied 落状态”**，
   并新增可判定的哨兵错误 `patchplan.ErrPatchOutcomeUncertain`（`operations.go:27`），
   同时把 apply / rollback 两处 “outcome is unknown”（`operations.go:447`、`operations.go:657`）统一 wrap 到该哨兵，
   调用方从此可以程序化区分“可重试 / 必须人工确认”。

### A3【P1 新发现 → 已修复】Remote Agent 崩溃后 “running” 收据永久卡死 operation id

`ledger.Begin` 写入 `State="running"`，`Complete` 只接受 `running`（`ledger.go:135`）。
agent 被 OOM kill / 断电 / 进程被杀时，收据永远停在 running：

- 同 operation_id 重试 → `Begin` 返回 `ErrOperationExists` → HTTP 409，**永远**；
- `stats.Running` 永不回落，fleet 状态长期说谎；
- 无人值守场景下这是典型的“一次崩溃、永久降级”。

修复：`ledger.go` 新增 `settleStaleRunning`，`Begin` 命中 running 收据时，
若 `CreatedUTC` 超过 `StaleRunningOperationAfter`（2h，刻意远大于 30min 执行上限，避免误判在途任务），
就把它结算为 `uncertain` 并同步 stats（`Running--`/`Uncertain++`，Total 不变，维持校验不变式）。
新增测试 `internal/remoteagent/ledger_recovery_test.go` 三条：崩溃收据被结算、fresh running 不被误结算且仍可 Complete。

### A4【P2 残留 → 已记录】`ledger.Complete` 写失败时返回 500，收据停在 running

transport.go:195。本轮靠 A3 的 2h 兜底自愈，不再单独施工；
若后续要做“立即补偿”，必须用 detached 短窗口并避免在磁盘满时无限重试。

---

## 三、B 类：锁作用域（去掉粗锁之后必须补细锁）

### B1【P1 整改引入 → 已修复】patchplan 没有 target 级串行

上一轮 P2-02 判定“全局 `Manager.mu` 粒度过粗”，本轮整改**直接删除了全局锁**，
只留下 `lockPlan(planID)` 与 `lockOperation(operationID)` —— 两者都是**内容域**锁：

- 同一文件、不同 offset/不同字节 ⇒ 不同 planID ⇒ 并发执行；
- 两个 in-place apply（或 apply 与 rollback）同时打开同一文件，各自写自己的段，
  再各自做整文件 hash ⇒ 双方都看到对方的字节 ⇒ 双双 A2 死区；
- copy 模式另有输出文件竞争：两个不同 plan 写同一 `output_path`，
  `Stat` 都不存在 → 都 `Rename` → 后者覆盖前者，而两个 plan 都报告成功。

修复（`internal/patchplan/operations.go`）：

- 新增 `lockTarget(path)`（`targets/.<sha256(lower(clean(path)))>.lock`，路径已 `Clean`+小写归一）；
- `applyLocked`：in_place 锁 `plan.Path`，copy 锁 `output`（**每个事务恰好一把资源锁**，因此不可能自锁死锁）；
- `rollbackLocked`：事务全程锁 `plan.Path`；
- 固定加锁顺序 **plan → operation → target**，并在注释中写明，composite/copy 全部复用同一入口，无旁路。
- 检查过 `multi.go` 不存在第二个公开 apply/rollback 入口，故单点插桩即覆盖全家。

### B2【P1 数据竞争 → 已修复】`Runtime.x32Guard` 无同步读

`x32Guard` 只在 `guardOnce.Do` 内写（`modules/runtime.go:236`），
但 `resetXDBGSession` 与 `CloseContext` **直接读字段**且不经过 `mutationGuard()`，
因此 shutdown 与首次 x32 调用并发时是一次真正的 Go 数据竞争（race detector 未必命中该时序）。

修复：新增 `loadedGuard()`，一切读取都经 `mutationGuard()`（借 `sync.Once` 建立 happens-before），
`resetXDBGSession` / `CloseContext` 改用之。

### B3【P2 生命周期竞态 → 已修复】Close 超时后仍可能装入新 session generation

`backend.Lazy.CloseContext` 在等 `startDone` 超时时会调用 `finishCloseState()`，
而它把 `closing` 复位成 `false`；此时仍在返回路上的 `b.start` 若“成功”，
`ensure` 只检查 `b.closing`（`backend.go:122`）→ **Close 已经返回错误之后，仍然装入一个活 generation**，
该 session 再也不会被任何人关闭。

修复：新增 `closeEpoch`，`CloseContext` 每次自增；`ensure` 在决定启动时捕获 epoch，
安装前要求 `closeEpoch` 未变且 `!closing`，否则走“startup 期间被关闭”的丢弃 + cleanup 路径。

### B4【P3 残留】`rotatingLog.Write` 持 `l.mu` 跨越文件写
### B5【P2 残留】`recordio.WriteFileShardQuota` / `CheckShardQuota` 仍用不可取消的 `Acquire(...,10s)`
（`internal/recordio/shard_quota.go:27,52`）—— 上一轮 P2-04 的同类残留；请求驱动路径应改用 `AcquireContext`。

---

## 四、C 类：shutdown 与生命周期预算

### C1【P2 → 已修复】workflow 信号量忙时**整段跳过**调试器 teardown

`modules/runtime.go` 旧逻辑：`acquireXDBGWorkflow` 失败 → 只 join 错误 →
`else` 分支不执行 → x32dbg 的 `CloseContext`、guard 清理、bits 复位**全部跳过**。

修复：acquire 失败不再跳过清理；改为记录“shutdown 时 workflow 繁忙”错误，
并用 `cleanupContext()`（调用方 ctx 已失效时给一个 5s detached 补偿窗口，符合上一轮 Family 6
“只允许明确补偿 effect 使用短暂 detached context”的约束）照常完成 x32dbg 32/64、guard、ghidra、r2 的 drain。

### C2【P3 → 仅记录，故意不改】关闭预算互相矛盾

`backend.backendCloseTimeout = 30s`，但 `main.go:99` 只给 `runtime.CloseContext` 10s；
运维脚本 `tools/ops/manage-autostart.ps1` 给 20s + 10s（`Wait-Listener` / task-state 轮询）。
端口由 `defer listener.Close()` 提前释放，脚本不会误判，但“30s 实际永远用不到”是配置谎言。
不在本轮改动的原因：放大内部窗口会改变无人值守重启的可观测行为，应与脚本一起、由运维确认后调整。

---

## 五、D 类：进程所有权与日志（上一轮 Family 7/8 的漏网页）

### D1【P1 → 已修复】radare2 完全被进程树与日志整改漏掉

上一轮 P1-09 / P1-10 的整改只覆盖 `processCleanup` 的两个调用者（ghidra、x32dbg）。
`internal/backend/radare2.go` 走 `mcp.CommandTransport`：

- **没有 Job Object** → RR 被强杀时 `r2mcp.exe` 及其子进程孤儿化，占端口、占文件、拖死下次启动；
- **完全没有 stderr 落盘** → 已核实 SDK 的 `CommandTransport.Connect` 只接管 stdout/stdin，
  子进程 stderr **继承 RR 自身的 stderr**：既不轮转（回到 P1-10 的磁盘耗尽），
  又可能在无人读取的管道上写满而**阻塞 r2mcp**，表现为 r2 后端莫名 hang。

修复：

- `common_windows.go` 新增 `attachKillOnCloseJob(cmd, log)` —— 专供“Start/Wait 由别人负责”的子进程，
  只挂 kill-on-close job 并释放日志句柄，**绝不调用 `cmd.Wait()`**
  （SDK 的 `pipeRWC.Close` 已经 Wait；重复 Wait 会产生假的 “exec: Wait was already called” 关闭错误）；
- `radare2.go` 用 `openLog(root, "radare2.log")` 接 stderr，Connect 失败时 `errors.Join(err, logFile.Close())`，
  Connect 成功后挂 job，挂 job 失败则关闭 session 并上报，绝不留下“活 session + 无 owner”；
- 额外堵住一个孤儿窗口：SDK 的 `CommandTransport.Connect` 是**先 Start 再做握手**，握手失败时它不会替你收尾子进程。
  新增 `reapStartedCommand(cmd)` 在 Connect 失败路径 Kill 掉已启动的 child
  （刻意不 `Wait`：transport 的读 goroutine 还挂在 stdout 管道上，此时 Wait 不安全；
  被 Kill 的子进程已释放端口/文件，进程对象在 RR 退出时回收）。

### D2【P2 → 仅记录】Job Object 在 `Start()` 之后才 assign
`ghidra.go:286`、`x32dbg.go:91` 都是先起进程再 `AssignProcessToJobObject`，
在该窗口内已创建的子进程不受 kill-on-close 管辖。彻底修法需要 `CREATE_SUSPENDED` + assign + resume，
但 Go `exec.Cmd` 不暴露主线程句柄，需走 `NtQueryInformationProcess`/PEB 或原生 CreateProcess，
风险高于收益，本轮记录为已知残余限制（生产影响很小：daemon 子进程都在握手之后才 fork）。

### D3【P3 → 已修复】后端日志 0o644，与持久化记录的 0o600 + ACL 约定不一致
`common_windows.go` 的 `openLocked` 原来用 `0o644` 打开 `ghidra.log` / `x32dbg-*.log` / `radare2.log`。
日志里会出现目标路径、endpoint、崩溃输出，机密性却比任何一条 JSON 状态都低。
修复：改为 `0o600` 并在每次（含轮转后的重新）打开时调用 `securefile.RestrictFile`，与 recordio 同一套约定。
刻意**没有**对 `evidence/` 目录本身做 `RestrictDir`：该目录同时被审计/研究输出使用，
收紧目录 ACL 属于跨模块策略变更，需在发布流程里单独确认。

---

## 六、E 类：有界 I/O 与内存放大

### E1【P1 → 已修复】`compatibility_import` 无上限读整个文件
`internal/compatibility/store.go:62` 对**调用方给定的路径**直接 `os.ReadFile` 后才 `json.Unmarshal`。
一个 10 GB 的“manifest”就是一次确定性 OOM。
修复：`recordio.ReadFileLimit(absolute, MaxImportManifestBytes)`（新增 16 MiB 上限，`types.go`），
size gate 前移到任何分配之前 —— 与上一轮 P1-05 的验收原则同一条。

### E2【P1 → 部分修复 / 剩余为已知债务】full hash 仍在很多用户路径前面
已核实整改把 `InspectBounded*` 正确铺到了 malware / dfir / sarif / sbom / cloud / cti /
attack-graph / protocol-sample / readcap 等有字节语义的路径。剩余两类：

1. **ctx 丢失**：`internal/server` 114 个 handler 里约 100 个签名是 `func(_ context.Context, ...)`，
   底层 `hookplan`、`bindiff`、`die`、`compatibility`、`iosinspect`、`firmwareinspect`、
   `processcontrol`、`x32_watch` 等全是无 ctx 的 `targetidentity.Inspect(path)`；
   客户端断开后哈希仍然继续跑。
2. **双重全量哈希**：`iosinspect/ipa.go`、`firmwareinspect/firmware.go` 等 currentness 路径先 hash 一遍、
   结束时再 hash 一遍（正是上一轮“典型反例”的形状）。

不在本轮一次性修完的理由：这是**跨 50 个包的 ctx 签名重构**，
半 threading（改一半、中间函数仍吞 ctx）比不改更危险。
建议按 Family 3 剩余项单独立项：先给“只做 currentness 校验”的第二次 hash 复用第一次结果（纯赢，无语义变化），
再逐包把 ctx 透传到 `InspectContext`。

### E3【P2 → 已修复】Remote Agent 无 deadline 时等于“永远运行”
`transport.go:133` 原实现 `deadline, _ := time.Parse(...)` 忽略错误，且 `DeadlineUTC==""` 时**不建任何执行 deadline**。
修复：统一用 `DefaultJobExecutionWindow`（30min）封顶，调用方 deadline 更早则取更早值；
解析失败不再产生“立刻过期的 context”，而是落到默认上限。
（`ServeMTLS` 仍无 `WriteTimeout`：单值 WriteTimeout 会截断合法长任务，属错误修法，
应改用 `http.NewResponseController(...).SetWriteDeadline` 按 handler 设置，本轮记录未施工。）

### E4【P3 → 已修复】写失败诊断本身成为无界输出
`internal/server/httpwrite.go`、`internal/remoteagent/httpwrite.go` 原本对每次 encode/write 失败
`log.Printf` 一行。客户端持续断连时这是**自我放大的 stderr 洪水**（且绕开 consolelog 的色彩/串行约定）。
修复：计数器 + 采样（第 1 次与每 1000 次输出，并带累计次数）。

---

## 七、F 类：持久化状态生命周期（本轮新增整改代码的问题集中区）

### F1【P1 → 已修复】配额检查放在昂贵扫描**之后**
`memscan.Start` 先 `initialScan`（最高 1 GiB、30s）再 `saveNew → ensureNewScanCapacity`；
`pointermap.Build` 同样。到 1024 条记录后，每次 Start 都是“白烧一遍 I/O 然后失败”，永远如此。
修复：`manager.go` 在打开进程内存之前加 pre-flight 配额闸门（memscan `Start`、pointermap `Build`）。

### F2【P1 → 已修复】写路径按估算放行，读路径按实际拒收 → 产生永远打不开的状态
`MaxCandidateStateBytes=64 MiB` 的估算**不含 `RegionIdentity`、History 与 JSON 语法开销**，
而 `load` 用 `MaxPersistedScanBytes=128 MiB` 的实际文件大小把关。
于是存在一段“预算判定通过、成功落盘、之后再也 load 不出来”的扫描 ——
数据写进去了，却永远无法 refine/verify，只能手删文件。

修复：让写路径与读路径共享同一个物理上限 ——
`memscan.stateLimitWriter` / `pointermap.persistedMapLimitWriter` 在流式编码过程中计数，
超过 `MaxPersisted{Scan,Map}Bytes` 立刻失败；`recordio.WriteStream` 丢弃临时文件、不发布，
因此“不可打开的记录”从此不可能存在。保留流式内存优势，不引入整包 buffer。
新增单测 `internal/memscan/state_limit_test.go`。

### F3【P2 → 已修复】配额统计口径自相矛盾
`scanStorageUsage` / `mapStorageUsage` 用 `map[string]struct{}` 去重**条数**，
却对分片 + legacy 两个位置的**字节**重复累加，还缺 `info.Size() < 0` 防御。
修复：改为 `bytesByID` 去重并取较大副本计费，count 与 bytes 口径一致。

### F4【P1 → 已修复】recent 索引：一条坏记录让 API 永久失败，而且“自愈”会自我毒化
跨行推断（这是本轮最有价值的一条）：

- `job.ListRecent` 对每个索引条目 `s.Get(id)`，**任何错误直接 return err**；
- 仪表盘按 `ListRecent(500)` 调用 → 一条被外部删除或损坏的记录让 dashboard 永久 500；
- 更隐蔽：`rebuildJobIndexUnlocked` / `scanAllJobHeaders` 遇到**第一个**坏 header 就整体失败，
  而 `currentJobIndexUnlocked` 在 dirty 标记存在时**必须**走 rebuild；
  → 如果只把读路径改成“标脏重建”，就会得到“每次读都重建、每次重建都失败”的**永久毒化**。

因此修复必须同时做三件事：

1. `ListRecent`：跳过取不到/坏记录，遇到 `ErrNotExist` 补一个 `markJobIndexDirty()`（`job/index.go`）；
2. rebuild/scan 的遍历改成**逐条容错**：新增 `readJobHeaderBestEffort` + 共用 `walkJobRecords`
   （条目级错误跳过，目录级错误仍致命，`ErrNotExist` 视为并发删除）；
3. `List()`（显式全量语义）保持严格：只容忍扫描期间文件消失，坏记录仍然报错。

### F5【P1 → 已修复】casebook 同一模式的横扫
`casebook.List(limit)` 也是“索引 + 逐条 Get + 一错全错”，
`rebuildCaseIndexUnlocked` 也遇到第一个坏 header 就整体失败。
修复：`verify.go` 列表跳过坏条目并在 `ErrNotExist` 时调用新增的 `invalidateCaseIndex()`；
`index.go` rebuild 改为条目级容错（`ErrNotExist` 目录错误容忍，其它 walkErr 仍致命）。
复核确认 casebook 的读/写/索引三处 size gate 均已由 `MaxCaseRecordBytes` + `ReadFileLimit` 覆盖（该包干净）。

### F6【P1 → 已修复】ledger Stats rebuild 一坏全坏 + legacy/分片双计
`rebuildStatsUnlocked` 之前对任何无法解码或未知状态的收据直接 return err，
而它位于 `Begin`/`Complete` 的写路径上 → **一个坏文件让所有远程作业永久失败**。
另外它先走分片目录再走 legacy 根目录，同一 operation id 会被计两次（Total 虚高）。
修复：条目级跳过并计数 `OperationStats.Unreadable`（刻意**不**进入 `Total == Σstate` 不变式）、
按 operation id 去重（分片优先）、并对分片文件校验 `basename == sha256(operation_id)`
（把 `read()` 已有的身份一致性约束铺到 rebuild，防止错位文件被计入）。
新增测试：坏收据不影响 Stats、也不阻止新作业。

### F7【P1 → 需决策】memscan / pointermap 没有任何 prune 或 delete API
grep 结果：两个包唯一的删除动作是迁移时清 legacy 文件，既无 Manager 级 Delete，也无 MCP 工具。
于是 1024 条 / 4 GiB 命中配额后，**唯一出路是人工删 `state/research/**` 文件**。
这不是可以“顺手写一个”的改动：自动删除研究会毁掉别人的证据，必须由使用方确认保留策略
（建议：新增 `memscan_prune`/`pointermap_prune` 显式工具 + 按数量/年龄归档到 `archive/` + 配额告警字段）。

### F8【P2 → 需复核后施工】packregistry 每次 Get 全量水合冷归档
`store.go:80 Get() = GetHot() + hydrateArchivedState()`，
即每次注册表读取都会遍历 `receipts/audit/packs` 三个归档目录并把全部内容物化成内存对象。
两点更正（避免误传）：

- 归档**不会**“自己撑爆水合上限”：写入侧 `registry*ArchiveShardMaxFiles` 与读取侧
  `registry*ArchiveMaxFiles = shard * 256` 是按构造一致的，水合上限不可能被自家写入超过；
- 真正的问题是 O(全归档)/次 的 CPU+heap 成本随 7x24 增长，以及 **shard 写满后没有 prune**，
  注册表最终拒绝新 receipt（诚实失败，但不可恢复）。

### F9【P2 → 仅记录】casebook 索引缓存的跨进程踩踏
`casebook.go` 在缓存写失败后于锁外 `os.Remove(indexPath)`，可能删掉另一进程刚发布的新索引；
`clearCaseIndexDirty(id)` 只按 id 删标记、不校验 `UpdatedUTC`/owner，削弱了
`committedCaseIndexDirtyUnlocked` 注释里声明的崩溃栅栏。需连带设计 marker owner 语义，本轮未改。

### F10【P0 风险 → 需决策】状态目录布局迁移与“旧版 EXE 共存”
本轮整改把多个 lock sidecar 与记录路径改了布局（`data/<shard>/<id>.json`、
`operations/{prepared,archive,locks}/<shard>/...`、`receipts/<kk>/<id>.json`）。
风险：`.tmp/promotion/ReverseResearch.prev.exe` 是**被支持的回滚目标**，
一旦新旧两版对同一 `state/` 运行：

- 两边使用**不同 sidecar** 保护同一 JSON → 互斥失效 → 丢更新；
- 新版迁移后会删除 legacy 文件 → 回滚旧版后记录“全部消失”。

需要显式决定其一：布局版本哨兵（启动即拒绝混用）、旧/新两把锁同时持有、
或迁移期保留 legacy 不删。属于发布/回滚策略决策，不宜由代码单方面定，本轮列为最高优先待决项。

---

## 八、复核后判定“不是 BUG”的条目（避免后人重复调查）

1. **x32 guard 收据读取无上限** —— 复核为**误报**：
   `modules/x32_guard.go:552` 已用 `recordio.ReadFileLimit(..., maxX32MutationReceiptBytes)`，
   `saveReceipt`/`writeCompletedReceiptArchiveBytes` 都有 body 上限 + `recordio.WriteFileShardQuota`。
2. **`ensure` 里 `cancel()` 会立刻杀掉刚建立的 MCP session** —— 复核为**误报**：
   go-sdk v1.7.0 `jsonrpc2.NewConnection` 默认 `PropagateCancellation=false`，
   连接 ctx 被 `notDone{}` 包裹，取消 connect ctx 不会关闭已建立的 session。
3. **`x32MutationGuard.Close()` 造成 use-after-close** —— 复核为**误报**：
   它只是按 `RuntimeID` 清理 durable session binding，幂等且可重建，不存在“一次性关闭后永久失效”。
4. **`rotatingLog` 被子进程继承句柄导致 rename 失败** —— 复核为**误报**：
   `cmd.Stdout` 传的是 `io.Writer` 而非 `*os.File`，os/exec 走 pipe + 拷贝 goroutine，
   归档文件本身不被子进程持有，rename 安全。
5. **`Console.lineWriter` 无界内存** —— 上一轮 P2-01 已正确修复（64 KiB 行上限 + 截断标记），
   未见回归；`Write` 返回 `originalLength` 是符合 io.Writer 契约的有意设计。
6. **GPU/显存** —— 仍然没有任何 CUDA/Vulkan/Direct3D/ML runtime 代码路径，
   本轮依旧**没有证据**支持 RR 自身存在 VRAM 泄漏；极限资源压力仍在 Go heap / Ghidra JVM /
   page cache / 磁盘。

---

## 九、验证记录

| 项目 | 命令 | 结果 |
| --- | --- | --- |
| 构建 | `go build ./...` | PASS |
| vet（全模块） | `go vet ./...` | **PASS，无输出**（上一轮记为“60s 超时，不能宣称 PASS”，本轮已跑完） |
| gofmt | `gofmt -l internal cmd tools` | PASS（无文件） |
| 全量测试（真实退出码） | `go test -count=1 ./...` | **REAL_EXIT=0，54 个包 ok，0 FAIL** |
| race（本轮改动包 + server 相关） | `go test -race -count=1 ./internal/{backend,modules,patchplan,remoteagent,recordio,job,casebook,memscan,pointermap}` | PASS（见 G3 的一次时序抖动） |
| 新增回归 | `remoteagent/ledger_recovery_test.go`(3) + `job/index_test.go`(1) + `memscan/state_limit_test.go`(1) | PASS |

说明：把 `go test` 与 `go build`/`go vet` 并发跑会争用构建缓存，曾让一次全量 `go test ./...`
在 20 分钟内只输出一行；终止并发构建后重跑即正常完成。这也是**上一轮把“管道退出码 0”当成
测试通过**之后需要避开的第二个坑：验证必须串行、并且直接读退出码。

### G3【P3 新发现 → 仅记录】硬编码 1 秒墙钟预算的回归测试在 -race 下不稳定
`internal/modules/x32_watch_test.go:296` 用 `Timeout: time.Second` 驱动
`TestObserveWriteCallerCancellationCleansOnlyTaskResources`。整包 -race 并发跑时该用例曾报
`cancelled watch returned cleanup error: context deadline exceeded`；单独 `-count=3` 与整包重跑均通过。
判定为测试预算问题而非代码回归（race 插桩 + 同包并发测试饿死 1s 预算）。
生产含义值得注意：**同样的短墙钟预算若出现在工具默认参数里，在高负载 7x24 进程里会产生假的
`timeout_or_cancel`**；建议把这类超时改成可注入/带余量，或在 CI 中对该用例降并发。


### G1【P1 → 已修复】Ghidra worker 断言测试在 Windows 上不可能通过
`internal/backend/ghidra_python_test.go:92` 用 `strings.Contains(text, filepath.Join(...))`
比较 Python 输出。MSYS2 CPython 打印 `C:/msys64/...`（正斜杠），
`filepath.Join` 在 Windows 产出反斜杠 → 断言恒假。也就是说
**“JPype 必须来自 UCRT64 系统 site、re_mcp_ghidra 必须来自 bundle”这条真实护栏长期处于从未被执行过的状态**。
修复：两侧统一 `filepath.ToSlash` 后比较，并把 `t.Fatalf` 的输出参数换成原始 `output`（避免打印已改小写的文本误导排障）。

### G2【P2 → 流程教训】管道吞掉退出码导致“测试通过”的假象
`go test ./... 2>&1 | tail -80` 的 `$?` 是 `tail` 的退出码，恒为 0，
因此上一轮报告里“race 验证全部 PASS”“test 通过”这类结论**可信度取决于是否直接读退出码**。
本轮改为把输出重定向到文件并单独回显 `$?`。同理，`go vet`/`staticcheck` 的 60s 超时窗口
不应被写成“PASS”，也不应被写成“无问题”。

---

## 十、建议后续施工顺序（按可无人值守运行排序）

1. **F10 状态布局共存策略**（回滚即数据“消失”，风险最高，需要一次产品决策）。
2. **E2 剩余 ctx 透传 + 双重 hash 合并**（先做无语义风险的第二次 hash 复用）。
3. **F7 memscan/pointermap prune API**（配额命中后当前只能手删文件）。
4. **B5 `WriteFileShardQuota` 可取消化**（P2-04 同类残留，横扫所有仍用 `Acquire` 的请求驱动路径）。
5. **F8 packregistry 读取侧成本**（把全量水合改成按需/分页，并补 prune）。
6. **F9 casebook 索引 marker owner 语义**。
7. **D2 CREATE_SUSPENDED 进程树接管**、**D3 日志权限 0o600**、**C2 关闭预算与运维脚本对齐**。
8. **A4 ledger Complete 失败的即时补偿**（A3 已提供 2h 兜底，优先级可降低）。

---

## 十一、本轮改动文件清单

```
internal/patchplan/patchplan.go      restoreSingleEdit 读回校验
internal/patchplan/operations.go     lockTarget + apply/rollback 事务插桩 + ErrPatchOutcomeUncertain + 诚实错误
internal/backend/backend.go          closeEpoch，关闭后不再可能装入新 generation
internal/backend/common_windows.go   attachKillOnCloseJob + closeOptional（不 Wait 的进程树接管原语）
                                     + reapStartedCommand（握手失败不留孤儿）+ 日志 0o600/ACL
internal/backend/radare2.go          Job Object 接管 + radare2.log 轮转 stderr + 错误合并
internal/backend/ghidra_python_test.go 路径分隔符归一，恢复护栏有效性
internal/modules/runtime.go          loadedGuard 消除数据竞争；shutdown 不再跳过调试器清理
internal/remoteagent/ledger.go       settleStaleRunning：崩溃遗留 running 的自愈
internal/remoteagent/ledger_stats.go 条目级容错 + operation 去重 + 分片身份校验
internal/remoteagent/status.go       OperationStats.Unreadable（不进 Total 不变式）
internal/remoteagent/limits.go       DefaultJobExecutionWindow / StaleRunningOperationAfter 等
internal/remoteagent/transport.go    作业统一执行上限，忽略解析错误不再制造“立即过期”
internal/remoteagent/httpwrite.go    采样诊断
internal/server/httpwrite.go         采样诊断
internal/server/server.go            身份/哈希重工具的 resource weight
internal/job/index.go                容错遍历 + 共享 walkJobRecords + ListRecent 降级 + markJobIndexDirty
internal/casebook/index.go           rebuild 条目级容错 + invalidateCaseIndex
internal/casebook/verify.go          List 降级返回可读条目
internal/memscan/manager.go          pre-flight 配额 + stateLimitWriter
internal/memscan/storage_quota.go    统计口径一致 + 负数防御
internal/pointermap/manager.go       pre-flight 配额 + persistedMapLimitWriter
internal/pointermap/storage_quota.go 同上
internal/compatibility/{store.go,types.go} 导入清单 size gate 前移
```

新增测试：`internal/remoteagent/ledger_recovery_test.go`、`internal/memscan/state_limit_test.go`、
`internal/job/index_test.go`（追加）。
