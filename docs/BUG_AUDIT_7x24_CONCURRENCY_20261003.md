# ReverseResearch 高并发 / 7x24 无人值守极限 BUG 静态审计报告

> 审计基线：c099cea
> 审计日期：2026-10-03
> 项目根目录：<repo-root>
> 本轮约束：不修改源码，只输出问题报告；每个 BUG 按问题类别归档，并横向排查同类实现。

---

## 一、审计结论

本轮按最坏生产条件审查：

- 多 MCP 客户端并发；
- 7x24 小时长期不重启；
- RAM 接近极限、磁盘 I/O 和 page cache 紧张；
- backend 启动失败、部分失败、客户端取消、服务重启同时发生；
- case、job、operation、audit、scan、pointer-map、log 持续累积；
- 所有 bounded、limit、max_bytes 都必须真正限制最昂贵的工作；
- 错误恢复、补偿写、shutdown、进程回收必须比正常路径更严格。

### 发现数量

| 严重度 | 数量 | 含义 |
| --- | ---: | --- |
| P0 / Critical | 1 | 可能出现数据损坏且系统误报“已经恢复” |
| P1 / High | 10 | 高并发或长期运行下可导致 OOM、磁盘耗尽、服务雪崩、deadline 失效、进程残留 |
| P2 / Medium | 10 | 明显的吞吐、取消、队列、I/O、内存放大和可扩展性问题 |
| P3 / Low | 3 | 主要影响可观测性和细粒度性能 |
| **合计** | **24** | 已做同类模式横向扫描 |

### 最高优先级问题族

1. 补偿事务与 rollback 的真实 postcondition。
2. backend session 生命周期与并发 teardown。
3. bounded 文件分析在 full hash 前先做 size gate。
4. 进程级统一资源 admission，而不是只靠单工具上限。
5. durable state retention、compaction、pagination、GC。
6. Remote Agent deadline 与 caller cancel 真正向下传播。

---

# 二、P0 / Critical

## BUG-P0-01：单编辑 patch 的失败恢复吞掉写盘错误，却明确声称“已恢复”

### 类别
补偿事务 / 回滚正确性 / 数据完整性

### 证据范围
- internal/patchplan/patchplan.go，约 335-379 行
- internal/patchplan/operations.go，约 661-702 行
- 对照：internal/patchplan/multi.go，约 298-341、444-499 行

单编辑 patch 最终验证失败后，会尝试把 expected 原始字节写回，但 WriteAt 和 Sync 的错误被直接忽略，然后返回“patch byte verification failed; original bytes were restored”。

rollback 的镜像路径也一样：恢复后的 hash 不正确时，尝试重新写 replacement，WriteAt / Sync 错误被忽略，却返回“rollback verification failed; replacement bytes were restored”。

### 风险
磁盘满、I/O error、文件系统异常、设备掉线、权限变化等情况下：

- 目标文件可能仍处于未知或部分修改状态；
- 系统却告诉上层恢复已经成功；
- 自动化可能继续下一步；
- 证据链和 patch receipt 与真实字节不一致。

### 同类扫描
同目录 composite patch 的 restoreOpenFileEdits 会把 restoreErr 通过 errors.Join 返回，做法正确。说明这是单编辑实现与 composite 实现不一致，不是有意设计。

### 修复边界
不能只改两个忽略错误的语句。必须横扫：

- patch single；
- patch composite；
- apply；
- rollback；
- copy patch；
- hook plan；
- afterEffect；
- verify failure compensation；
- 所有“restored / rolled_back”结论。

任何“恢复成功”都必须有可验证 postcondition；补偿失败应进入 uncertain/unknown，而不是继续声称恢复成功。

---

# 三、P1 / High

## BUG-P1-01：Lazy backend 启动忽略 caller context，并在互斥锁内执行最长 60 秒外部启动

### 类别
后端生命周期 / 锁粒度 / 取消传播 / 健康检查

### 证据
internal/backend/backend.go：

- Lazy.ensure 的 context 参数被丢弃；
- 获取 b.mu 后一直持有；
- 使用 context.Background 派生固定 60 秒 startup timeout；
- b.start 在持锁状态执行。

### 跨模块后果
healthz -> r.statuses -> modules.Statuses -> Lazy.Status，而 Status 也需要同一把 b.mu。

因此 backend 启动卡住时，healthz 也可能卡住。最需要 health 的时候 health 反而失去响应。

### 高并发后果
- 所有并发调用堆在 mutex 后；
- 已取消请求也不能阻止正在进行的 backend startup；
- 大量 waiter goroutine 可累积；
- watchdog 可能把 backend startup failure 错判成整个 RR hang。

### 同类范围
Ghidra、radare2、x32dbg 都通过 Lazy。

---

## BUG-P1-02：Ghidra/r2 共享 ClientSession，任一并发调用失败会关闭其他在途调用

### 类别
共享会话生命周期 / 故障隔离 / 并发 teardown

### 证据
Lazy.Call 得到共享 session 后离开锁并执行 CallTool。多个调用可同时使用同一 session。

任意一个调用出错后，invalidate 会：

- 清空共享 session；
- session.Close；
- cleanup。

没有 inflight 计数、generation、closing barrier 或 drain。

### 风险
A、B 两个并发 Ghidra/r2 调用中，只要 A 传输失败并 invalidate，B 的正常在途调用也可能被 A 连带关闭。

### 同类扫描
x32dbg 有 xdbgWorkflowMu，全局串行，因此主要不受这种共享 session 并发 teardown 影响。Ghidra/r2 没有等价隔离。

---

## BUG-P1-03：graceful shutdown 没有完整 drain backend inflight，超时后可关闭仍在使用的 session

### 类别
shutdown / drain / 生命周期竞态

### 证据
cmd/reverseresearch/main.go：

- HTTP Shutdown 最多等待 10 秒；
- runServe 返回时 defer runtime.Close；
- runtime.Close 返回错误未合并到 runServe。

internal/modules/runtime.go：

- x32dbg Close 有 workflow mutex；
- Ghidra/r2 没有 inflight barrier；
- 直接 backend.Close。

### 风险
一个 Ghidra/r2 调用超过 shutdown 10 秒时：

1. HTTP Shutdown 超时；
2. runServe 返回；
3. defer runtime.Close 关闭 backend session；
4. 在途调用被强制中断；
5. cleanup 错误还可能被吞掉。

### 同类范围
tunnel.Stop、backend invalidate、process cleanup 也存在 cleanup error 被忽略，见 P3-01。

---

## BUG-P1-04：没有进程级全局 workload admission，单工具上限在并发下形成乘法风险

### 类别
资源治理 / OOM / I/O 饱和

### 扫描结果
生产代码未发现统一：

- semaphore；
- MaxConcurrent；
- weighted resource limiter；
- worker pool；
- process-wide RAM/I/O budget。

但单次工具上限很高：

- memscan：最多 1 GiB，1,000,000 candidates；
- pointermap：最多 1 GiB 每 depth，最多 8 depth、500,000 nodes、100,000 chains；
- malware：最多 512 MiB；
- DFIR：最多 512 MiB；
- SARIF/SBOM/CTI/cloud inventory/attack graph：最多 256 MiB；
- source audit：总读取最多 2 GiB。

### 风险
多个合法重任务同时执行时，会叠加：

- Go heap；
- JSON 临时对象；
- page cache；
- Ghidra Java RAM；
- debugger process RAM；
- 磁盘吞吐。

局部 bounded 不等于全进程 bounded。

---

## BUG-P1-05：大量 bounded 工具在检查 max_bytes 之前先完整 SHA-256 文件

### 类别
边界检查顺序 / I/O DoS / bounded 语义失效

### 根因
internal/targetidentity/identity.go 的 Inspect 会：

- 打开文件；
- sha256.New；
- io.Copy 直到 EOF；
- 没有 context；
- 没有 max size。

### 已确认同类范围
以下均存在 full Inspect 在 size reject 之前，且很多结束后还会再次 full Inspect：

- internal/malware/triage.go
- internal/dfir/dfir.go
- internal/sourceaudit/sarif.go
- internal/sourceaudit/sbom.go
- internal/cloudinventory/inventory.go
- internal/cti/cti.go
- internal/core/p2_security.go 的 attack graph
- internal/core/p1_interchange.go 的 protocol sample
- internal/core/p1_research.go 的 protocol sample
- internal/remoteagent/readcap.go 的 readStableExcerpt
- iOS / firmware / DIE 的 currentness 路径

### 典型反例
remote file.read_excerpt 默认只读几 KiB，最大 64 KiB。

但 readStableExcerpt：

1. 先完整 Inspect/hash；
2. 再读几 KiB；
3. 再完整 Inspect/hash。

对 100 GB 文件，一个几 KiB bounded read 可造成约 200 GB 全盘读取。

### 风险
- max_bytes 只限制后半段，不限制最昂贵 I/O；
- 超大文件可合法触发长时间磁盘满载；
- 多并发时形成 I/O DoS；
- Remote Agent deadline/cancel 也无法中断 Inspect。

---

## BUG-P1-06：memscan / pointermap 可持久化巨大 JSON，并在 refine/save 时制造多份内存副本

### 类别
内存放大 / 大对象持久化 / GC 压力

### memscan
允许：

- 1,000,000 Candidates；
- 1 GiB scan bytes。

每个 Candidate 保存 address、hex、value、完整 RegionIdentity。

Scan 再保存全量 Candidates 和全量 History。

Refine 时可能同时存在：

- JSON 解码后的旧 candidates；
- 新 result slice；
- json.MarshalIndent 输出字节；
- recordio 临时文件缓冲。

### pointermap
允许：

- 500,000 nodes；
- 100,000 chains；
- 8 depth；
- 1 GiB / depth。

Map 同样整体 JSON 持久化、整体读取和序列化。

### 风险
单 scan/map 即可能产生巨大 state；并发时 heap 和 GC 呈乘法放大。

---

## BUG-P1-07：多套 durable state 无 retention/GC，且 List/Stats 随历史总量线性退化

### 类别
7x24 状态膨胀 / 磁盘增长 / O(N) 管理操作

### 同类范围

#### Remote Agent OperationLedger
- 每 operation 永久一个 JSON；
- Stats 每次 ReadDir；
- 每个文件 ReadFile + Unmarshal；
- 无 retention/prune。

#### Job Store
- job 永久保留；
- List 全目录读取、解析、排序；
- operation 维度另有 receipt。

#### x32 mutation guard
- 每 mutation operation 一个永久 JSON；
- 未发现统一回收。

#### packregistry
RegistryState 持续 append：

- Receipts；
- Audit。

每次 mutation 都读整文件、append、sort、计算 revision、MarshalIndent、重写整文件。

#### collaboration
workspace.History 持续 append；每次 mutation 同样是整文件 read-modify-write。

#### memscan / pointermap
scan/map 和 history 长期保留，未发现统一 GC。

### 风险
运行时间越长：

- state 文件数越来越多；
- Stats/List 越来越慢；
- 单一 registry/workspace JSON 越来越大；
- antivirus/index/backup 成本不断上升；
- 恢复和管理操作最终失控。

---

## BUG-P1-08：Remote Agent 的 deadline_utc 只在接单瞬间检查，没有成为真实执行 deadline

### 类别
deadline 语义 / 取消传播 / 远程执行合同

### 证据
internal/remoteagent/contract.go 的 ValidateJob 只检查当前是否已经超过 deadline。

internal/remoteagent/transport.go 后续直接调用 handler(r.Context(), job)，没有根据 job.DeadlineUTC 创建执行 deadline。

### 风险
只剩 1 秒 deadline 的任务仍可被接收，然后继续运行远超过 1 秒。

### 同类扫描
以下 builtin handler 直接忽略 context：

- artifact.inspect
- artifact.hash
- artifact.metadata
- tool.inventory
- environment.fingerprint
- file.read_excerpt
- case.evidence.capture

其中多个还会调用无 context 的全文件 targetidentity.Inspect。

---

## BUG-P1-09：backend cleanup 只 Kill 单进程，不保证清理 Windows 子进程树，Kill/Wait 错误还被吞

### 类别
进程树生命周期 / orphan process / 句柄泄漏

### 证据
internal/backend/common_windows.go 的 processCleanup：

- cmd.Process.Kill；
- cmd.Wait；
- 两者错误均忽略；
- 没有 Windows Job Object / process tree ownership。

### 风险
Ghidra Python -> Java/worker 等子进程可能在父进程被 Kill 后继续存活：

- 占 RAM；
- 占端口；
- 占文件；
- 保持数据库；
- 下次启动冲突。

### 同类扫描
Ghidra adopted daemon 明确设计为保留，不属于 leak。本 BUG 只针对 RR 自己 owned 的 process tree。

---

## BUG-P1-10：backend 日志永久 O_APPEND，无 rotation/retention，长期运行可填满磁盘

### 类别
日志生命周期 / 磁盘耗尽

### 证据
- internal/backend/common_windows.go 的 backend log 以 O_APPEND 打开；
- internal/backend/ghidra.go 的 ghidra.log 以 O_APPEND 打开；
- 全仓未找到 rotation、MaxSize、retention、truncate 机制。

### 风险
磁盘满后会进一步影响：

- state 写入；
- receipt；
- Ghidra project；
- auth/config；
- patch rollback；
- 原子 temp/rename。

日志问题最终可能演变为状态一致性问题。

---

# 四、P2 / Medium

## BUG-P2-01：Tunnel lineWriter 对永不换行的输入使用无限 bytes.Buffer

### 类别
无界内存 buffer / 日志解析

internal/consolelog/console.go 的 lineWriter：

- 先把 payload 写入 buffer；
- ReadString 查找换行；
- 没换行时把整段读出再写回；
- 没有 max line length。

异常 tunnel/logger 持续输出无换行长串时，heap 会无限增长。

同仓其他 boundedBuffer 已有长度限制，TunnelWriter 没有。

---

## BUG-P2-02：patchplan 一个全局 Manager.mu 串行所有文件、所有 plan 的大文件 I/O

### 类别
过粗全局锁 / 吞吐瓶颈

Plan/Get/DryRun/Verify 以及 apply/rollback 使用同一 Manager.mu。

Plan 持锁期间还会：

- targetidentity.Inspect 全文件 hash；
- computePatchedHashes；
- file lock；
- state save。

两个完全无关的目标文件也不能并发操作。

patchplan 已经有 per-plan/per-operation recordio lock，因此全局 mutex 粒度明显过粗。

---

## BUG-P2-03：x32dbg workflow mutex 等待不可取消，也没有最大排队深度

### 类别
不可取消队列 / goroutine 堆积

x32dbg Call 在进入实际 ctx-aware 调用之前先 Lock xdbgWorkflowMu。

ObserveWrite 也持有这把锁覆盖整个 watch 生命周期。

单 debugger 串行本身合理，但等待者：

- 无法在排队时响应 ctx.Done；
- 没有 queue bound；
- 高并发时已取消请求仍可堆在 mutex 后面。

---

## BUG-P2-04：recordio.Acquire 每 5ms 轮询文件锁，高争用下形成 thundering herd，且不可按 caller context 取消

### 类别
锁争用 / 轮询风暴 / 取消

recordio.Acquire：

- tryLock；
- 失败 Sleep 5ms；
- 常见 wait 2 秒或 10 秒；
- 不接 context。

调用范围包括：

casebook、collaboration、compatibility、hookplan、job、knowledge、memscan、x32 guard、packregistry、patchplan、pointermap、processcontrol、remoteagent、auth、toolindex。

很多 waiter 同时争一把锁时，每秒会产生大量无意义唤醒。

说明：空 lock sidecar 不属于 stale lock BUG，OS handle 释放锁这一点设计是正确的。

---

## BUG-P2-05：structuredResult 对大结果做多份完整复制，形成明显 heap/GC 放大

### 类别
结果序列化 / 内存放大

internal/server/host_tools.go 的 structuredResult：

1. 原始 Go value；
2. json.Marshal 得到 []byte；
3. json.Unmarshal 成 interface tree；
4. string(body) 再复制文本；
5. 同时返回 TextContent 与 StructuredContent；
6. MCP/HTTP 后续还会再次编码。

几乎所有 host/core/web/android tool 都使用该 helper。

高并发大结果下，瞬时 heap 可远大于业务对象本身。

Remote Agent 结果还会 Base64，再增加约 33% 大小。

---

## BUG-P2-06：Remote Agent HTTP 层缺少统一 handler 并发上限、执行兜底时限和 generic 结果体上限

### 类别
HTTP 服务资源治理

已有保护：

- mTLS；
- 1 MiB request body；
- ReadHeaderTimeout。

缺少：

- handler concurrency limiter；
- per-capability admission；
- 统一 execution timeout；
- generic CapabilityResult.Body 最大值；
- 统一 bulk response 策略。

当前 builtin 多数有自己的边界，但 CapabilityHandler 是扩展接口，未来新增 handler 很容易绕过限制。

---

## BUG-P2-07：Case.List 的 limit 只限制返回数量，不限制全量 I/O/解析/排序

### 类别
伪分页 / 全表扫描

internal/casebook/verify.go 的 List(limit)：

1. ReadDir 全部 case；
2. 全部 ReadFile；
3. 全部 Unmarshal；
4. 全部 validate；
5. 全部 sort；
6. 最后才截 limit。

目录有 100,000 个 case 时，即使 limit=20，也读取 100,000 个文件。

remoteagent Stats、job List 的全表扫描归在 P1-07。

---

## BUG-P2-08：RefreshRemoteAgentStatus 丢弃上层请求取消，固定从 context.Background 派生 1~30 秒请求

### 类别
取消传播 / 无效后台工作

internal/core/p4_agent.go 的 RefreshRemoteAgentStatus 不接 caller context，使用 context.Background 创建 timeout。

MCP client 已取消后，TLS/HTTP status 请求仍可继续最多 30 秒。

---

## BUG-P2-09：waitTCP 用 cmd.ProcessState 判断早退，但 startup 阶段没有 Wait，子进程提前退出时通常仍等满 deadline

### 类别
启动失败检测 / 恢复延迟

internal/backend/common_windows.go 的 waitTCP：

- Dial port；
- 看 cmd.ProcessState；
- Sleep 150ms。

但 ProcessState 通常要 Wait 后才会设置；startup waiting 期间没有并发 Wait。

backend 秒退时：

- Ghidra 可能仍等近 30 秒；
- xdbg 可能等近 12 秒；
- Lazy.mu 同时被占；
- health 还会被 P1-01 连带阻塞。

---

## BUG-P2-10：持久化 string/array 主要依赖单请求 8 MiB body cap，缺少 durable object 的累计业务上限

### 类别
持久化状态放大 / 输入语义限制

很多 schema 的 string、comments、description、history 等没有严格业务级 maxLength/maxItems。

8 MiB MCP body 只能限制一次请求，不能限制：

- 同一 case 多次 append；
- collaboration history；
- audit；
- evidence；
- comments；
- CLI 绕过 HTTP body cap。

这会继续放大 P1-07 的整文件 read-modify-write。

---

# 五、P3 / Low

## BUG-P3-01：关键 cleanup 错误大量被吞，无人值守时清理失败缺少证据

### 类别
错误可观测性

代表位置：

- cmd/reverseresearch/main.go：tunnel.Stop 错误忽略；
- runServe：defer runtime.Close 返回值忽略；
- internal/backend/backend.go invalidate：session.Close / cleanup 错误忽略；
- internal/backend/common_windows.go：Kill / Wait 错误忽略；
- Ghidra/xdbg 多个 startup failure 分支 cleanup error 忽略。

不是所有 Close error 都必须升级为业务错误，但 process/session/shutdown 这类 correctness-critical cleanup 不能统一丢弃。

---

## BUG-P3-02：全局 consoleMu 串行 stdout/stderr/tunnel 输出，异常大日志行会阻塞所有状态日志

### 类别
日志锁粒度 / 可观测性延迟

internal/consolelog/console.go：

- 所有 console write 共用 global consoleMu；
- lineWriter 还先持有自己的 w.mu，再进入 consoleMu。

正常流量问题不大，但和 P2-01 巨大无换行 buffer 组合时，READY、ERROR、shutdown 等日志也会被阻塞。

---

## BUG-P3-03：HTTP response encode/write 错误普遍忽略，客户端断连与服务端输出异常缺少统一指标

### 类别
输出错误可观测性

代表：

- internal/remoteagent/transport.go
- internal/remoteagent/status.go
- internal/server/server.go

存在忽略 json Encoder / WriteString 返回错误的情况。

客户端正常断开可不升级为业务失败，但持续 broken pipe、encode failure 应有计数或诊断指标。

---

# 六、跨类别组合风险

## 组合 A：超大文件 + bounded 工具 + 高并发
P1-05 + P1-04：

- 单个请求声称只分析 64/256 MiB；
- 实际先完整 hash 数十/数百 GB；
- 多个请求同时执行；
- 又没有全局 admission。

结果是磁盘和 page cache 被合法调用直接打满。

## 组合 B：backend 秒退 + health watchdog
P1-01 + P2-09：

- backend 秒退；
- waitTCP 不能快速知道进程已退出；
- Lazy.mu 长时间占用；
- healthz 又需要该 mutex；
- watchdog 看到的是整个 RR health timeout。

容易触发错误 restart loop。

## 组合 C：日志填满磁盘 + patch compensation
P1-10 + P0-01：

- backend log 长期占满磁盘；
- patch verify 失败；
- 自动恢复写也失败；
- 单编辑路径吞掉恢复错误；
- 上层却收到 original bytes were restored。

这是本轮最危险的组合。

## 组合 D：巨大 scan state + structuredResult
P1-06 + P2-05：

- load/refine 已持有巨大 candidates；
- save 又生成巨大 JSON；
- result helper 继续 marshal/unmarshal/string；
- 多并发进一步放大 heap 和 GC。

## 组合 E：Remote Agent deadline + 全文件 hash
P1-08 + P1-05：

- deadline 只在接单时看一次；
- handler 忽略 ctx；
- targetidentity.Inspect 不支持 ctx；
- 大文件 hash 可以长期越过 deadline。

---

# 七、已检查但不判定为 BUG 的点

## 1. Ghidra adopted daemon 不随 Runtime.Close 被杀
这是显式设计，用于保留打开数据库和 daemon currentness，不当作 leak。

## 2. recordio lock sidecar 文件不删除
源码明确依赖 OS handle lock；进程退出自动释放锁。空 sidecar 不等于 stale lock，不当作 BUG。

## 3. x32dbg workflow 串行
单 debugger session 串行合理。问题是等待不可取消和无 queue bound，已经单列 P2-03。

## 4. GPU / 显存
当前 Go 生产源码未发现 CUDA、Direct3D compute、Vulkan compute、ML runtime、GPU allocator 或显存 cache/session ownership。

因此本轮没有证据支持 RR 自身存在直接 VRAM leak。

当前极限资源风险主要集中在：

- Go heap；
- Ghidra Java / debugger process RAM；
- page cache；
- disk I/O；
- file/process handles；
- state/log disk usage。

以后若引入本地 LLM、视觉模型、OCR/GPU decompiler，应另做 VRAM admission/eviction 审计。

---

# 八、审计覆盖与工具结果

## 源码分区
整根目录 source audit 会被 runtime/state 大体积第三方和运行数据先撞扫描上限，所以改为源码职责分区，避免 runtime 扫不完冒充源码扫完。

实际审计：

- internal：271 files，约 1.58 MB，257 Go；
- cmd：30 files，约 278 KB，29 Go；
- tools：9 files，约 86 KB；
- patches：3 Python files，约 107 KB。

source audit 的 secret candidates 位于测试 fixture/literal，本轮未判定为生产 secret 泄漏。

## 全仓模式扫描
横扫过：

- goroutine；
- Mutex/RWMutex；
- channel；
- timer/ticker；
- context.Background / WithTimeout / WithDeadline；
- os.ReadFile / io.ReadAll / ReadDir / WalkDir；
- O_APPEND；
- process Start/Kill/Wait；
- ignored cleanup errors；
- durable append arrays；
- whole JSON Marshal/Unmarshal；
- targetidentity.Inspect；
- recordio.Acquire；
- HTTP client/server；
- max_bytes / candidates / nodes / chains；
- Close / shutdown 生命周期。

## go vet
执行 go vet ./...，60 秒执行窗口内超时，stdout/stderr 均为空。

**不能宣称 PASS，也没有 diagnostic 可加入报告。**

## staticcheck
执行 staticcheck ./...，同样在 60 秒执行窗口内超时，stdout/stderr 均为空。

**不能宣称 PASS。**

## race 验证
执行：

    go test -race ./internal/backend ./internal/recordio ./internal/modules ./internal/patchplan ./internal/remoteagent

全部 PASS。

---

# 九、最终修复闭环（2026-10-03）

> 本节记录“直接修”之后的最终状态。上面的原始审计证据保留不改，便于以后复盘问题为什么存在；本节是当前源码的闭环结论。
>
> 第二轮同类模式复查与补修过程见：`BUG_AUDIT_ROUND2_FIX_20261003.md`。

## 9.1 24 个原始 BUG 逐项核销

| BUG | 最终状态 | 闭环要点 |
| --- | --- | --- |
| P0-01 | ✅ CLOSED | patch apply / rollback / compensation 不再只相信 WriteAt/Sync；恢复后重新读取验证 postcondition，恢复失败进入 uncertain，不再虚报 restored。 |
| P1-01 | ✅ CLOSED | Lazy backend 启动继承 caller context；startup 生命周期与锁状态拆开，取消请求不会被固定 Background startup 吞掉。 |
| P1-02 | ✅ CLOSED | backend session 引入 generation / inflight / closing 生命周期；单次失败不再直接关闭其他在途共享调用。 |
| P1-03 | ✅ CLOSED | shutdown 使用 CloseContext/drain；backend/x32/runtime 清理错误参与返回值，超时/未 drain 会显式暴露。 |
| P1-04 | ✅ CLOSED | 增加进程级重任务 admission / bounded concurrency；Remote Agent handler 也有统一并发闸门，避免合法重任务乘法叠加。 |
| P1-05 | ✅ CLOSED | target identity 增加 context/bounded 路径；大文件 bounded 工具不再先做无限 full hash。Pack build/verify 也改为流式 SHA-256。 |
| P1-06 | ✅ CLOSED | memscan / pointermap 增加单任务 state budget、decode 前文件硬上限、持久化 quota；达到预算返回 partial，而不是继续撑大 heap。 |
| P1-07 | ✅ CLOSED | Remote operation、Job/operation、x32 receipt、Collaboration history、Pack archive、memscan/pointermap 全部改成 recent/hot + shard/quota/backpressure；不再依赖无限增长。 |
| P1-08 | ✅ CLOSED | Remote Agent 将 deadline_utc 转成真实执行 context deadline；builtin/read/currentness 路径传播 caller context。 |
| P1-09 | ✅ CLOSED | Windows backend 子进程由 Job Object 管理，kill-on-close 覆盖进程树；Kill/Wait/Close 关键错误不再统一吞掉。 |
| P1-10 | ✅ CLOSED | backend log 增加 rotation/size retention，长期运行不再无限 O_APPEND。 |
| P2-01 | ✅ CLOSED | Tunnel lineWriter 增加最大行缓存，超长无换行输出不会无限增长 bytes.Buffer。 |
| P2-02 | ✅ CLOSED | patchplan 去掉全局 Manager.mu 大锁，按 plan / operation / target 分层锁；不同目标可并发，同一目标保持互斥。 |
| P2-03 | ✅ CLOSED | x32 workflow 改为 context-aware admission，等待可取消并受队列/并发边界控制。 |
| P2-04 | ✅ CLOSED | recordio 增加 AcquireContext 与退避等待；高争用不再固定 5ms 轮询，caller cancel 可终止等待。 |
| P2-05 | ✅ CLOSED | structuredResult 改为单份结构化 JSON/RawMessage 路径，避免 marshal → unmarshal → string 的重复大对象复制。 |
| P2-06 | ✅ CLOSED | Remote Agent HTTP 增加 handler concurrency gate、执行时限、request/result body 上限及统一输出错误诊断。 |
| P2-07 | ✅ CLOSED | Case.List 改为 bounded recent index（256）；普通 limit 查询不再先全目录 ReadFile/Unmarshal/sort。 |
| P2-08 | ✅ CLOSED | RefreshRemoteAgentStatus 使用 caller context；MCP 请求取消后不会继续固定 Background 请求。 |
| P2-09 | ✅ CLOSED | backend startup 有独立进程退出观察；子进程秒退可提前结束 waitTCP，不再默认等满端口 deadline。 |
| P2-10 | ✅ CLOSED | Case、Collaboration、Job、Pack、Remote、Compatibility、Engagement、Hook/Patch、Process lease、ToolIndex/Auth 等 durable object 都增加累计大小/文件数量/读取上限。 |
| P3-01 | ✅ CLOSED | correctness-critical cleanup（runtime/backend/session/process/log/record lock/temp/receipt）错误均进入 errors.Join 或明确诊断；仅无错误返回的 release/defer 保持原语义。 |
| P3-02 | ✅ CLOSED | console 不再使用一把 global consoleMu 串行 stdout/stderr；两条输出流分别串行，超长 line 又有 P2-01 的硬边界。 |
| P3-03 | ✅ CLOSED | Server / Remote Agent HTTP JSON/text 输出统一 helper，encode/write/broken-pipe 会留下诊断，不再静默。 |

## 9.2 第二轮“同类代码举一反三”补修

除原始 24 项外，又补了同类别的长期运行缺口：

- Remote OperationLedger stale-running 自动转 `uncertain`，防止 crash 后 operation_id 永久占用。
- Remote receipt 总量硬上限；单 receipt、stats cache、registration/status、TLS PEM 全部 decode 前限流。
- Job recent cache 固定上限；主记录与 operation 幂等副本都走 hash shard quota，并处理双写半提交补偿。
- x32 completed receipt 进入 hash 分片冷归档；effect 执行前预留 receipt 容量；超大 MCP 返回只持久化 digest 摘要。
- Collaboration cold history、Pack receipts/audit/packs 都改为 hash 分片，并使写入 quota 与 hydration 上限一致。
- memscan / pointermap 增加显式删除能力，用于 quota 满时安全释放状态；因此 MCP 工具目录由修复前 238 增至 **240**（新增 `memory_scan_delete`、`pointer_map_delete`）。
- Compatibility、Engagement、Hook/Patch 状态、Process lease、ToolIndex、Auth token 等小型持久化记录统一改成 bounded read + bounded write。
- Pack manifest 构建和校验统一使用流式 SHA-256，且要求 regular file，避免大 pack 文件整块进入 Go heap。
- 生产代码中显式忽略 `session.Close / runtime.Close / tunnel.Stop / Process.Kill / Wait` 等关键 cleanup 的模式已系统性复扫并收口。

## 9.3 最终验证结果

### 功能/回归
按包分组执行并通过：

- `internal/backend`
- `internal/modules`
- `internal/patchplan`
- `internal/recordio`
- `internal/targetidentity`
- `internal/malware`
- `internal/dfir`
- `internal/sourceaudit`
- `internal/cloudinventory`
- `internal/cti`
- `internal/detection`
- `internal/memscan`
- `internal/pointermap`
- `internal/casebook`
- `internal/collaboration`
- `internal/job`
- `internal/packregistry`
- `internal/remoteagent`
- `internal/consolelog`
- `internal/server`
- `internal/core`（P1-P4 + 其余测试逐项运行）
- `internal/compatibility`
- `internal/engagement`
- `internal/hookplan`
- `internal/processcontrol`
- `internal/toolindex`

Server 统一工具目录测试最终通过，当前工具数：**240**。

### 静态检查
最终针对全部本轮改动高风险包分组执行：

    go vet <changed/high-risk packages>
    staticcheck <changed/high-risk packages>

均 **PASS，0 diagnostic**。

### Race
最终/分阶段 race 覆盖并通过：

- backend / modules / patchplan / recordio
- remoteagent / job / collaboration
- casebook / packregistry
- memscan / pointermap
- server / core P3-P4
- compatibility / engagement / toolindex / hookplan / processcontrol

均 **PASS，无 data race**。

### Build / diff
执行：

    git diff --check
    go build ./cmd/reverseresearch

均通过。Git 仅输出 Windows 工作树 LF→CRLF 提示，不是 whitespace error。

### 关于 `go test ./...`
单条全仓命令在当前远程 runner 的 60 秒窗口内多次无法完成，因此最终没有把“单命令 `go test ./...` PASS”写成结论。

为了避免把 runner 超时误报为代码失败，最终改为：

1. 按包分组跑全部本轮修改相关测试；
2. `internal/core` 编译 test binary 后逐项执行慢测试；
3. 高风险包再跑 `-race`；
4. 分组执行 vet/staticcheck；
5. 最后主程序 build。

因此本报告的 PASS 结论只覆盖上述实际执行并成功的验证，不虚构未完成的单命令全仓结果。

---

# 十、最终结论

本轮原始 24 项问题以及第二轮同类模式复查发现的生产级缺口，已经完成代码修复、回归、静态检查、race 与主程序 build 闭环。

当前没有已知 RED；没有为了“报告好看”保留未验证的 P0/P1 项。

后续若继续扩展 GPU/本地模型、大规模分布式 Agent 或新的 destructive capability，需要重新做对应资源 admission / VRAM / exactly-once 审计，不能直接沿用本轮结论。

这只说明现有测试覆盖范围内没有 Go data race。本文多数问题属于业务生命周期竞态、资源放大、deadline 语义、持久化退化，race detector 不一定能发现。

---

# 九、后续修复必须按 Family 横扫，禁止只打单点补丁

## Family 1：补偿事务
范围：

- patch single/composite；
- apply/rollback；
- copy patch；
- hookplan；
- afterEffect；
- receipt terminal state。

验收原则：任何 restored/rolled_back 都必须有可验证 postcondition。

## Family 2：backend lifecycle
范围：

- Lazy.ensure；
- Call；
- invalidate；
- Close；
- Ghidra；
- radare2；
- x32dbg；
- health/status；
- shutdown。

验收原则：

- caller cancel 不留下无意义 startup；
- Status 不被外部启动长时间锁死；
- 一个 request failure 不无条件杀其他 inflight；
- shutdown 有明确 drain/uncertain 规则。

## Family 3：bounded I/O
范围：所有 targetidentity.Inspect + max_bytes 组合。

验收原则：**廉价 size gate 必须在 full hash/read 前。**

同时统一 full identity、bounded identity、currentness、same-handle validation primitive。

## Family 4：全局资源 admission
范围：

- memscan；
- pointermap；
- source audit；
- malware；
- DFIR；
- SARIF/SBOM；
- CTI/cloud；
- attack graph；
- backend heavy call。

验收原则：不仅单请求 bounded，整个 RR process 也必须 bounded。

## Family 5：durable state lifecycle
范围：

- cases；
- jobs；
- operation receipts；
- remote agent ledger；
- x32 guard；
- scans；
- pointer maps；
- pack registry；
- collaboration；
- evidence/logs。

每种 record 都必须定义：

- 最大数量；
- 最大年龄；
- pagination；
- archive；
- compaction；
- GC owner；
- crash-safe GC；
- quota。

## Family 6：context/deadline
范围：

- MCP/HTTP request；
- Remote Agent deadline_utc；
- backend startup；
- file hash；
- outbound status；
- x32 queue；
- record lock。

原则：取消尽可能向下传播；只有明确的补偿 effect cleanup 才允许短暂 detached context。

## Family 7：process ownership
范围：

- Ghidra；
- x32dbg；
- future external tools；
- daemon adoption；
- startup failure；
- shutdown。

必须明确 owned/adopted、父子树、cleanup owner、成功判定和 orphan 回收。

## Family 8：输出与日志
范围：

- TunnelWriter；
- backend logs；
- HTTP response；
- structuredResult；
- Remote Agent Base64 result。

原则：

- line bounded；
- log bounded；
- result bounded；
- bulk data 不在内存重复多份；
- 断连/写失败可观察。

---

# 十、建议施工优先级

## 第一批：先解决 correctness 和雪崩入口
1. P0-01 patch compensation 真实 postcondition。
2. P1-01 / P1-02 / P1-03 backend lifecycle。
3. P1-05 bounded I/O 顺序。
4. P1-04 process-wide resource admission。
5. P1-08 Remote Agent deadline。
6. P1-10 log rotation。

## 第二批：7x24 长期稳定性
7. P1-06 scan/map storage。
8. P1-07 durable retention/GC/index。
9. P1-09 Windows process tree ownership。
10. P2-02 / P2-03 / P2-04 锁与队列。

## 第三批：内存效率和可观测性
11. P2-05 structuredResult。
12. P2-01 line buffer。
13. P2-06 Remote Agent transport resource boundary。
14. P2-07 真分页。
15. P2-08 / P2-09 cancel 与 startup fast fail。
16. P3 cleanup/output telemetry。

---

# 十一、最终判断

ReverseResearch 目前已有不少正确基础：

- stable sidecar lock；
- recordio 原子替换思路；
- 大量工具有 per-request bounds；
- x32 mutation 有 lease / operation receipt / uncertain 语义；
- Ghidra daemon bearer、PID/currentness 校验较完善；
- focused race tests 当前通过。

但按“高并发 + 7x24 + 极限资源 + 无人值守”标准，当前最大结构性短板不是普通 data race，而是：

1. **资源上限是局部的，不是全局的；**
2. **bounded I/O 存在 full-hash 前置漏洞；**
3. **durable state 没有完整生命周期；**
4. **backend session 没有 inflight 隔离；**
5. **deadline/cancel 没有完整传播；**
6. **错误恢复路径仍存在会误报成功的 P0 数据完整性 BUG。**

后续修复必须按本报告 Family 级别施工并做同类回归，不能只对编号对应的单个函数打补丁。
