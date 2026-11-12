# Seep-Reverse-Lab

Seep-Reverse-Lab is a local-first Windows + Android + Web automated reverse-engineering workbench. `ReverseResearch.exe` remains its backward-compatible local execution core/CLI name; native binaries, games, CTF/Pwn, web/network, mobile, firmware and related research still share the same Core.

ReverseResearch does **not** require its MCP server for normal local work. Core capabilities and local tool adapters can be invoked directly from the CLI. MCP is an optional adapter for ChatGPT, team sharing, and other MCP clients. The platform scope is intentionally broader than legacy-game modding; see `docs/platform-scope.md` and `docs/seep-reverse-lab.md`. The local-source P3 productization baseline (report/dashboard, collaboration/RBAC, bounded mTLS Remote Agent, and signed pack registry) is documented in `docs/P3-productization.md`; that document does not claim the online RR/RT service has already been promoted. P4 local-source increments are tracked in `docs/P4-productization.md`.

## Documentation index

原 JavaScript 工具已加入 Webpack/Rspack/esbuild 模块工厂、内部依赖、入口与异步 chunk 的静态候选恢复；模块原始源码的 UTF-8 字节范围与 SHA、独立命名的 AST 呈现哈希沿同一 AST/facts/比较/应用图提供。`app javascript` / `app_javascript_inspect` 分页完整事实，`app analyze` / `app_javascript_application` 返回独立于文件路径的虚拟模块关系；动态、spread、重复键保持不确定，未执行目标或增加工具副本。

All files under `docs/` are maintained in Simplified Chinese; file names stay in English because code and knowledge manifests reference those exact paths.

| Document | What it owns |
| --- | --- |
| `docs/architecture.md` | Core ownership boundaries: target/process identity, backends, memscan/pointermap, hook/patch guards, router/tool index, case records, MCP adapter, production runtime. |
| `docs/platform-scope.md` | Product principles, capability domains, current specialist Skills and Domain Packs, tool acquisition boundaries, Android/Web runtime limits. |
| `docs/seep-reverse-lab.md` | The master workbench shape: three reverse-engineering lanes, single-owner Skill + MCP contract, G1-G4 workflow, non-goals. |
| `docs/p0-security-research-contracts.md` | P0 contract reference: ownership matrix, Engagement/Scope, Generic Job states, Case v2 chain, detection validation, ToolIndex/Recipe v2, Canonical Report. |
| `docs/P3-productization.md` | Historical local-source P3 baseline (explicit non-claims included). |
| `docs/P4-productization.md` | Current local-source P4 increments with verification evidence. |
| `docs/chatgpt-tunnel.md` | Operations: `serve --tunnel`, Secure MCP Tunnel setup, ChatGPT app catalog, Windows ACL hardening and Scheduled-Task autostart with graceful restart. |
| `docs/upstream-snapshots.md` | Pinned upstream revisions for the bundled runtimes and the retained smoke fixture digest. |

## Runtime bundle

The third-party runtime tools (Ghidra, Temurin JDK, radare2, x32dbg, JADX, AAPT2/R8, DiE, WABT) are distributed as a Release asset rather than committed to Git:

- Release: https://github.com/zpbsu27-bit/ReverseResearch/releases/tag/v0.1.0
- Asset: `ReverseResearch-runtime-20261113.zip`
- Extract at the repository root so `runtime/` is populated; see `RUNTIME-README.md` in the release.
- `state/` and `runtime/network-lab/` are never published.

## Local CLI

Windows 一键入口：

- 双击仓库根目录的 `一键编译MCP.bat`，在 `dist/candidate/ReverseResearch-MCP.exe` 生成 Windows amd64 候选程序，显示绝对路径、时间、大小、SHA-256 与当前安装位置。候选通过验证后，运行 `.\一键编译MCP.bat --promote` 编译并发布；现有 promotion owner 保留回滚副本、状态布局闸门和同名计划任务的优雅重启。自动化可加 `--no-pause`；Go 不在 PATH 时尝试标准安装路径，也可通过 `RR_GO_EXE` 指定已有 go.exe。编译完成只代表候选生成，运行版本以 `/healthz`、MCP 握手和发布回执核对。
- 双击已安装的 `ReverseResearch-MCP.exe` 会启动本地 MCP；启动 BAT、自启任务、发布、回滚及 ACL 共同使用 `tools/ops/runtime-artifact.psm1` 的路径规则：优先 dist 的 MCP EXE，其次根目录 `ReverseResearch.exe`，最后根目录 MCP EXE。`dist/candidate` 不参与安装文件选择。双击 `一键启动MCP.bat` 显式执行 `serve` 并保留退出窗口；停止按 Ctrl+C，帮助用 `--help`，只读版本查询用 `--version`。EXE 从所在目录向上查找配置，从其他工作目录启动也定位同一项目。
- MCP 窗口实时显示带毫秒时间的启动、HTTP 请求和工具调用日志：青色为接入/排队/执行，绿色为监听就绪或协议返回成功，黄色为警告/取消/4xx，红色为错误/5xx/响应写入失败，白色为普通信息，灰色为运行摘要。每 30 秒显示 HTTP/工具数量、活动请求、排队/执行数量及协议成功/错误/取消计数；成功的 `/healthz` 探测只计数，失败或取消仍显示，避免刷屏。请求/工具日志不打印参数、结果、请求正文、查询值、header 或 bearer。工具绿色返回表示 MCP 协议成功，业务状态仍以工具结果为准；本地就绪与隧道 ready 分别显示。控制台重定向时输出纯文本。重新编译后，旧进程的窗口需停止并重新启动才会采用新日志。
- 启用已配置的 ChatGPT 隧道时，在终端运行 `.\一键启动MCP.bat --tunnel`；其他 `serve` 参数也可传给此 BAT。
- 双击 `一键备份.bat` 默认生成源码 ZIP；运行 `.\一键备份.bat --full` 则生成完整工具集 ZIP，包含当前 RR 程序、源码、运行环境、研究状态、正式 network-lab 操作收据和发布回滚。两种模式都由 `tools/ops/backup-source.ps1` 统一筛选并压缩，逐项解压核对 SHA-256 后才发布正式 ZIP，同时生成 `.receipt.json`。默认输出在项目根目录，完成后打开资源管理器选中 ZIP；包内统一使用 `ReverseResearch/` 顶层目录。
- 默认源码模式排除运行时、研究数据和可重建依赖；完整模式排除 Git 元数据、开发验收、临时构建、重复 candidate 和可重建缓存。添加 `--preview` 可只查看范围。完整模式应在 RR 服务停止且项目 Debian 磁盘关闭后运行，以取得一致的状态和 VHDX；Windows WSL 组件、系统 Python 及其他项目的外部素材仍须由原安装或素材 owner 提供。
- 完整模式按每个文件实际读取时的共享读锁捕获字节，并记录筛选后、读取前的长度更新。ZIP 的 SHA 校验绑定捕获的原字节；它是当前文件快照，目录筛选后的新增文件和其他 owner 的整组提交仍需下一次存档，不声明所有并行工作同一时刻完成。

Build an isolated candidate without replacing a running installation:

```powershell
.\一键编译MCP.bat --no-pause
.\dist\candidate\ReverseResearch-MCP.exe --version
```

The examples below use the historical installed CLI name. For a candidate, substitute `.\dist\candidate\ReverseResearch-MCP.exe`. The installed path is selected by the shared runtime-artifact module. For the three complete research workflows and exact-candidate verification, see [research workflows](docs/research-workflows.md). Building a candidate leaves the running service on its installed bytes; promotion uses the existing release owner and preserves other tasks' analysis sessions.

`ReverseResearch-MCP.exe` with no arguments starts the local MCP server. Explicit `--help` prints help; the generic `ReverseResearch.exe` CLI retains its no-argument help behavior.

Examples:

```powershell
.\ReverseResearch.exe target identify "D:\game\game.exe"
.\ReverseResearch.exe target compare "old.exe" "new.exe"
.\ReverseResearch.exe die scan "game.exe" --verbose --timeout 15s

.\ReverseResearch.exe process inspect <pid>
.\ReverseResearch.exe process debug-route <pid>
.\ReverseResearch.exe process acquire <pid> --key <process-key> --owner analysis-a
.\ReverseResearch.exe process get <pid>
.\ReverseResearch.exe process release <pid> --key <process-key> --owner analysis-a --lease-id <lease-id>

# Read-only live memory scan/refinement without starting a debugger:
.\ReverseResearch.exe memory scan <pid> --key <process-key> --type u32 --value 100 --start 0x400000 --end 0x800000
.\ReverseResearch.exe memory scan <pid> --key <process-key> --type u32 --unknown --start 0x400000 --end 0x800000
.\ReverseResearch.exe memory refine <scan-id> --expected-version 1 --mode changed
.\ReverseResearch.exe memory refine <scan-id> --expected-version 2 --mode increased
.\ReverseResearch.exe memory refine <scan-id> --expected-version 3 --mode exact --value 250
.\ReverseResearch.exe memory get <scan-id> --sample 32

# Read-only pointer mapping and cross-process verification:
.\ReverseResearch.exe pointer scan <pid> --key <process-key> --target 0x12345678 --start 0x400000 --end 0x800000 --max-offset 4096 --max-depth 3
.\ReverseResearch.exe pointer get <map-id> --sample 32
.\ReverseResearch.exe pointer verify <map-id> --pid <new-pid> --key <fresh-process-key> --target 0x22345678

# Bounded task-owned write observation after acquiring the process lease:
.\ReverseResearch.exe watch write <pid> --key <process-key> --owner analysis-a --lease-id <lease-id> --operation-id watch-score-1 --address 0x12345678 --size 4 --timeout 30s --max-events 1

# Guarded x32dbg mutation after acquiring the process lease:
.\ReverseResearch.exe x32dbg AttachProcess --pid <pid> --process-key <process-key> --owner analysis-a --lease-id <lease-id> --operation-id attach-1
.\ReverseResearch.exe x32dbg SetRegister --json '{"register":"eax","value":"1"}' --pid <pid> --process-key <process-key> --owner analysis-a --lease-id <lease-id> --operation-id set-eax-1

# Guarded PE detour planning and rollback:
.\ReverseResearch.exe hook plan --path "game.exe" --source-rva 0x1234 --destination-rva 0x4567 --expected "55 8B EC 83 EC"
.\ReverseResearch.exe hook get <hook-id>
.\ReverseResearch.exe hook list --path "game.exe"
.\ReverseResearch.exe hook apply <hook-id> --expected-version 1 --operation-id hook-apply-001 --confirm-in-place
.\ReverseResearch.exe hook verify <hook-id>
.\ReverseResearch.exe hook rollback <hook-id> --expected-version 3 --operation-id hook-rollback-001

# Version-bound compatibility records; record-only does not mean compatible:
.\ReverseResearch.exe compat add --game "Example Game" --build "1.0" --module "game.dll" --outcome candidate --validation record-only
.\ReverseResearch.exe compat import --manifest ".\compatibility.json"
.\ReverseResearch.exe compat list --game "Example Game"
.\ReverseResearch.exe compat verify <compat-id>

.\ReverseResearch.exe diff quick "old.exe" "new.exe"
.\ReverseResearch.exe diff functions "old.exe" "new.exe" --threshold 70
.\ReverseResearch.exe diff migrate "old.exe" "new.exe" --anchors ".\anchors.json" --threshold 70
.\ReverseResearch.exe sync preview --json-file ".\semantic-sync.json"

.\ReverseResearch.exe patch plan --path "game.exe" --offset 0x1234 --expected "75 0A" --replacement "EB 0A"
.\ReverseResearch.exe patch plan --path "game.exe" --edits-json '[{"offset":4660,"expected_hex":"75 0A","replacement_hex":"EB 0A"},{"offset":8192,"expected_hex":"90","replacement_hex":"CC"}]'
.\ReverseResearch.exe patch dry-run <plan-id>
.\ReverseResearch.exe patch apply <plan-id> --output "game.patched.exe" --operation-id patch-copy-001
.\ReverseResearch.exe patch apply <plan-id> --in-place --operation-id patch-live-001
.\ReverseResearch.exe patch verify <plan-id>
.\ReverseResearch.exe patch rollback <plan-id> --operation-id patch-rollback-001

.\ReverseResearch.exe route "把旧版函数迁移到新版"
.\ReverseResearch.exe prepare "做一道 CTF Pwn 题，先看保护再分析 ROP"
# Optional explicit discovery roots for tools installed outside PATH:
$env:REVERSERESEARCH_TOOLS = 'D:\Android\platform-tools;D:\ReverseTools\bin'
.\ReverseResearch.exe tools scan
.\ReverseResearch.exe tools show
.\ReverseResearch.exe tools ensure frida ghidra   # plan only; no install
.\ReverseResearch.exe contract audit
.\ReverseResearch.exe capability status native-static
.\ReverseResearch.exe capability list

# Web runtime: installed-browser identity, isolated profile, read-only loopback CDP, local SourceMap/WASM inspection.
.\ReverseResearch.exe web backends
.\ReverseResearch.exe web profile --id case-01 --browser chrome
.\ReverseResearch.exe web cdp --endpoint http://127.0.0.1:9222
.\ReverseResearch.exe web source .\app.js
.\ReverseResearch.exe web sourcemap .\app.js.map --source-index 0 --offset 0 --limit 8192
.\ReverseResearch.exe web har .\capture.har --offset 0 --limit 50
.\ReverseResearch.exe web sse .\capture.sse --offset 0 --limit 50
.\ReverseResearch.exe web wasm .\module.wasm
.\ReverseResearch.exe web wasm .\module.wasm --wabt --view wat --limit 8192
.\ReverseResearch.exe web wasm .\module.wasm --wabt --view details

# Android runtime: explicit device authorization, evidence capture, and one-shot currentness-bound UI action.
.\ReverseResearch.exe android status
.\ReverseResearch.exe android devices
.\ReverseResearch.exe android probe <serial>
.\ReverseResearch.exe android workspace <serial>
.\ReverseResearch.exe android snapshot <serial>
.\ReverseResearch.exe android tap <serial> --snapshot <id> --ui-sha <sha256> --operation-id tap-001 --resource-id <resource-id>

# P1 security research owners. Observation/plan commands do not silently execute effectful work.
.\ReverseResearch.exe malware triage .\sample.bin --case <malware-case-id>
.\ReverseResearch.exe detection sigma --rule .\rule.yml --positive .\positive.json --negative .\negative.json --case <case-id> --telemetry Sysmon --telemetry-available --false-positive-notes "reviewed" --coverage "fixture validated"
.\ReverseResearch.exe dfir inspect .\evidence.evtx --case <dfir-case-id>
.\ReverseResearch.exe dfir timeline .\timeline.jsonl --case <dfir-case-id>
.\ReverseResearch.exe fuzz plan --target .\target.exe --harness .\harness.exe --corpus .\corpus --engine libfuzzer --sanitizers asan --case <vuln-case-id>
.\ReverseResearch.exe crash fingerprint --json .\crash.json
.\ReverseResearch.exe protocol infer --samples .\messages.json --case <protocol-case-id> --name demo
.\ReverseResearch.exe protocol validate --model .\messages.json --fixtures .\independent-fixtures.json --case <protocol-case-id> --name demo
.\ReverseResearch.exe source audit .\repo --case <source-case-id>
.\ReverseResearch.exe source sarif .\results.sarif --case <source-case-id>
.\ReverseResearch.exe source sbom .\bom.json --case <supply-chain-case-id>
.\ReverseResearch.exe purple coverage <purple-case-id>
.\ReverseResearch.exe purple plan <purple-case-id> --technique T1053 --target <scoped-target> --action <allowed-action> --effect-class "runtime mutation" --operation-id purple-plan-001

.\ReverseResearch.exe sandbox plan --name "CTF lab" --kind wsl --route ctf-sandbox
.\ReverseResearch.exe sandbox create --name "local analysis" --kind filesystem

.\ReverseResearch.exe case create --title "Version migration" --route binary-diff
.\ReverseResearch.exe case list --limit 20
.\ReverseResearch.exe case evidence <case-id> --summary "candidate bytes" --source "old.exe"
.\ReverseResearch.exe case finding <case-id> --title "matched function" --conclusion "same call-site role" --strength observed --evidence <evidence-id>
.\ReverseResearch.exe case path <case-id> --title "validated path" --details "UI -> handler -> write" --findings <finding-id>
.\ReverseResearch.exe journal add --title "Ghidra Unicode naming" --body "Use content-addressed ASCII project names" --tags ghidra,unicode --domain static-analysis --arch x64 --tools ghidra
.\ReverseResearch.exe case verify <case-id>
.\ReverseResearch.exe journal search --origin journal --domain static-analysis --arch amd64 --tools ghidra ghidra unicode
.\ReverseResearch.exe journal search --origin builtin --tools x32dbg
.\ReverseResearch.exe journal show <note-id>
.\ReverseResearch.exe journal read <note-id> --revision <sha256-from-search> --start-line 1 --max-lines 80

.\ReverseResearch.exe module status
.\ReverseResearch.exe r2 open_file --json '{"file_path":"D:\\game\\game.exe"}'
.\ReverseResearch.exe module batch --json-file .\analysis-batch.json
```

A module batch keeps the lazy backend session alive for the whole batch, which is useful for workflows such as open → analyze → query → close without starting the ReverseResearch MCP server.

A successful batch retains the existing JSON array and successful-row fields. Successful `r2.analyze` responses intentionally carry a `reverseresearch/r2-result` observation in MCP `_meta` and therefore use the full MCP result format. An `unknown` or `cached_unverified` observation does not prove analysis completion. Other successful tools retain the existing payload/Meta output contract. On the first transport, MCP tool, or explicitly recognized r2 result failure, the batch stops and returns a nonzero exit code. Its stdout is a JSON object with `status: "partial"`, the successful prefix in `results`, the failed step's zero-based `index`, `module`, `tool`, `error` and original MCP `result` (when available) in `failure`, plus `total` and `unexecuted` counts. `partial` also applies when no step succeeded; a failed step may already have had effects. Later steps, including an explicit `close_file`, are not called or retried. The existing runtime owner still closes its backend session. A single module call keeps stdout empty on failure. These observations do not verify analysis completeness or repair the provider's analysis cache.

## Offline SourceMap, HAR and SSE inspection

The REA integration uses the existing Core. `web source` summarizes inline/external classic and embedded indexed SourceMap v3; `web sourcemap` reads embedded source in bounded UTF-8 byte pages. `web locate <map> --line 0 --column 0` decodes VLQ coordinates using zero-based lines and UTF-16 columns. Indexed source indexes flatten in section order; section URLs and source declarations are never fetched. Missing content and explicitly unmapped positions stay unavailable. This is a strict local profile, not full ECMA-426 consumer conformance.

`web har` projects a historical HAR 1.2 into a bounded summary, preserving original producer ordinals and JSON pointers. Every record's projected fields and duplicate JSON keys are checked before selection. Headers, cookies, bodies, URL credentials, fragments and query values are excluded; visible URL paths/query names may still contain sensitive data. This is a summary profile, not full HAR-schema validation, wire-byte recovery, a current browser observation or request replay.

Follow `next_offset` using `--expected-sha256 <sha256-from-first-page>` (MCP `expected_sha256`); review counts and coverage. HAR summaries have a 48 KiB page budget; embedded source text is capped at 64 KiB per request. `web har-api` projects exact historical method/URL groups; `web har-body --entry-ordinal 0 --side response` explicitly reads retained text/base64 producer body bytes. `web har-compare <before> --right <after>` compares redacted summaries, with `expected_sha256` pinned to `comparison_sha256`. Body reading may expose captured data and does not recover original wire bytes. MCP tools include `web_source_map_locate`, `web_har_api`, `web_har_body_read` and `web_har_compare`. Source and closure records remain in the existing upstream reference and implementation ledger.

`web sse` / `web_sse_inspect` inspect a retained UTF-8 SSE response body. CR/LF/CRLF, blank-line dispatch, multi-line data and inherited/reset event IDs are handled explicitly. Event summaries preserve original byte/line spans and data/ID hashes; default output omits payloads and raw IDs. Use `--data-preview-bytes 256` (MCP `data_preview_bytes`) when a bounded prefix is useful; visible labels and opted-in data may contain secrets. Follow `next_offset` under the same `expected_sha256`. Input is capped at 32 MiB, lines at 1 MiB, joined event data at 4 MiB, and encoded event pages at 48 KiB.

EOF data without a final blank line stays undispatched and is reported as a coverage gap. `[DONE]` is only a recorded marker; later events are retained and application completion stays `unverified`. SSE framing does not translate provider JSON, establish server/tool execution, reconnect or replay. The protocol/reconstruction methods and reviewed fixed upstream objects are documented in the existing Web/Evidence playbooks and UP01–UP03 of the implementation ledger.

## Static application inspection

All `app` commands share Core/CLI/MCP and never run the supplied target:

`app analyze` accepts an ASAR or local directory, including inventoried
`node_modules`. It derives static paths for `import` and `require`, package
`main`/index lookup, self references, and `imports`/`exports` conditions,
arrays and patterns. Conditions use the declared order under the default
Node profile. Results retain the package metadata hashes and distinguish
blocked, missing, unavailable and unsupported relationships. They do not prove
that the application loads or runs. Logical paths are case sensitive;
symlinks, external private-import targets, custom loaders and bundler aliases
are not followed. Selected file bytes, package metadata and path boundaries
participate in the same pagination hash. Limits are 2,048 selected files,
8,192 directory/unread-file boundaries, 1 MiB per selected file and 32 MiB
selected bytes. The current MCP executable also accepts these CLI commands.

```powershell
.\ReverseResearch.exe app analyze .\application.asar --limit 20
.\ReverseResearch.exe app asar .\application.asar
.\ReverseResearch.exe app read .\application.asar --entry main.js --limit 8192
.\ReverseResearch.exe app javascript .\application.asar --entry main.js
.\ReverseResearch.exe app managed .\application.dll --limit 20
.\ReverseResearch.exe app method .\application.dll --token 0x06000001
.\ReverseResearch.exe app compare-managed .\before.dll --right .\after.dll
.\ReverseResearch.exe app compare-javascript .\before.js --right .\after.js
.\ReverseResearch.exe app go .\program.exe
.\ReverseResearch.exe app go-read .\program.exe --part module-body --limit 8192
.\ReverseResearch.exe app package .\application.ipa --family apple --view bundles
.\ReverseResearch.exe app package .\entry.hap --family harmony
.\ReverseResearch.exe app package .\application.apk --family android --view manifest
.\ReverseResearch.exe app package .\application.apk --family android --view resources
.\ReverseResearch.exe app package .\application.apk --family android --view resource-values --resource-index 0
.\ReverseResearch.exe app dex .\application.apk --entry classes.dex --view methods
.\ReverseResearch.exe app dex .\classes.dex --view strings
.\ReverseResearch.exe app evm .\runtime.hex --encoding hex
.\ReverseResearch.exe app zip .\package.zip
.\ReverseResearch.exe app zip-read .\package.zip --entry app/main.js
.\ReverseResearch.exe app tar .\firmware.tar.gz
.\ReverseResearch.exe app tar-read .\firmware.tar.gz --entry etc/config.json
.\ReverseResearch.exe ios plist .\Info.plist
.\ReverseResearch.exe ios plist-data .\archive.plist --object-index 12 --limit 8192
.\ReverseResearch.exe ios keyed .\archive.plist --root root
.\ReverseResearch.exe ios nib .\Main.nib --view values --limit 20
.\ReverseResearch.exe crash inspect .\recorded.core --view threads --limit 5
.\ReverseResearch.exe crash note .\recorded.core --note-index 0 --part descriptor
.\ReverseResearch.exe case view <case-id> --finding <exact-finding-id>
```

ASAR validates all packed ranges and declared SHA-256 integrity before paging; links/unpacked targets stay unavailable. ZIP inventory checks names/ranges; selected entry reading checks decompression size and CRC. TAR/gzip TAR validates all members before paging, checks gzip CRC, and leaves links/special/sparse entries unavailable. Archive readers do not extract files. AST analysis covers selected `.js/.mjs/.cjs` files and declares imports, import/export bindings, export value shapes, functions and Electron/endpoint/CommonJS candidates; directory analysis omits `.git/node_modules/.tmp`. Binding names retain AST spelling; relative module paths remain candidates. TypeScript/JSX, bundler alias resolution and runtime reconciliation are outside this profile.

Apple XML/bplist00 inspection preserves a bounded object table, exact integer text, IEEE representations, data hashes and UID identities. Binary byte ranges bind the original artifact; XML ranges bind normalized UTF-8 without BOM with a separate digest. Explicit data reads preserve empty values. NSKeyedArchiver retains original `$objects` indices, nil/cyclic/unresolved references and declared class names; root selection filters named roots while object paging stays build local. Compiled NIBArchive v1 exposes inert object/value declarations and opaque class extensions. These readers never instantiate Foundation/UIKit classes or claim rendered UI or runtime behavior. Input is capped at 16 MiB, objects/references/depth/output are bounded, and every page can be fenced by `expected_sha256`.

Recorded core inspection supports the explicit Linux ELF64 amd64 little-endian, ABI-v0 profile on any host. It records segment/note bytes, all 27 PRSTATUS registers and supported SIGINFO fields with source ranges; unknown note bytes stay readable. Historical PIDs never select or authorize a live process. Missing notes, unwind, crash-thread association, executable identity and exploitability remain unknown. Input is capped at 32 MiB; no debugger or emulation process starts. ELF program/section allocation budgets and static file capture remain owned by `targetidentity`.

PE/CLI reports freeze SHA/MVID/build-local tokens and expose selected static CIL instructions and P/Invoke declarations. It does not load CLR, recover C#, unpack NativeAOT/IL2CPP or prove native calls. Static comparisons preserve ambiguous declarations; raw IL equality excludes headers/locals/EH and cannot prove semantic equivalence across token reassignment. Go inspection uses the pinned standard-library buildinfo decoder. EVM linear decoding reports PUSH4/EQ selector candidates, with ABI/mutability/control flow unverified.

`app package` reuses the ZIP snapshot/path/range/CRC reader for Apple and Harmony package projections. Apple bundle anatomy preserves nearest bundle/parent paths, shallow/deep/versioned framework Info.plist candidates, bounded executable candidates and exact framework-name hints. Harmony ZIP-backed `.hap/.hsp/.app` reports root Stage/FA manifest path hints, Ark/native/script/resource/signing components and child packages without recursion. Returned available component bytes are CRC checked and SHA hashed; bundle view and unreturned components remain inventory declarations. These profiles do not parse manifest/plist semantics, verify signatures, decode Ark/CoreUI or establish loaded runtimes/native bindings.

`app go-read` preserves exact original header/compiler/module ranges and bytes for inline and historical-pointer Go records through the canonical native mapping owner. Non-UTF-8 data remains base64 without replacement characters. The `module` part retains Go framing; `module-body` requires exact known sentinels (or an explicitly empty historical module) and reports the separate body range/UTF-8 status. Ambiguous maps/headers, integer wrap, unsupported containers and more than 1 MiB aggregate strings fail explicitly. Byte paging is SHA fenced; raw availability is independent of text-summary/semantic parsing and supply-chain authentication.

The existing `web wasm` / `web_wasm_inspect` entry supports optional WABT 1.0.42 (`--wabt` / `use_wabt:true`). Default inspection only reads partial structure. The WABT profile validates with `--enable-all`, then returns byte-paged `wat` or `details` with input/output/tool SHA-256 and exact banners/arguments. Put trusted tools in `runtime/wabt/wabt-1.0.42/bin` or an existing `REVERSERESEARCH_TOOLS` directory; runtime never installs tools. Inputs are captured into a private, read-only temporary copy, rechecked around commands and removed on completion. Invalid modules retain bounded structured diagnostics and fail the CLI/MCP call. Bind successive pages with both expected SHA fields. WAT does not prove source, byte round-trip identity or execution; the adapter never instantiates WASM.

`case view` is a SHA-fenced, disposable projection of canonical Case links and recorded WorkItem/Hypothesis/Finding states; exact `finding_id` selects a dossier. It checks evidence currentness and never accepts completion or joins targets/functions by text. PE/ELF/Mach-O layout, native analysis, route selection, process controls and final Case review reuse their existing owners. This integration does not claim complete REA parity; detailed remaining provider/platform gaps are recorded in the implementation ledger.

## Pinned Detect It Easy static inspection

`die scan` is a local, read-only adapter over the project-owned Detect It Easy 3.21 `diec.exe` runtime. ReverseResearch verifies the pinned executable SHA-256 and exact `die 3.21` version before every scan, requests JSON output, and rechecks the target identity after analysis so file drift is rejected. The default timeout is 15 seconds and the hard maximum is 2 minutes; stdout/stderr are bounded. The adapter does not start Ghidra/x32dbg/r2 or mutate the target.

## Research integrity and reusable knowledge

`case verify` checks the current source size/SHA-256, object identities and Evidence -> Finding -> Path references. Findings now carry an evidence-strength grade separate from subjective confidence: `observed`, `inferred`, or `unverified`; new findings default to `unverified`. Historical findings without a grade stay readable and are reported as `ungraded_findings` rather than silently rewritten. Verification returns the exact case JSON revision and explicit unbound-observation counts. A changed source, missing source, broken reference, invalid strength, or case revision that moves during verification produces diagnostics; an invalid result also exits nonzero. Verification does not rewrite history or turn a research hypothesis into a runtime-verified fact.

Cases use stable per-case OS locks across cooperating CLI processes. Knowledge notes are immutable and use the same safe publisher; an ID collision never replaces an existing note. Failed publication retains the prior record. Lock sidecars are intentionally retained and must not be deleted while clients are running. Older executables that do not participate in this locking protocol must not write the same records concurrently.

Knowledge search/show includes a SHA-256 `revision` and source metadata. `journal read` requires that revision, caps excerpts at 200 lines / 32 KiB, and rejects stale revisions or unsafe IDs. Local notes can carry structured `domain`, `architectures`, and `tools` applicability; `journal search` filters those fields plus route and origin. Architecture aliases such as `x64`, `amd64`, and `x86_64` normalize to `x86-64`. The legacy `Search(query, limit)` API remains journal-only; filtered search explicitly opts into the builtin corpus. ReverseResearch embeds a small reviewed, immutable builtin corpus covering target currentness, guarded patching, x32dbg process control, and Ghidra runtime/currentness. Builtin records use fixed `builtin_...` IDs, explicit provenance, `evidence_status=reviewed`, revision-pinned reads, and cannot be overwritten through the journal. Explicit provenance can be supplied to `journal add` with `--source`, `--license`, `--source-revision`, `--engine`, `--target-version`, and `--evidence-status`. Local notes default to unverified / unspecified provenance; historical notes remain readable without silent rewriting. Provenance labels are author statements, not executable instructions or proof of redistribution permission.

`diff migrate` accepts a JSON array such as:

```json
[{"label":"known-function","old_rva":4144,"old_name":"sym.KnownFunction"}]
```

Use either selector or both; when both are supplied they must both match. JSON RVAs are numeric decimal values. The result distinguishes mapped, unmapped and ambiguous candidates; `UNMATCH` and below-threshold rows are excluded, symbol names are case-sensitive, and target content is rechecked after analysis. All results remain `candidate-only` with `runtime_verified=false`. The command neither applies symbols nor patches a binary. For independent semantic corroboration, `tools/smoke/ghidra-isolated` can start a separate Ghidra backend on a separate port/state root and compare old/new database functions without touching the already-running Ghidra daemon; that evidence still does not become runtime execution proof.

`sync preview --json-file <request.json>` consumes an already-reviewed migration result plus source/target semantic snapshots. It previews function names/comments and structure/member names, types, and comments without starting Ghidra. Every action is classified as `suggest`, `preserve`, `conflict`, `same`, or `skip`; target-side user names are always preserved, existing differing comments/types become conflicts, ambiguous/unmapped functions are skipped, and missing structures/members are additive suggestions only. The result always declares `validation=preview-only`, `runtime_verified=false`, and `writes_performed=false`.

## Verification without touching live analysis

Run from the project root:

```powershell
go test ./internal/... ./cmd/... ./tools/... -count=1
- `internal/casebook` - research Case → Evidence → Finding → Path records with source hashing.
go vet ./...
staticcheck ./...
C:\msys64\ucrt64\bin\python.exe -m unittest tests.test_ghidra_runtime_regressions -v
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify\verify-research-records.ps1
```

The package-scoped test patterns are intentional: only Go packages under the source tree participate in the source gate, even when the project root also contains large research datasets or runtime bundles.

Build the candidate first. The execution-policy option applies only to this verification process, not the machine-wide policy. The script runs separate CLI processes in a unique `.tmp/record-closeout/smoke-*` directory, exercises case/journal persistence, source-drift rejection, Unicode paths, Hook/patch round trips and concurrent evidence writers, and emits a JSON report with the candidate hash. Hook disassembly uses the explicit `REVERSERESEARCH_TOOLS` discovery roots, so the smoke never changes its Core root back to the production repository just to find radare2/radiff2. It snapshots production persistent state (`hooks`, `patches`, `compatibility`, `research`, `knowledge`, `sandboxes`) and fails if the candidate leaves any change there. A successful run removes its scratch directory automatically; a failed run keeps the scratch directory for diagnosis. It does not start Ghidra, attach a debugger, replace the installed executable, or consume the existing 19096 session.

Source/test completion, production promotion, and connected-client catalog refresh are recorded separately. The internal implementation ledger is kept in the private project archive and is not distributed.

## Windows production hardening and autostart

For the long-running Windows installation, keep the executable/runtime/state boundaries private and register the server as a per-user logon task:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\harden-local-install.ps1 -Action Apply
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-autostart.ps1 -Action Install
~~~

Read-only checks:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\harden-local-install.ps1 -Action Audit
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\ops\manage-autostart.ps1 -Action Status
~~~

The ACL audit allows only the current user, SYSTEM, and local Administrators on the installed executable, tunnel/runtime configuration, state/evidence trees, rollback directory, and configured tunnel API key. The autostart definition uses the shared installed-artifact resolver with `serve --tunnel`, runs at the current user's logon with Limited privileges, and retries failed starts three times at one-minute intervals. ReverseResearch can adopt an authenticated existing Ghidra daemon during a service restart so open analysis databases do not have to be terminated for an RR/RT upgrade.

Use `manage-autostart.ps1 -Action Restart` for production restarts. It sends an authenticated POST to the loopback `/control/shutdown` endpoint, waits for the current server to close cleanly, and then starts the canonical Scheduled Task. `-Action Stop` performs only the graceful stop. This avoids accumulating stale backend MCP session attachments during upgrades.
## Optional MCP adapter

Start the local loopback MCP endpoint explicitly:

```powershell
.\ReverseResearch.exe serve
```

Endpoint:

```text
http://127.0.0.1:19100/mcp
```

The local HTTP MCP endpoint is loopback-only and requires a bearer token. On first startup ReverseResearch creates a 32-byte random token at `state/auth/local-mcp.token`; clients must send `Authorization: Bearer <token>` to `/mcp`. A malformed persisted token fails startup rather than being silently replaced. `/healthz` remains read-only and unauthenticated. Non-loopback `--listen` values are rejected.

The Secure MCP Tunnel uses its existing tunnel ID/control-plane API key and in-memory transport; it does not reuse or expose the local bearer token.

Enable OpenAI Secure MCP Tunnel only when needed:

```powershell
.\ReverseResearch.exe serve --tunnel
```

The same optional MCP adapter exposes:

- `x32dbg_*` - dynamic debugging.
- `ghidra_*` - static analysis and decompilation.
- `r2_*` - lightweight headless analysis.
- `target_*`, `process_*`, `memory_scan_*`, `pointer_map_*`, `write_watch`, `hook_*`, `compatibility_*`, and `patch_*` - thin MCP wrappers over the same local Core/runtime owners used by the CLI.
- `reverse_status` - backend state without starting a backend.

Current ChatGPT ingress variants are:

- `RR` - ordinary Server URL connection.
- `RT` - OpenAI Secure MCP Tunnel.

The checked-in `testdata/online-rr-rt-contract-20261001.json` records the historical 124-tool backend/status contract; the 238-tool deployment and the subsequent 270-tool RR audit are dated evidence in the private project archive. Version 0.4.0 registers 280 tools, including the ten previously CLI-only operations: `binary_diff_quick`, `binary_diff_functions`, `function_migration_plan`, `journal_add/search/get/read`, `capability_status`, `playbook_list`, and `sandbox_create`. CLI and MCP share the same Core owners. Source registration, installed runtime and the refreshed ChatGPT catalog each require their own verification; current delivery evidence lives in the private project archive and the [workflow guide](docs/research-workflows.md).

Remote MCP calls can only access files and processes visible to the machine running ReverseResearch. Another computer's local files or live game process are not implicitly available; they must be transferred/mounted or analyzed by a local execution endpoint on that machine.

## Seep-Reverse-Lab agent skill

`skills/seep-reverse-lab/SKILL.md` is the single progressive-disclosure control plane for Windows, Android, and Web reverse work. `config/routes.json` owns classification only; `config/playbooks.json` maps eligible routes to the master Skill plus one platform `reference_path`, gates, failure reference and done criteria. This avoids a second routing table inside prompts or Skill files.

The MCP adapter exposes `task_route`, `task_prepare`, `playbook_get`, and `tool_index_scan` over the same Core owners used by the CLI. They are backend-lazy: route/prepare/playbook lookup starts no analysis process, and tool-index refresh only updates machine-local `state/tool-index.json`. `task_prepare` returns route, current capability/provision truth, sandbox recommendation, and the validated route-owned playbook gates. The master Skill adds classification/environment/control/action gates, a two-strike stop rule, symptom-driven references, evidence discipline, and an explicit completion gate.

`skills/seep-reverse-lab/scripts/doctor.ps1` is a Windows preflight helper. It queries the existing tool index/module status and reports proxy variables, relevant running processes, and the dedicated ReverseResearch backend ports without killing or attaching to anything. Android/Web now also have bounded local runtime owners: Web exposes installed-browser identity/policy, isolated-profile preparation, loopback-only read-only CDP discovery, local SourceMap validation and static WASM inspection; Android exposes explicit adb authorization/probe, per-device hashed workspaces, UI hierarchy/screenshot evidence, and one-shot currentness-bound selector taps. These adapters do not auto-authorize devices, do not install certificates, do not launch or take over a daily browser profile, and do not auto-replay uncertain device actions.

## Safety model

Patch operations are guarded by target SHA-256, file size, expected original bytes, an immutable plan digest, and the expected post-patch SHA-256. A plan can contain one edit or a canonicalized set of disjoint same-length edits. Composite edits are sorted by offset before identity/digest generation, overlapping ranges are rejected, identical source/replacement bytes are rejected, the edit count is capped at 4096, and the combined mutation payload is capped at 1 MiB. The same logical composite plan therefore has one stable identity regardless of input ordering. Copy mode is the default safe path; in-place modification must be explicitly requested. Rollback refuses to overwrite later unrelated changes.

Apply and rollback also have durable `operation_id` receipts. A receipt is persisted before the file effect, and cooperating CLI/MCP processes serialize on stable sidecar locks. A retry can complete an interrupted operation only when the current file is exactly the original source state or the exact planned postcondition; any other state fails closed. Reusing one explicit `operation_id` for a different plan/mode/output is rejected. This is local cooperating-process recovery, not a claim of filesystem power-loss atomicity, network-share locking, or multi-file transactions.

Live-process inspection freezes PID, creation time, main-module base, executable SHA-256, and PE architecture into one process key. `process debug-route <pid>` and the `process_debug_route` host tool reuse that fresh process identity to preview the internal debugger route without attaching or starting a backend: i386/32 selects x32dbg, amd64/64 selects x64dbg, and unsupported/non-PE/mismatched targets fail closed. The public `x32dbg_*` namespace remains unchanged for compatibility. A cooperating-process control lease is persisted under `state/process-control`; the same owner can replay acquisition, a different owner is rejected, and PID reuse cannot inherit the old lease. Release additionally requires the current `lease_id`, which fences a delayed release from deleting a newer same-owner lease after release/reacquire.

`memory scan/refine/get` is a separate read-only Windows process-memory path and does not require a debugger attach. Initial scans support exact or unknown values for u8/i8/u16/i16/u32/i32/u64/i64/f32/f64; persisted candidate sets can then be refined by exact, changed, unchanged, increased, or decreased. Every scan is bound to the frozen process key, every candidate retains its memory-region identity, and refinement drops candidates whose region identity changed. Candidate-set versions are fenced by `--expected-version`; byte/candidate/time caps and unreadable/query failures are reported explicitly instead of silently claiming complete coverage.

`pointer scan/get/verify` builds on that same read-only memory access. Pointer search is bounded by range, offset, depth, bytes, nodes, chains, and timeout. Persisted roots are module-file SHA/size + RVA anchors; verification takes a fresh process key, rebases the RVA to the currently loaded module base, rechecks the module file identity, and dereferences every saved level again. This lets a valid chain survive PID/process restart, module relocation, and changed heap allocation while rejecting stale process identity, module drift, unreadable levels, or pointer drift.

`watch write` / `write_watch` is the bounded dynamic observation owner. It requires an existing process-control lease but does not release that lease. The watch takes the local xdbg workflow lock, refuses to hijack an already-bound xdbg session, attaches its own session, rejects a watched address that already has a breakpoint, installs one aligned hardware write breakpoint, and collects bounded pause evidence: instruction pointer, module/base/RVA, current thread, registers, thread list, call stack, event log, and before/after bytes. Normal cleanup removes only that exact hardware breakpoint with the canonical x64dbg `bphc <address>` command and stops the task-owned debug session; it never calls `DeleteAllBreakpoints`. If timeout/cancellation causes the backend transport itself to reset, the watch clears only its own runtime session binding and reports `backend_reset/resources_released` instead of pretending the targeted delete ran.

`hook plan/get/list/apply/verify/rollback/cancel` is the guarded PE detour owner. Planning is read-only: the bundled radare2 6.2.2 CLI proves that the source RVA is an exact whole-instruction boundary and extends the overwrite only across complete instructions; those bytes are cross-checked against the target file. Active hook source intervals are registered under `state/hooks`, and overlaps fail closed until the prior plan is cancelled or rolled back. The current relocation model is deliberately narrow: a same-module `E9 rel32` jump is calculated from source RVA to destination RVA, with NOP padding across the proven overwrite span and explicit range/executable-section checks. This is not an automatic trampoline/code-cave allocator. Apply and rollback require expected versions plus operation IDs, revalidate PE structure and the exact frozen original/applied bytes, and recover idempotently across the tested post-effect/pre-state-commit windows. Unknown bytes are never overwritten.

`compat add/import/get/list/verify` records DLL/Hook compatibility without conflating storage with proof. Records freeze exact module identity and may bind a guarded Hook plus case/evidence IDs. `compatible` is rejected unless validation is `runtime-verified`, the linked case/evidence is currently valid, and at least one referenced evidence item is explicitly marked `kind=runtime` or `kind=runtime-verification`; record-only/static material can remain candidate/incompatible but cannot be silently promoted. Manifest import preserves declared validation. `compat verify` only audits current module/Hook/evidence bindings and always reports `compatibility_revalidated=false`; it does not start a backend or rerun the game.

Typed x32dbg mutations now cross a second final-effect boundary. `AttachProcess` first binds the debugger session to the leased process and the current ReverseResearch runtime generation; memory/register/breakpoint/execution mutations then require that same runtime binding, PID, process key, owner and lease ID plus an explicit `operation_id`. A new ReverseResearch runtime cannot inherit an old attach merely because the target lease still exists. Normal runtime shutdown clears its binding; after an abnormal controller crash, recovery is fail-closed until the stale process lease is explicitly released/reacquired and a new attach operation is issued. ReverseResearch persists a prepared receipt before the backend call. A completed identical operation returns the cached result without executing again; an interrupted/prepared operation is reported as uncertain and is never replayed. `_rr_guard` carries the same metadata through MCP; direct CLI calls can use `--pid`, `--process-key`, `--owner`, `--lease-id`, and `--operation-id`. `ExecuteDebuggerCommand`, `LoadBinary`, and `RestartDebug` are blocked at this low-level boundary because they can bypass typed target/session ownership.

The same boundary has an isolated real-effect verifier: `go run ./tools/smoke/x32-effect -root .`. It only runs when the dedicated x32 MCP port is free and no existing x32dbg/x64dbg/headless process is detected. The verifier launches its own 32-bit fixture, proves a guarded memory write changes the target, restores the value externally, proves completed-operation replay does not write again, rejects conflicting reuse of the operation ID, and checks the task-owned binding/port are released. The checked evidence summary lives at `testdata/x32-effect-evidence-20261002.json`; it does not imply the production RR/RT deployment was upgraded.

Ghidra and radare2 backend mutations still are not automatically replayed after an uncertain failure. The x32dbg guard is a cooperating-process safety boundary; it does not claim protection against a separate non-cooperating debugger that writes the same process.

Ghidra uses the machine's single MSYS2 UCRT64 CPython 3.14 runtime. Before starting the daemon, ReverseResearch verifies the Python ABI/SOABI, loads UCRT64-native dependencies such as JPype from that interpreter's system site-packages, and then loads `mcp`, `re_mcp`, `re_mcp_ghidra`, and the retained Python-side Ghidra adapter from the project bundle. Worker subprocesses inherit the same ordered search path. A standalone Python 3.12 runtime is no longer required or indexed.

Ghidra 12.1.4 does not allow arbitrary Unicode in its internal project item names. ReverseResearch therefore keeps the original Unicode source path as identity and maps an unsupported basename (including Chinese filenames) to a stable content-addressed ASCII database name only for import; the temporary alias is removed after import. Chinese source/project/state directories remain supported. Isolated validation uses a separate port/state/evidence root and does not stop or replace an existing Ghidra daemon.

## Layout

- `cmd/reverseresearch` - CLI plus optional `serve` entry point.
- `internal/core` - protocol-independent target and patch services.
- `internal/modules` - local lazy capability runtime shared by CLI and MCP.
- `internal/router` - structured task routing backed by `config/routes.json`.
- `internal/toolindex` - machine-local tool discovery/indexing used before acquisition; `REVERSERESEARCH_TOOLS` adds explicit off-PATH search roots without auto-installing anything.
- `internal/capability` - route-level readiness/coverage evaluation from routes + tool index + provisioning recipes.
- `internal/bindiff` - local radiff2-backed file/function diff with target identity, RVA normalization and confidence labels.
- `internal/migration` - anchored, ambiguity-aware candidate migration plans, without symbol application or runtime approval.
- `internal/recordio` - shared cooperating-process locks and replacement-safe record publication.
- `internal/processcontrol` - live Windows process identity plus cooperating-process control leases with PID-reuse and lease-generation fencing.
- `internal/casebook` - research Case → Evidence → Finding → Path records with source hashing.
- `internal/knowledge` - machine-local field journal / reusable research knowledge.
- `internal/sandbox` - research workspace planning/creation with filesystem, WSL and Docker profiles.
- `internal/provision` - versioned tool acquisition planning from `config/tool-recipes.json`.
- `internal/backend` - backend lifecycle/connectors.
- `internal/catalog` - verified static MCP tool manifests.
- `internal/server` - optional MCP adapter and HTTP endpoint.
- `internal/targetidentity` - target identity and PE metadata.
- `internal/patchplan` - guarded patch lifecycle.
- `patches/ghidra` - versioned local overlays applied to the ignored Ghidra runtime.
- `runtime` - production runtime dependencies.
- `docs` - design and maintenance notes.
- `evidence` - verification output.
- `state` - runtime state, ignored by Git.
- `testdata` - retained integration-test fixtures.

## Branding

- `ReverseResearch.ico` - Windows executable/source icon.
- `ReverseResearch.png` - 256x256 ChatGPT App icon (PNG, under 10 KB).
