# tools

项目维护与验证工具，按职责分层：

- ops/：本机生产运维脚本。包含 ACL 加固、Windows 登录自启动、graceful Stop/Restart 和 ZIP 备份。根目录“一键备份.bat”调用 backup-source.ps1，后者唯一拥有 Source/Full 筛选、ZIP 创建、逐文件 SHA 校验及完成后打开文件夹的逻辑。`--full` 包含 RR 的运行环境、数据和素材，默认仍为源码模式。
- verify/：候选二进制和研究记录的隔离验收脚本。不会直接拿生产 EXE 做测试。
- smoke/：需要实际启动隔离后端或真实效果路径的 Go smoke 工具。
- fixtures/：供 smoke/verify 临时构建使用的小型测试进程源码，不是生产入口。
- network-lab/：可复用的本地网络仿真工具集。项目根目录“一键网络仿真.bat”进入，单一WSL2 Debian内隔离多个netns，按配置测试NAT、延迟、丢包、端口阻断和恢复；源码、配置和说明都在此处。

约定：
1. 生产入口只在 cmd/，这里不放正式产品入口。
2. 测试辅助源码不放 runtime/，避免与第三方部署运行时混在一起。
3. ops/ 和 verify/ 脚本默认从两级父目录定位项目根目录。

`ops/runtime-artifact.psm1` 是编译/启动/自启/发布/ACL 的共享无状态路径解析器。候选输出固定在 `dist/candidate/ReverseResearch-MCP.exe`；installed 按现有 dist/根目录 CLI/根目录 MCP 顺序选择。`manage-promotion.ps1` 是发布及回滚唯一 owner，回执绑定目的路径与字节哈希，串行发布并拒绝 prepared 回执、目的漂移和未知安装字节。版本查询使用 EXE `--version`，不会创建研究状态。

`smoke/research-workflows` 在全新、独立 root 与 loopback 端口启动指定候选，经真实 MCP 验收 Windows PE、跨版本候选迁移、JS/SourceMap/HAR 三条流程及 Case/Review/Report/Journal/Sandbox。需要已有的 Windows GCC、DiE 3.21、radiff2；不会下载工具或执行分析目标，最后通过认证 shutdown 优雅退出。既有 evidence 目录会被拒绝，结果不明时先读原 receipt，使用说明见 `docs/research-workflows.md`。

传入确切的 `-android-aapt2`、`-android-r8`、`-android-jdk` 三项可加入第四条 Android 离线流程。原验收 owner 从 `fixtures/android` 自有源文件用真实本机 javac/D8/AAPT2 生成惯性 unsigned APK，核对 producer/source currentness，再经实际 MCP 与同一 Case/Review/Report/Journal 验收。该 fixture producer 不进入生产分析/安装入口，也不要求设备。
