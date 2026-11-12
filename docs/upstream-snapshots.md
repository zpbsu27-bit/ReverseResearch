# 上游组件快照

ReverseResearch 把运行时二进制保留在 `runtime/` 下，并在此记录上游源码修订版本，因此不必再让旧的迁移树留在磁盘上。

- radare2 MCP：`https://github.com/radareorg/radare2-mcp.git` @ `bc339602b0dbac04619127bee395795c4e140f1e`
- re-mcp / Ghidra 后端：`https://github.com/jtsylve/re-mcp.git` @ `7b38aa92952bd0621e8c964dc859f1515fe26a10`
- x64dbg MCP 服务端：`https://github.com/duty1g/x64dbg-mcp-server.git` @ `6b1507ada373d30d15133e27250a7675bc63b69d`

## 工作流 / Skill 灵感来源

这些仓库仅作为方法论来源被审阅；它们的源码树与第三方二进制都没有被 vendored 进 ReverseResearch。

- reverse-skill：`https://github.com/zhaoxuya520/reverse-skill.git` @ `cab634bd855fc287f6e420c1f36fd1a6b9245960`
- apk-reverse：`https://github.com/newliver666/apk-reverse.git` @ `7b6c6932a95f03d778e81e5e1a2cbf6f62dc97fd`
- REA（Reverse Engineer Anything）：`https://github.com/morluto/rea.git` @ `cf415619cadcfcb18cda59a54b26c9d164f750a4`，2026-10-09 审阅主仓库 MIT 许可证。只吸收源码模式与方法；HAR/SourceMap 使用 RR 原创 Go 实现，没有引入上游 Node 依赖、商业 provider、agent 安装器或第二套事实存储。具体施工与验收记录保存在私有项目归档中，不随开源树分发。
- reverse-skill 于 2026-10-09 复核 HEAD 仍为上述 `cab634b...`；本轮追加方法吸收由同一实施清单 UP02/UP03 核销。
- REA 扩展审阅（2026-10-12）：`fa87dd2aac3eaeb49875c54e93ec18c98cc92e4d`，MIT，LICENSE SHA-256 `798f9e4d18e49b30bf2f12696c8ced73dc4e1413da375a333d01281543a1ea8b`。覆盖当前 contracts 与应用/托管/Web/Go/EVM/artifact/provider 文档，以及 `KeyedArchiveReader.ts`、`domain/apple/keyedArchive.ts`、`NibArchive.ts`、`docs/recorded-crashes.md` 和 recorded core adapter 的声明/边界。新增静态能力使用原创 Go 实现、标准库与固定 Go ECMAScript parser，不引入 REA Node/agent bootstrap/事实存储。布局识别与 byte snapshot 复用 RR targetidentity。唯一核销记录接续 REA04–REA18；部分静态支持不宣称完整 REA/provider/runtime 等价。
- WABT 原生工具 profile 固定 [1.0.42](https://github.com/WebAssembly/wabt/releases/tag/1.0.42)，source commit `ff0ef7e0009402740c805a9744c09b05be063e48`，Apache-2.0。本机供给的官方 Windows x64 archive `wabt-1.0.42-windows-x64.tar.gz` 已与 [官方 release metadata](https://github.com/WebAssembly/wabt/releases/expanded_assets/1.0.42) SHA-256 `62f1eb2b51aa57cf0f0b8ba333bf2c72a049930aa9c5de01dcad271c4fe48c88` 核对，仅选取 wasm-validate/wasm-objdump/wasm2wat/wat2wasm，LICENSE 保存在 runtime/wabt。工具由 ToolIndex 与原 WASM 查询复用，运行时不下载安装；version/banner/hash 不是任意 caller-supplied 工具的 publisher authentication 或 OS sandbox。Windows producer 验收与其他平台 UNVERIFIED 分开记录。
- Apple plist 字节格式参考 [Apple CoreFoundation CFBinaryPList.c](https://github.com/apple-oss-distributions/CF/blob/main/CFBinaryPList.c)，Linux amd64 core ABI 参考固定 [Linux v6.18 elfcore.h](https://github.com/torvalds/linux/blob/v6.18/include/linux/elfcore.h)、[user_64.h](https://github.com/torvalds/linux/blob/v6.18/arch/x86/include/asm/user_64.h) 和 [siginfo.h](https://github.com/torvalds/linux/blob/v6.18/include/uapi/asm-generic/siginfo.h)。只参考格式/ABI事实，未复制 APSL/GPL 解析器实现；128-bit 数值保留原始字节和值，不模拟 Foundation 的截位行为。NIBArchive 是上游审阅的受限格式 profile，不声明为 Apple 官方完整规范。
- PawanOsman/ChatGPT 旧代理固定对象 `46043c685100e9d6d22501b39a196d3b6762878a`（AGPL-3.0）；旧链接现跳到 OpenCursor，其当前 HEAD `b4528f95ca5ab4cddf22bef3e19431fad00feb01` 单独记录，不作为旧代理来源。
- acheong08/ChatGPT：`9167b325addc7d3520987face684e8230bd62b46`（已归档、GPL-2.0）。只吸收历史协议研究方法，未证明旧 endpoint/auth 当前可用。
- lininn/codex-proxy：`4e30ee7f0f7932a113934d38f718ac5d4189fb64`（MIT）。xblanc33/CodexProxy：`368bd7f49497395fd910858d37ab2e4e9c7f18fc`（package 声明 ISC、无独立 LICENSE）。两者是根据逆向用途选择的 `coddexproxy` 研究候选，未复制实现；SSE 使用 RR 原创 Go 实现及 WHATWG 公开 framing 规则，施工/核销记录为 UP01–UP03。

被采纳的模式与不采纳的边界记录在 `skills/seep-reverse-lab/references/upstream.md`。ReverseResearch 本地的安全性/当前性归属方具有优先权。

WF15 的包路径关系参考固定 REA `fa87dd2aac3eaeb49875c54e93ec18c98cc92e4d`
中的 `JavaScriptArtifactPathResolution.ts` 与 `javascriptPackageImportAliases.ts`，
以及 Node 官方 [packages](https://nodejs.org/download/release/v22.15.0/docs/api/packages.html)
和 [ESM resolver](https://nodejs.org/download/release/v22.15.0/docs/api/esm.html) 算法说明。
Go 实现沿 RR 原 artifact/strict-JSON owner 编写，没有复制 Node loader 或增加 Node 产品依赖。
固定 builtin 名称数据来自本机 Node v24.19.0 的 `module.builtinModules` 观察；同一版本的
`import.meta.resolve` / `createRequire().resolve` 仅在独立测试 producer 中运行，未加载任何被分析模块。

## 冒烟测试夹具

WF16 参考同一固定 REA 的 `javascriptStaticAnalysisBundler.ts` 与 `javascriptBootstrap.ts`，
沿 RR 原 AST/facts/comparison/application owner 实现静态模块恢复，未移植 Babel/Node 产品栈。
`patches/javascript-parser` 保留固定 `github.com/tdewolff/parse/v2@v2.8.16` 的
root/buffer/js 源码、MIT LICENSE、逐文件上游 SHA 与范围 API 最小补丁；根 go.mod 的
replace 是唯一编译 parser 来源。范围对应原始 UTF-8 字节，结构化呈现哈希明确使用
`tdewolff-js-render-v1`，不声称与 REA 的 `babel-ast-v1` 兼容。
独立 producer 使用 Webpack 5.102.1 / esbuild 0.25.10 编译三份惰性 CJS 源码；
脚本、输入、模块 ID、输出 SHA 与小型生成夹具位于 `internal/appinspect/testfixture/bundler-producer.cjs`
及 `internal/appinspect/testdata/bundlers/`。只有验证使用临时 Node packages，输出未执行。

- `testdata/mcp-smoke.exe`
- 大小：2560 bytes
- SHA-256：`b5f4cffdc8864c57a400831c6555880515f24bc9aa38ac08538683dead45f840`

该夹具是一个本地小型测试可执行文件，仅用于后端集成检查。
