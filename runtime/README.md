# Runtime

runtime/ is the ignored deployment/runtime dependency tree. It contains third-party engines and their retained adapters, not project source code or build workspaces.

## Layout

- die/ - Detect It Easy 3.21 Windows x64 portable runtime. Canonical CLI: diec.exe.
- ghidra/app/ - Ghidra distribution.
- ghidra/java/ - Java runtime used by Ghidra.
- ghidra/python-packages/ - retained Python-side MCP/Ghidra packages. Windows uses MSYS2 UCRT64 CPython 3.14 with UCRT64 system-site first on PYTHONPATH. The native Linux profile uses CPython 3.13 in ghidra/python-env/bin/python and one native wheel bundle here, including JPype; Windows binaries and extension modules cannot satisfy that profile.
- ghidra/java/native/ - native Linux JDK profile with executable bin/java and bin/javac. The verified Ghidra 12.1.4 distribution uses JDK21; a JRE alone is refused before backend startup.
- android/jadx-headless/0.7.1/ - pinned offline jadx-headless-mcp-0.7.1-all.jar (SHA256 6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75). This is an interpreted engine artifact, not a native executable. Tracked patches/jadx owns the MIT metadata bridge; the shared full JDK21 and original backend lifecycle run it. ToolIndex publishes four artifact/interpreter identities and runtime-profile-present; actual startup/analysis/native cleanup are separate evidence. Analysis never downloads a missing runtime.
- radare2/engine/ - radare2 distribution.
- radare2/mcp/ - deployable r2mcp binaries only; Windows retains r2mcp.exe, r2mcp-svc.exe and libcore_r2mcp.dll. Native Linux discovery also accepts r2mcp or the extracted package path usr/local/bin/r2mcp; engine/usr/bin and engine/usr/lib retain the corresponding native radare2 files. Meson/Ninja intermediates do not belong here.
- x32dbg/release/ - x32dbg/x64dbg runtime and MCP plugin payload.
- x32dbg/commithash.txt - pinned upstream build identity.
- network-lab/debian/ - the single reusable WSL2 Debian network-lab disk. Source and profiles live under tools/network-lab; receipts/state live under evidence/network-lab and state/network-lab. Scenarios reuse network namespaces, never copies of this disk or games. The Microsoft WSL system component is managed by its official Windows installer.

## Ownership rules

- Large runtime bytes are intentionally ignored by Git; only this README is tracked.
- Version-controlled ReverseResearch patches live under patches/, not here.
- internal/backend synchronizes the tracked Ghidra overlays into ghidra/python-packages/ before backend startup. Therefore an identical file under patches/ghidra and runtime/ghidra/python-packages is intentional source/deployment duplication.
- Python bytecode caches, editor metadata, SDKs, compiler import libraries, Meson/Ninja build trees/packages, help-only artifacts, and other build intermediates must not be retained in runtime/. UCRT64-shadowed Python package duplicates are also removed after isolated Ghidra smoke verification.
- Runtime-generated mutable data belongs under state/ or evidence/, never under this directory.

Native Linux backends require delegated cgroup v2, clone-into-cgroup support and cgroup.kill. The original backend owner contains the process before exec and verifies the group is empty on close. Missing containment support fails before starting the backend; static Core/CLI/MCP reads remain usable. Windows retains Job-object cleanup; x32/x64dbg requires Windows. Other hosts do not receive a fake successful process-tree implementation.

DiE is pinned to the official horsicq/DIE-engine 3.21 release under the MIT license. The retained Windows x64 archive identity documented by the project is SHA-256 078f2934f267392247f9c7b759a1c2457a48bc2000b25b80c2f129955ee4a3b9; the extracted diec.exe SHA-256 is dda171a904f6dc3a2c414e99e9d718c8d7500bc26c3dcdc1a72ec0e7d718cfe7.
