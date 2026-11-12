param([string]$Executable)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if ([string]::IsNullOrWhiteSpace($Executable)) {
    $Executable = Join-Path $repo '.tmp\record-closeout\ReverseResearch.exe'
}
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$originalExe = Join-Path $repo 'ReverseResearch.exe'
$originalHash = if (Test-Path -LiteralPath $originalExe) { (Get-FileHash -LiteralPath $originalExe -Algorithm SHA256).Hash } else { '' }
if ($Executable -eq $originalExe) { throw 'Use an isolated candidate build, not the live executable.' }
$scratch = Join-Path $repo ('.tmp\record-closeout\smoke-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
Copy-Item -LiteralPath (Join-Path $repo 'config') -Destination (Join-Path $scratch 'config') -Recurse
Copy-Item -LiteralPath (Join-Path $repo 'skills') -Destination (Join-Path $scratch 'skills') -Recurse
$workers = @()
$pointerFixtures = @()
$checks = New-Object System.Collections.Generic.List[string]
$savedToolRoots = $env:REVERSERESEARCH_TOOLS
$radare2Exe = Get-ChildItem -LiteralPath (Join-Path $repo 'runtime\radare2\engine') -Recurse -File -Filter 'radare2.exe' -ErrorAction Stop | Select-Object -First 1
if ($null -eq $radare2Exe) { throw 'Bundled radare2.exe was not found for isolated hook smoke.' }
$smokeToolRoots = @($radare2Exe.DirectoryName)
if (-not [string]::IsNullOrWhiteSpace($savedToolRoots)) {
    $smokeToolRoots += @($savedToolRoots -split [IO.Path]::PathSeparator | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}
$env:REVERSERESEARCH_TOOLS = (@($smokeToolRoots | Select-Object -Unique) -join [IO.Path]::PathSeparator)
$rootStateGuardNames = @('hooks','patches','compatibility','research','knowledge','sandboxes')

function Assert-Check([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAILED: ' + $Name) }
    $checks.Add($Name)
}

function Get-GuardedRootStateSnapshot {
    $entries = New-Object System.Collections.Generic.List[string]
    foreach ($name in $rootStateGuardNames) {
        $dir = Join-Path (Join-Path $repo 'state') $name
        if (-not (Test-Path -LiteralPath $dir)) {
            $entries.Add(('missing|' + $name))
            continue
        }
        foreach ($file in @(Get-ChildItem -LiteralPath $dir -Recurse -Force -File -ErrorAction SilentlyContinue | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($repo.Length + 1)
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $entries.Add(($relative + '|' + $file.Length + '|' + $hash))
        }
    }
    return (@($entries | Sort-Object) -join "`n")
}

$rootStateBefore = Get-GuardedRootStateSnapshot
$smokeSucceeded = $false

function Invoke-RR {
    param([string[]]$CLIArgs, [int]$ExpectedExit = 0, [switch]$Raw)
    $errorFile = Join-Path $scratch ('stderr-' + [guid]::NewGuid().ToString('N') + '.txt')
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Executable @CLIArgs 2> $errorFile)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    $text = $lines -join "`n"
    if ($code -ne $ExpectedExit) {
        $detail = Get-Content -LiteralPath $errorFile -Raw
        throw ('Unexpected CLI exit ' + $code + ' for ' + ($CLIArgs -join ' ') + ': ' + $detail)
    }
    if ($Raw) { return $text }
    return ConvertFrom-Json -InputObject $text
}

function Start-PointerFixture([string]$Path) {
    $process = New-Object Diagnostics.Process
    $process.StartInfo.FileName = $Path
    $process.StartInfo.WorkingDirectory = $scratch
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.RedirectStandardInput = $true
    if (-not $process.Start()) { throw 'Could not start pointer fixture.' }
    $line = $process.StandardOutput.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) {
        $detail = $process.StandardError.ReadToEnd()
        if (-not $process.HasExited) { $process.Kill() }
        throw ('Pointer fixture emitted no metadata: ' + $detail)
    }
    $record = [pscustomobject]@{ Process = $process; Info = (ConvertFrom-Json -InputObject $line) }
    $script:pointerFixtures += $record
    return $record
}

function Stop-PointerFixture($Fixture) {
    if ($null -eq $Fixture -or $null -eq $Fixture.Process -or $Fixture.Process.HasExited) { return }
    try {
        $Fixture.Process.StandardInput.WriteLine('stop')
        $Fixture.Process.StandardInput.Flush()
    } catch {}
    if (-not $Fixture.Process.WaitForExit(5000)) {
        $Fixture.Process.Kill()
        $null = $Fixture.Process.WaitForExit(3000)
    }
}

Push-Location $scratch
try {
    $help = Invoke-RR -CLIArgs @() -Raw
    Assert-Check ($help.Contains('Usage:')) 'no-argument invocation prints help without serving'
    $module = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($module.backends).Count -eq 3 -and @($module.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'local module status starts no backend'
    $contract = Invoke-RR -CLIArgs @('contract', 'audit')
    Assert-Check ($contract.match -and $contract.rr_tool_count -eq 124 -and $contract.rt_tool_count -eq 124 -and $contract.local_base_tool_count -eq 124) 'online RR and RT backend contracts match the retained local base catalog'

    $prepared = Invoke-RR -CLIArgs @('prepare', 'analyze', 'this', 'Android', 'APK', 'DEX', 'with', 'JADX')
    Assert-Check ($prepared.route.route.id -eq 'android' -and $prepared.playbook.id -eq 'android' -and $prepared.playbook.skill_path -eq 'skills/seep-reverse-lab/SKILL.md' -and $prepared.playbook.reference_path -eq 'skills/seep-reverse-lab/references/android.md' -and @($prepared.playbook.gates).Count -ge 4) 'task prepare joins canonical route with the Android Seep playbook without starting a backend'
    $webPlaybook = Invoke-RR -CLIArgs @('playbook', 'route', 'js-web')
    Assert-Check ($webPlaybook.id -eq 'js-web' -and $webPlaybook.reference_path -eq 'skills/seep-reverse-lab/references/web.md') 'playbook route resolves the Web reference through the validated playbook owner'
    $unknownPrepared = Invoke-RR -CLIArgs @('prepare', 'unclassified-object-zzqv')
    Assert-Check ($unknownPrepared.route.route.id -eq 'unclassified' -and $null -eq $unknownPrepared.playbook) 'unmatched work remains unclassified instead of force-fitting a platform playbook'
    $moduleAfterPrepare = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($moduleAfterPrepare.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'route prepare and playbook lookup start no analysis or debugger backend'

    $identityPrepared = Invoke-RR -CLIArgs @('prepare', 'analyze', 'this', 'BloodHound', 'Active', 'Directory', 'attack', 'path')
    Assert-Check ($identityPrepared.route.route.id -eq 'identity-ad' -and $identityPrepared.playbook.id -eq 'identity-ad' -and $identityPrepared.playbook.skill_path -eq 'skills/seep-identity/SKILL.md') 'P2 identity routing resolves the specialist playbook without starting a backend'

    $p2GraphPath = Join-Path $scratch 'p2-attack-graph.json'
    [IO.File]::WriteAllText($p2GraphPath, '{"source_kind":"candidate-smoke","nodes":[{"id":"user:a","kind":"identity"},{"id":"host:1","kind":"host"}],"edges":[{"from":"user:a","to":"host:1","kind":"admin-of"}]}', (New-Object Text.UTF8Encoding($false)))
    $p2Graph = Invoke-RR -CLIArgs @('attackgraph', 'import', $p2GraphPath, '--from', 'user:a', '--to', 'host:1')
    Assert-Check ($p2Graph.graph.sha256.Length -eq 64 -and $p2Graph.path.found -and @($p2Graph.path.edges).Count -eq 1) 'P2 attack graph import is content-addressed and computes only an observation-side candidate path'

    $p2CloudPath = Join-Path $scratch 'p2-cloud-inventory.json'
    [IO.File]::WriteAllText($p2CloudPath, '{"provider":"aws","scope_id":"candidate-smoke","resources":[{"id":"role:app","type":"iam-role","name":"app"},{"id":"bucket:data","type":"s3-bucket","name":"data","public":true}],"relationships":[{"from":"role:app","to":"bucket:data","kind":"can-access"}]}', (New-Object Text.UTF8Encoding($false)))
    $p2Cloud = Invoke-RR -CLIArgs @('cloud', 'inventory', $p2CloudPath)
    Assert-Check ($p2Cloud.report.read_only -and $p2Cloud.report.provider -eq 'aws' -and @($p2Cloud.report.resources).Count -eq 2 -and $p2Cloud.report.graph.sha256.Length -eq 64) 'P2 cloud inventory import remains offline/read-only and produces a canonical graph'

    $p2StixPath = Join-Path $scratch 'p2-stix.json'
    [IO.File]::WriteAllText($p2StixPath, '{"type":"bundle","id":"bundle--candidate-smoke","objects":[{"type":"malware","id":"malware--1","name":"demo"},{"type":"indicator","id":"indicator--1","pattern":"[file:name = ''demo'']"},{"type":"relationship","id":"relationship--1","relationship_type":"indicates","source_ref":"indicator--1","target_ref":"malware--1"}]}', (New-Object Text.UTF8Encoding($false)))
    $p2Stix = Invoke-RR -CLIArgs @('cti', 'import', $p2StixPath)
    Assert-Check (@($p2Stix.report.objects).Count -eq 2 -and @($p2Stix.report.relationships).Count -eq 1) 'P2 CTI import parses bounded local STIX without external synchronization'

    $p2Hunt = Invoke-RR -CLIArgs @('hunt', 'plan', '--hypothesis', 'scheduled-task-persistence', '--telemetry', 'Sysmon,EDR', '--techniques', 'T1053', '--adapters', 'sigma,osquery')
    Assert-Check (-not $p2Hunt.plan.execution_performed -and @($p2Hunt.plan.telemetry).Count -eq 2) 'P2 threat hunt remains plan-only with explicit telemetry'

    $p2IPARoot = Join-Path $scratch 'p2-ipa-root'
    $p2AppDir = Join-Path $p2IPARoot 'Payload\Demo.app'
    $null = New-Item -ItemType Directory -Path $p2AppDir -Force
    [IO.File]::WriteAllText((Join-Path $p2AppDir 'Info.plist'), 'plist', (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllBytes((Join-Path $p2AppDir 'Demo'), [byte[]](0xcf,0xfa,0xed,0xfe,0))
    $p2IPAPath = Join-Path $scratch 'p2-demo.ipa'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($p2IPARoot, $p2IPAPath)
    $p2IOS = Invoke-RR -CLIArgs @('ios', 'inspect', $p2IPAPath)
    Assert-Check ($p2IOS.report.read_only -and @($p2IOS.report.app_roots).Count -eq 1 -and @($p2IOS.report.macho_candidates).Count -eq 1) 'P2 iOS inspection remains static/read-only and inventories the IPA Mach-O candidate'

    $p2FirmwarePath = Join-Path $scratch 'p2-firmware.bin'
    [IO.File]::WriteAllBytes($p2FirmwarePath, [byte[]](0x68,0x73,0x71,0x73,0,0,0,0))
    $p2Firmware = Invoke-RR -CLIArgs @('firmware', 'inspect', $p2FirmwarePath)
    Assert-Check ($p2Firmware.report.read_only -and $p2Firmware.report.format -eq 'squashfs') 'P2 firmware inspection classifies the immutable image without extraction or execution'

    $moduleAfterP2 = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($moduleAfterP2.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'P2 import inspect and plan flows start no analysis or debugger backend'

    $webBackends = Invoke-RR -CLIArgs @('web', 'backends')
    Assert-Check (@($webBackends.backends).Count -eq 2 -and @($webBackends.backends | Where-Object { $_.integration_policy -notmatch 'installed-only' -or $_.redistribution_allowed }).Count -eq 0) 'Web backend inventory is installed-only and non-redistributed'
    $webJS = Join-Path $scratch 'web-smoke.js'
    $webMap = Join-Path $scratch 'web-smoke.js.map'
    [IO.File]::WriteAllText($webMap, '{"version":3,"file":"web-smoke.js","sources":["src/smoke.ts"],"names":[],"mappings":"AAAA","sourcesContent":["const x=1;"]}', (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($webJS, "console.log(1);`n//# sourceMappingURL=web-smoke.js.map`n", (New-Object Text.UTF8Encoding($false)))
    $webSource = Invoke-RR -CLIArgs @('web', 'source', $webJS)
    Assert-Check ($webSource.sha256.Length -eq 64 -and $webSource.source_map.version -eq 3 -and $webSource.source_map.embedded_source_count -eq 1) 'Web local SourceMap v3 is identity-bound without remote fetch or execution'
    $webWasm = Join-Path $scratch 'web-smoke.wasm'
    [IO.File]::WriteAllBytes($webWasm, [byte[]](0,97,115,109,1,0,0,0,7,7,1,3,114,117,110,0,0))
    $wasm = Invoke-RR -CLIArgs @('web', 'wasm', $webWasm)
    Assert-Check ($wasm.version -eq 1 -and @($wasm.exports).Count -eq 1 -and $wasm.exports[0].name -eq 'run') 'Web WASM inspection remains static and bounded'
    $androidStatus = Invoke-RR -CLIArgs @('android', 'status')
    Assert-Check ($androidStatus.adb.name -eq 'adb' -and $androidStatus.frida.name -eq 'frida') 'Android runtime status reports optional adb/frida truth without requiring a device'
    $androidWorkspace = Invoke-RR -CLIArgs @('android', 'workspace', 'smoke-device-serial')
    Assert-Check ($androidWorkspace.device_sha256.Length -eq 64 -and $androidWorkspace.device_authorization_required -and (Split-Path -Leaf $androidWorkspace.certificate_path) -eq 'certificates') 'Android per-device workspace hashes the serial and isolates certificate/evidence/operation state'

    $null = Invoke-RR -CLIArgs @('x32dbg', 'WriteMemToAddress', '--json', '{"address":"401000","byteString":"90"}') -ExpectedExit 1 -Raw
    Assert-Check $true 'unguarded x32dbg mutation is rejected before backend startup'
    $null = Invoke-RR -CLIArgs @('x32dbg', 'ExecuteDebuggerCommand', '--json', '{"command":"attach 99"}') -ExpectedExit 1 -Raw
    Assert-Check $true 'generic x32dbg command is blocked by guarded mutation boundary'
    $moduleAfterGuard = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($moduleAfterGuard.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'x32dbg guard rejection starts no backend'
    $die = Invoke-RR -CLIArgs @('die', 'scan', $Executable, '--verbose', '--timeout', '15s')
    Assert-Check ($die.tool.version -eq '3.21' -and $die.tool.sha256.Length -eq 64 -and @($die.detects).Count -gt 0) 'pinned DiE 3.21 returns structured static detections'

    $processIdentity = Invoke-RR -CLIArgs @('process', 'inspect', [string]$PID)
    Assert-Check ($processIdentity.key.Length -eq 64 -and $processIdentity.creation_utc -ne '' -and $processIdentity.main_module_base -ne 0 -and $processIdentity.image.sha256.Length -eq 64) 'live process identity binds creation base and executable hash'
    Assert-Check ($processIdentity.image.format -eq 'pe' -and $processIdentity.image.pe.machine -eq 'amd64' -and $processIdentity.image.pe.bits -eq 64) 'current PowerShell host is a 64-bit amd64 PE process'
    $debugRoute = Invoke-RR -CLIArgs @('process', 'debug-route', [string]$PID)
    Assert-Check ($debugRoute.process_key -eq $processIdentity.key -and $debugRoute.format -eq 'pe' -and $debugRoute.machine -eq 'amd64' -and $debugRoute.bits -eq 64 -and $debugRoute.architecture -eq 'x86-64' -and $debugRoute.backend -eq 'x64dbg' -and $debugRoute.public_module -eq 'x32dbg' -and -not $debugRoute.attach_performed) '64-bit process route preview selects x64dbg without attaching'
    $moduleAfterRoute = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($moduleAfterRoute.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'process debug-route preview starts no debugger backend'
    $scanStart = [UInt64]$processIdentity.main_module_base
    $scanEnd = $scanStart + 4096
    $memoryScan = Invoke-RR -CLIArgs @('memory', 'scan', [string]$PID, '--key', $processIdentity.key, '--type', 'u32', '--unknown', '--start', [string]$scanStart, '--end', [string]$scanEnd, '--max-bytes', '4096', '--max-candidates', '2048', '--timeout', '3s')
    Assert-Check ($memoryScan.version -eq 1 -and $memoryScan.process.key -eq $processIdentity.key -and $memoryScan.candidate_count -gt 0 -and $memoryScan.coverage_complete -and $memoryScan.step_complete) 'bounded unknown-value memory scan persists a complete candidate set'
    Assert-Check ($memoryScan.candidate_sample[0].region.region_size -gt 0 -and $memoryScan.candidate_sample[0].raw_hex.Length -eq 8) 'memory candidates bind raw u32 values to region identity'
    $memoryRefined = Invoke-RR -CLIArgs @('memory', 'refine', $memoryScan.id, '--expected-version', '1', '--mode', 'unchanged', '--timeout', '3s')
    Assert-Check ($memoryRefined.version -eq 2 -and $memoryRefined.candidate_count -gt 0 -and $memoryRefined.step_complete -and $memoryRefined.last_mode -eq 'unchanged') 'memory scan refinement advances the versioned unchanged candidate set'
    $memoryRead = Invoke-RR -CLIArgs @('memory', 'get', $memoryScan.id, '--sample', '4')
    Assert-Check ($memoryRead.version -eq 2 -and $memoryRead.candidate_count -eq $memoryRefined.candidate_count -and @($memoryRead.candidate_sample).Count -le 4) 'memory scan get returns the persisted refined candidate set'
    $moduleAfterMemory = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($moduleAfterMemory.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'direct memory scan and refinement start no debugger backend'

    $pointerFixtureExe = Join-Path $scratch 'pointer-fixture.exe'
    $pointerBuildOutput = @(& go -C $repo build -o $pointerFixtureExe ./tools/fixtures/pointer 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ('Could not build pointer fixture: ' + ($pointerBuildOutput -join ' | ')) }
    $fixtureA = Start-PointerFixture $pointerFixtureExe
    $fixtureAIdentity = Invoke-RR -CLIArgs @('process', 'inspect', [string]$fixtureA.Process.Id)
    Assert-Check ($fixtureAIdentity.key.Length -eq 64 -and $fixtureA.Info.pid -eq $fixtureA.Process.Id) 'pointer fixture A has a fresh process identity'
    $pointerMap = Invoke-RR -CLIArgs @(
        'pointer', 'scan', [string]$fixtureA.Process.Id,
        '--key', $fixtureAIdentity.key,
        '--target', [string]$fixtureA.Info.target_address,
        '--start', [string]$fixtureA.Info.scan_start,
        '--end', [string]$fixtureA.Info.scan_end,
        '--max-offset', '64',
        '--max-depth', '2',
        '--max-bytes', '1048576',
        '--max-nodes', '4096',
        '--max-chains', '1024',
        '--timeout', '5s'
    )
    Assert-Check ($pointerMap.version -eq 1 -and $pointerMap.source_process.key -eq $fixtureAIdentity.key -and $pointerMap.pointer_size -eq 8 -and $pointerMap.chain_count -gt 0 -and $pointerMap.coverage_complete) 'pointer map persists bounded module-anchored candidates'
    $pointerMapRead = Invoke-RR -CLIArgs @('pointer', 'get', $pointerMap.id, '--sample', '200')
    $depthTwoA = @($pointerMapRead.chain_sample | Where-Object { $_.depth -eq 2 -and $_.source_root_address -eq $fixtureA.Info.root_slot_address -and $_.offsets[0] -eq 16 -and $_.offsets[1] -eq 32 })
    Assert-Check ($depthTwoA.Count -eq 1 -and $depthTwoA[0].anchor.module_sha256.Length -eq 64 -and $depthTwoA[0].anchor.rva -gt 0) 'pointer map recovers the exact fixture depth-two chain with a module RVA anchor'
    $fixtureRootRva = [UInt64]$depthTwoA[0].anchor.rva
    Stop-PointerFixture $fixtureA

    $fixtureB = Start-PointerFixture $pointerFixtureExe
    $fixtureBIdentity = Invoke-RR -CLIArgs @('process', 'inspect', [string]$fixtureB.Process.Id)
    Assert-Check ($fixtureBIdentity.key.Length -eq 64 -and $fixtureBIdentity.key -ne $fixtureAIdentity.key) 'pointer fixture restart produces a distinct process identity'
    $pointerVerify = Invoke-RR -CLIArgs @(
        'pointer', 'verify', $pointerMap.id,
        '--pid', [string]$fixtureB.Process.Id,
        '--key', $fixtureBIdentity.key,
        '--target', [string]$fixtureB.Info.target_address,
        '--timeout', '5s',
        '--sample', '200'
    )
    Assert-Check ($pointerVerify.complete -and $pointerVerify.cross_process -and $pointerVerify.valid_chains -gt 0) 'pointer map verifies valid chains across a fresh process instance'
    $depthTwoB = @($pointerVerify.chain_sample | Where-Object { $_.depth -eq 2 -and $_.anchor.rva -eq $fixtureRootRva -and $_.valid -and $_.target_match })
    Assert-Check ($depthTwoB.Count -eq 1 -and $depthTwoB[0].current_root_address -eq $fixtureB.Info.root_slot_address -and $depthTwoB[0].steps[0].offset -eq 16 -and $depthTwoB[0].steps[1].offset -eq 32) 'rebased exact fixture depth-two pointer chain resolves the restarted target'
    $null = Invoke-RR -CLIArgs @('pointer', 'verify', $pointerMap.id, '--pid', [string]$fixtureB.Process.Id, '--key', $fixtureAIdentity.key, '--target', [string]$fixtureB.Info.target_address) -ExpectedExit 1 -Raw
    Assert-Check $true 'pointer verification rejects a stale source process key against the restarted process'
    $moduleAfterPointer = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($moduleAfterPointer.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'pointer mapping and cross-process verification start no debugger backend'
    Stop-PointerFixture $fixtureB

    $lease = Invoke-RR -CLIArgs @('process', 'acquire', [string]$PID, '--key', $processIdentity.key, '--owner', 'smoke-owner')
    $leaseReplay = Invoke-RR -CLIArgs @('process', 'acquire', [string]$PID, '--key', $processIdentity.key, '--owner', 'smoke-owner')
    Assert-Check ($lease.lease_id -ne '' -and $leaseReplay.lease_id -eq $lease.lease_id) 'process control acquisition is idempotent for the same owner'
    $leaseRead = Invoke-RR -CLIArgs @('process', 'get', [string]$PID)
    Assert-Check ($leaseRead.lease_id -eq $lease.lease_id -and $leaseRead.process_key -eq $processIdentity.key) 'process control get revalidates the same process instance'
    $null = Invoke-RR -CLIArgs @('process', 'release', [string]$PID, '--key', $processIdentity.key, '--owner', 'smoke-owner', '--lease-id', $lease.lease_id)
    $null = Invoke-RR -CLIArgs @('process', 'get', [string]$PID) -ExpectedExit 1 -Raw
    Assert-Check $true 'released process control lease is no longer readable'


    $hookFixture = Join-Path $scratch 'hook-fixture.exe'
    Copy-Item -LiteralPath (Join-Path $repo 'testdata\mcp-smoke.exe') -Destination $hookFixture
    $hookOriginalHash = (Get-FileHash -LiteralPath $hookFixture -Algorithm SHA256).Hash
    $hookPlan = Invoke-RR -CLIArgs @(
            'hook', 'plan',
            '--path', $hookFixture,
            '--source-rva', '0x1000',
            '--destination-rva', '0x1030',
            '--expected', '6A05E829000000',
            '--description', 'candidate smoke entry detour'
    )
    Assert-Check ($hookPlan.state -eq 'planned' -and $hookPlan.version -eq 1 -and $hookPlan.overwrite_size -eq 7 -and @($hookPlan.instructions).Count -eq 2 -and $hookPlan.relocation -eq 'same-module-rva-rel32') 'hook plan proves whole instruction boundaries and rel32 relocation'

        $hookRead = Invoke-RR -CLIArgs @('hook', 'get', $hookPlan.id)
        $hookList = @(Invoke-RR -CLIArgs @('hook', 'list', '--path', $hookFixture))
        Assert-Check ($hookRead.id -eq $hookPlan.id -and @($hookList | Where-Object { $_.id -eq $hookPlan.id }).Count -eq 1) 'hook get/list recover the persisted interval'

        $hookBefore = Invoke-RR -CLIArgs @('hook', 'verify', $hookPlan.id)
        Assert-Check ($hookBefore.structure_match -and $hookBefore.current_state -eq 'original' -and $hookBefore.matches_expected_state) 'planned hook verifies exact frozen original bytes'

        $hookApplied = Invoke-RR -CLIArgs @('hook', 'apply', $hookPlan.id, '--expected-version', '1', '--operation-id', 'smoke-hook-apply', '--confirm-in-place')
        $hookReplay = Invoke-RR -CLIArgs @('hook', 'apply', $hookPlan.id, '--expected-version', '1', '--operation-id', 'smoke-hook-apply', '--confirm-in-place')
        Assert-Check ($hookApplied.state -eq 'applied' -and $hookApplied.version -eq 3 -and $hookReplay.version -eq $hookApplied.version) 'hook apply is versioned and same-operation replay safe'
        $hookAfterApply = Invoke-RR -CLIArgs @('hook', 'verify', $hookPlan.id)
        Assert-Check ($hookAfterApply.current_state -eq 'patch' -and $hookAfterApply.matches_expected_state) 'hook verify sees the exact applied detour bytes'

        $null = Invoke-RR -CLIArgs @('hook', 'plan', '--path', $hookFixture, '--source-rva', '0x1002', '--destination-rva', '0x1030') -ExpectedExit 1 -Raw
        Assert-Check $true 'active hook interval rejects an overlapping whole-instruction detour'
        $null = Invoke-RR -CLIArgs @('hook', 'plan', '--path', $hookFixture, '--source-rva', '0x1000', '--destination-rva', '0x1030', '--expected', '90 90 90 90 90 90 90') -ExpectedExit 1 -Raw
        Assert-Check $true 'hook plan rejects wrong original bytes'

        $hookRolledBack = Invoke-RR -CLIArgs @('hook', 'rollback', $hookPlan.id, '--expected-version', [string]$hookApplied.version, '--operation-id', 'smoke-hook-rollback')
        $hookRollbackReplay = Invoke-RR -CLIArgs @('hook', 'rollback', $hookPlan.id, '--expected-version', [string]$hookApplied.version, '--operation-id', 'smoke-hook-rollback')
        Assert-Check ($hookRolledBack.state -eq 'rolled_back' -and $hookRolledBack.version -eq 5 -and $hookRollbackReplay.version -eq $hookRolledBack.version) 'hook rollback is versioned and same-operation replay safe'
    Assert-Check ((Get-FileHash -LiteralPath $hookFixture -Algorithm SHA256).Hash -eq $hookOriginalHash) 'hook rollback restores the exact original fixture'

    $compat = Invoke-RR -CLIArgs @(
        'compat', 'add',
        '--game', 'Smoke Fixture',
        '--build', '1.0',
        '--module', $hookFixture,
        '--role', 'test-module',
        '--outcome', 'candidate',
        '--validation', 'record-only',
        '--notes', 'candidate smoke compatibility record only'
    )
    Assert-Check ($compat.id -ne '' -and $compat.outcome -eq 'candidate' -and $compat.validation -eq 'record-only' -and $compat.module.sha256.Length -eq 64) 'compatibility add binds an exact module identity without claiming compatibility'
    $compatRead = Invoke-RR -CLIArgs @('compat', 'get', $compat.id)
    Assert-Check ($compatRead.id -eq $compat.id -and $compatRead.module.sha256 -eq $compat.module.sha256) 'compatibility get returns the immutable module-bound record'
    $compatList = @(Invoke-RR -CLIArgs @('compat', 'list', '--game', 'Smoke Fixture', '--build', '1.0'))
    Assert-Check (@($compatList | Where-Object { $_.id -eq $compat.id }).Count -eq 1) 'compatibility list filters the persisted record'
    $compatVerify = Invoke-RR -CLIArgs @('compat', 'verify', $compat.id)
    Assert-Check ($compatVerify.record_valid -and $compatVerify.source_current -and -not $compatVerify.compatibility_revalidated) 'compatibility verify checks current bindings without rerunning or upgrading compatibility'
    $null = Invoke-RR -CLIArgs @('compat', 'add', '--game', 'Smoke Fixture', '--build', '1.0', '--module', $hookFixture, '--outcome', 'compatible', '--validation', 'record-only') -ExpectedExit 1 -Raw
    Assert-Check $true 'compatibility rejects a compatible outcome without runtime-verified case evidence'
    $moduleAfterCompat = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($moduleAfterCompat.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'compatibility record workflows start no analysis or debugger backend'

    $syncRequestPath = Join-Path $scratch 'semantic-sync-preview.json'
    $syncRequest = @{
        migration = @{
            entries = @(@{
                label = 'unit-update'
                status = 'mapped'
                old_rva = 4096
                new_rva = 8192
            })
        }
        source = @{
            functions = @(@{
                rva = 4096
                name = 'UpdateUnit'
                name_origin = 'user'
                comments = @(@{ kind = 'plate'; text = 'source note' })
            })
        }
        target = @{
            functions = @(@{
                rva = 8192
                name = 'ManualUpdateUnit'
                name_origin = 'user'
                comments = @(@{ kind = 'plate'; text = 'target note' })
            })
        }
    } | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($syncRequestPath, $syncRequest, [Text.UTF8Encoding]::new($false))
    $syncPreview = Invoke-RR -CLIArgs @('sync', 'preview', '--json-file', $syncRequestPath)
    Assert-Check ($syncPreview.validation -eq 'preview-only' -and -not $syncPreview.runtime_verified -and -not $syncPreview.writes_performed -and $syncPreview.preserved -eq 1 -and $syncPreview.conflicts -eq 1 -and $syncPreview.suggested -eq 0) 'semantic sync preview preserves target user names and reports comment conflicts without writes'
    $moduleAfterSync = Invoke-RR -CLIArgs @('module', 'status')
    Assert-Check (@($moduleAfterSync.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'semantic sync preview starts no Ghidra or debugger backend'

    $name = 'sample ' + [char]0x4E2D + [char]0x6587 + [char]0xFF08 + 'test' + [char]0xFF09 + '.bin'
    $source = Join-Path $scratch $name
    $original = [byte[]](0x10, 0x20, 0x30, 0x40)
    [IO.File]::WriteAllBytes($source, $original)
    $identity = Invoke-RR -CLIArgs @('target', 'identify', $source)
    Assert-Check ($identity.sha256.Length -eq 64 -and $identity.size -eq 4) 'Unicode parentheses and spaces survive native CLI arguments'

    $case = Invoke-RR -CLIArgs @('case', 'create', '--title', 'CLI record closeout', '--route', 'binary-diff')
    $evidence = Invoke-RR -CLIArgs @('case', 'evidence', $case.id, '--summary', 'bound fixture bytes', '--source', $source)
    $finding = Invoke-RR -CLIArgs @('case', 'finding', $case.id, '--title', 'fixture finding', '--conclusion', 'fixture only, not a game function', '--strength', 'observed', '--evidence', $evidence.id)
    Assert-Check ($finding.strength -eq 'observed') 'case finding persists explicit observed/inferred/unverified evidence strength separately from confidence'
    $null = Invoke-RR -CLIArgs @('case', 'path', $case.id, '--title', 'fixture path', '--details', 'input -> fixture -> record', '--findings', $finding.id)
    $verified = Invoke-RR -CLIArgs @('case', 'verify', $case.id)
    Assert-Check ($verified.valid -and $verified.evidence_checked -eq 1 -and $verified.ungraded_findings -eq 0) 'separate CLI invocations persist the complete graded evidence chain'
    $listed = @(Invoke-RR -CLIArgs @('case', 'list', '--limit', '1'))
    Assert-Check ($listed.Count -eq 1 -and $listed[0].id -eq $case.id) 'case IDs can be recovered by list'

    $note = Invoke-RR -CLIArgs @('journal', 'add', '--title', 'record-closeout knowledge', '--body', "first`nsecond`nthird", '--domain', 'native-static', '--arch', 'x64', '--tools', 'ghidra', '--source', 'local:generated-fixture', '--license', 'unspecified', '--source-revision', 'fixture-v1')
    $shown = Invoke-RR -CLIArgs @('journal', 'show', $note.id)
    Assert-Check ($shown.revision -eq $note.revision -and $shown.source.evidence_status -eq 'unverified') 'knowledge revision persists without promoting confidence'
    $part = Invoke-RR -CLIArgs @('journal', 'read', $note.id, '--revision', $note.revision, '--start-line', '2', '--max-lines', '1')
    Assert-Check ($part.text -eq 'second' -and $part.next_line -eq 3) 'revision-pinned segmented reading works'
    $found = @(Invoke-RR -CLIArgs @('journal', 'search', '--origin', 'journal', '--domain', 'native-static', '--arch', 'amd64', '--tools', 'ghidra', 'record-closeout'))
    Assert-Check ($found.Count -eq 1 -and $found[0].revision -eq $note.revision -and (@($found[0].architectures) -contains 'x86-64') -and (@($found[0].tools) -contains 'ghidra')) 'knowledge structured filters preserve revision and canonical scope'
    $builtin = @(Invoke-RR -CLIArgs @('journal', 'search', '--origin', 'builtin', '--domain', 'native-dynamic', '--arch', 'x86', '--tools', 'x32dbg'))
    Assert-Check ($builtin.Count -eq 1 -and $builtin[0].id -eq 'builtin_x32_process_guard' -and $builtin[0].source.evidence_status -eq 'reviewed') 'reviewed builtin knowledge is searchable by domain architecture and tool'
    $builtinPart = Invoke-RR -CLIArgs @('journal', 'read', $builtin[0].id, '--revision', $builtin[0].revision, '--max-lines', '1')
    Assert-Check ($builtinPart.text -match 'typed x32dbg mutation') 'builtin knowledge supports revision-pinned bounded reads'
    $null = Invoke-RR -CLIArgs @('journal', 'show', '../outside') -ExpectedExit 1 -Raw
    Assert-Check $true 'journal path traversal is rejected'

    $caseFile = Join-Path $scratch ('state\research\cases\' + $case.id + '.json')
    $before = (Get-FileHash -LiteralPath $caseFile -Algorithm SHA256).Hash
    [IO.File]::WriteAllBytes($source, [byte[]](0x99, 0x20, 0x30, 0x40))
    $drift = Invoke-RR -CLIArgs @('case', 'verify', $case.id) -ExpectedExit 1
    Assert-Check (-not $drift.valid -and $drift.issues[0].code -eq 'source_changed') 'same-size source drift produces JSON failure and nonzero exit'
    Assert-Check ((Get-FileHash -LiteralPath $caseFile -Algorithm SHA256).Hash -eq $before) 'verification never rewrites the case'
    [IO.File]::WriteAllBytes($source, $original)

    $plan = Invoke-RR -CLIArgs @('patch', 'plan', '--path', $source, '--offset', '1', '--expected', '20 30', '--replacement', 'AA BB')
    $dry = Invoke-RR -CLIArgs @('patch', 'dry-run', $plan.id)
    Assert-Check $dry.ready 'fixture patch dry-run is ready'
    $null = Invoke-RR -CLIArgs @('patch', 'apply', $plan.id, '--in-place', '--operation-id', 'smoke-patch-apply')
    $null = Invoke-RR -CLIArgs @('patch', 'apply', $plan.id, '--in-place', '--operation-id', 'smoke-patch-apply')
    Assert-Check $true 'explicit patch apply operation can be replayed safely'
    $patchCheck = Invoke-RR -CLIArgs @('patch', 'verify', $plan.id)
    Assert-Check $patchCheck.valid 'fixture patch postcondition holds'
    $null = Invoke-RR -CLIArgs @('patch', 'rollback', $plan.id, '--operation-id', 'smoke-patch-rollback')
    $null = Invoke-RR -CLIArgs @('patch', 'rollback', $plan.id, '--operation-id', 'smoke-patch-rollback')
    Assert-Check $true 'explicit patch rollback operation can be replayed safely'
    Assert-Check ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -eq $identity.sha256) 'fixture patch rollback restores the original hash'

    $compositeEdits = Join-Path $scratch 'composite-edits.json'
    [IO.File]::WriteAllText($compositeEdits, '[{"offset":0,"expected_hex":"10","replacement_hex":"A1"},{"offset":3,"expected_hex":"40","replacement_hex":"A4"}]', (New-Object Text.UTF8Encoding($false)))
    $composite = Invoke-RR -CLIArgs @('patch', 'plan', '--path', $source, '--edits-file', $compositeEdits)
    $compositeDry = Invoke-RR -CLIArgs @('patch', 'dry-run', $composite.id)
    Assert-Check ($compositeDry.ready -and $compositeDry.edit_count -eq 2 -and $compositeDry.total_byte_count -eq 2) 'composite patch dry-run reports two canonical edits'
    $null = Invoke-RR -CLIArgs @('patch', 'apply', $composite.id, '--in-place', '--operation-id', 'smoke-composite-apply')
    $compositeCheck = Invoke-RR -CLIArgs @('patch', 'verify', $composite.id)
    Assert-Check $compositeCheck.valid 'composite patch postcondition holds'
    $null = Invoke-RR -CLIArgs @('patch', 'rollback', $composite.id, '--operation-id', 'smoke-composite-rollback')
    Assert-Check ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -eq $identity.sha256) 'composite patch rollback restores the original hash'

    for ($i = 0; $i -lt 6; $i++) {
        $process = New-Object Diagnostics.Process
        $process.StartInfo.FileName = $Executable
        $process.StartInfo.Arguments = 'case evidence ' + $case.id + ' --summary parallel-' + $i
        $process.StartInfo.WorkingDirectory = $scratch
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $worker = [pscustomobject]@{ Process = $process; Started = $false; Stdout = $null; Stderr = $null; Index = $i }
        $workers += $worker
        $worker.Started = $process.Start()
        if (-not $worker.Started) { throw 'Could not start a test-owned CLI worker.' }
        $worker.Stdout = $process.StandardOutput.ReadToEndAsync()
        $worker.Stderr = $process.StandardError.ReadToEndAsync()
    }
    foreach ($worker in $workers) {
        $process = $worker.Process
        if (-not $process.WaitForExit(20000)) { throw 'A test-owned CLI worker exceeded its deadline.' }
        $output = $worker.Stdout.GetAwaiter().GetResult()
        $errorOutput = $worker.Stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $scratch ('worker-' + $worker.Index + '.json')), $output)
        [IO.File]::WriteAllText((Join-Path $scratch ('worker-' + $worker.Index + '.err')), $errorOutput)
        if ($process.ExitCode -ne 0) { throw ('CLI worker failed: pid=' + $process.Id + ' exit=' + $process.ExitCode + ' stderr=' + $errorOutput) }
    }
    $persisted = Invoke-RR -CLIArgs @('case', 'show', $case.id)
    Assert-Check (@($persisted.evidence).Count -eq 7) 'six concurrent executable processes lose no evidence'
    $final = Invoke-RR -CLIArgs @('case', 'verify', $case.id)
    Assert-Check ($final.valid -and $final.unbound_evidence -eq 6) 'unbound observations remain explicitly unbound'
    if ($originalHash -ne '') {
        Assert-Check ((Get-FileHash -LiteralPath $originalExe -Algorithm SHA256).Hash -eq $originalHash) 'live executable bytes remain unchanged'
    }
    Assert-Check ((Get-GuardedRootStateSnapshot) -eq $rootStateBefore) 'candidate smoke leaves production persistent state untouched'
    $report = [ordered]@{
        checked_utc = [DateTime]::UtcNow.ToString('o')
        candidate = $Executable
        candidate_sha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
        debug_route = $debugRoute
        pointer_map_id = $pointerMap.id
        pointer_cross_process_valid_chains = $pointerVerify.valid_chains
        scratch = $scratch
        scratch_retained_on_success = $false
        case_id = $case.id
        note_id = $note.id
        evidence_count = @($persisted.evidence).Count
        checks = $checks.ToArray()
        passed = $true
        live_executable_replaced = $false
        ghidra_session_modified = $false
    }
    $json = $report | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText((Join-Path $scratch 'report.json'), $json, (New-Object Text.UTF8Encoding($false)))
    $smokeSucceeded = $true
    Write-Output $json
} finally {
    foreach ($fixture in $pointerFixtures) {
        Stop-PointerFixture $fixture
        if ($null -ne $fixture.Process) { $fixture.Process.Dispose() }
    }
    foreach ($worker in $workers) {
        if ($worker.Started -and -not $worker.Process.HasExited) {
            $worker.Process.Kill()
            $null = $worker.Process.WaitForExit(3000)
        }
        $worker.Process.Dispose()
    }
    $env:REVERSERESEARCH_TOOLS = $savedToolRoots
    Pop-Location
    if ($smokeSucceeded -and (Test-Path -LiteralPath $scratch)) {
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}
