param([Parameter(Mandatory=$true)][string]$Executable)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$liveExe = Join-Path $repo 'ReverseResearch.exe'
if ((Test-Path -LiteralPath $liveExe) -and ((Resolve-Path -LiteralPath $liveExe).Path -eq $Executable)) {
    throw 'Use an isolated candidate build, not the live executable.'
}

$liveHashBefore = if (Test-Path -LiteralPath $liveExe) { (Get-FileHash -LiteralPath $liveExe -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
$candidateHash = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
$candidateSize = (Get-Item -LiteralPath $Executable).Length
$scratch = Join-Path $repo ('.tmp\p2-closeout\smoke-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch -Force
Copy-Item -LiteralPath (Join-Path $repo 'config') -Destination (Join-Path $scratch 'config') -Recurse
Copy-Item -LiteralPath (Join-Path $repo 'skills') -Destination (Join-Path $scratch 'skills') -Recurse

$checks = New-Object System.Collections.Generic.List[string]
$guardedStateNames = @('hooks','patches','compatibility','research','knowledge','sandboxes')

function Assert-Check([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAILED: ' + $Name) }
    $checks.Add($Name)
}

function Get-StateSnapshot {
    $entries = New-Object System.Collections.Generic.List[string]
    foreach ($name in $guardedStateNames) {
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

function Invoke-RR {
    param([string[]]$CLIArgs)
    $stderrPath = Join-Path $scratch ('stderr-' + [guid]::NewGuid().ToString('N') + '.txt')
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Executable @CLIArgs 2> $stderrPath)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($code -ne 0) {
        $detail = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        throw ('Unexpected CLI exit ' + $code + ' for ' + ($CLIArgs -join ' ') + ': ' + $detail)
    }
    return ConvertFrom-Json -InputObject ($lines -join "`n")
}

$stateBefore = Get-StateSnapshot
$passed = $false
Push-Location $scratch
try {
    $moduleBefore = Invoke-RR -CLIArgs @('module','status')
    Assert-Check (@($moduleBefore.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'candidate starts with all analysis/debugger backends idle'

    $identityPrepared = Invoke-RR -CLIArgs @('prepare','analyze','this','BloodHound','Active','Directory','attack','path')
    Assert-Check ($identityPrepared.route.route.id -eq 'identity-ad' -and $identityPrepared.playbook.id -eq 'identity-ad' -and $identityPrepared.playbook.skill_path -eq 'skills/seep-identity/SKILL.md') 'identity task resolves canonical P2 route and specialist playbook'

    $graphPath = Join-Path $scratch 'attack-graph.json'
    [IO.File]::WriteAllText($graphPath, '{"source_kind":"candidate-smoke","nodes":[{"id":"user:a","kind":"identity"},{"id":"host:1","kind":"host"}],"edges":[{"from":"user:a","to":"host:1","kind":"admin-of"}]}', (New-Object Text.UTF8Encoding($false)))
    $graph = Invoke-RR -CLIArgs @('attackgraph','import',$graphPath,'--from','user:a','--to','host:1')
    Assert-Check ($graph.graph.sha256.Length -eq 64 -and $graph.path.found -and @($graph.path.edges).Count -eq 1) 'attack graph import is content-addressed and path analysis remains candidate-only'

    $cloudPath = Join-Path $scratch 'cloud-inventory.json'
    [IO.File]::WriteAllText($cloudPath, '{"provider":"aws","scope_id":"candidate-smoke","resources":[{"id":"role:app","type":"iam-role","name":"app"},{"id":"bucket:data","type":"s3-bucket","name":"data","public":true}],"relationships":[{"from":"role:app","to":"bucket:data","kind":"can-access"}]}', (New-Object Text.UTF8Encoding($false)))
    $cloud = Invoke-RR -CLIArgs @('cloud','inventory',$cloudPath)
    Assert-Check ($cloud.report.read_only -and $cloud.report.provider -eq 'aws' -and @($cloud.report.resources).Count -eq 2 -and $cloud.report.graph.sha256.Length -eq 64) 'cloud inventory import is offline/read-only and normalized into a graph'

    $stixPath = Join-Path $scratch 'stix.json'
    [IO.File]::WriteAllText($stixPath, '{"type":"bundle","id":"bundle--candidate-smoke","objects":[{"type":"malware","id":"malware--1","name":"demo"},{"type":"indicator","id":"indicator--1"},{"type":"relationship","id":"relationship--1","relationship_type":"indicates","source_ref":"indicator--1","target_ref":"malware--1"}]}', (New-Object Text.UTF8Encoding($false)))
    $stix = Invoke-RR -CLIArgs @('cti','import',$stixPath)
    Assert-Check (@($stix.report.objects).Count -eq 2 -and @($stix.report.relationships).Count -eq 1) 'CTI import parses a bounded local STIX bundle without synchronization'

    $hunt = Invoke-RR -CLIArgs @('hunt','plan','--hypothesis','scheduled-task-persistence','--telemetry','Sysmon,EDR','--techniques','T1053','--adapters','sigma,osquery')
    Assert-Check (-not $hunt.plan.execution_performed -and @($hunt.plan.telemetry).Count -eq 2) 'threat hunt remains plan-only with declared telemetry'

    $ipaRoot = Join-Path $scratch 'ipa-root'
    $appDir = Join-Path $ipaRoot 'Payload\Demo.app'
    $null = New-Item -ItemType Directory -Path $appDir -Force
    [IO.File]::WriteAllText((Join-Path $appDir 'Info.plist'), 'plist', (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllBytes((Join-Path $appDir 'Demo'), [byte[]](0xcf,0xfa,0xed,0xfe,0))
    $ipaPath = Join-Path $scratch 'demo.ipa'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($ipaRoot, $ipaPath)
    $ios = Invoke-RR -CLIArgs @('ios','inspect',$ipaPath)
    Assert-Check ($ios.report.read_only -and @($ios.report.app_roots).Count -eq 1 -and @($ios.report.macho_candidates).Count -eq 1) 'iOS IPA inspection is static/read-only and inventories the Mach-O candidate'

    $firmwarePath = Join-Path $scratch 'firmware.bin'
    [IO.File]::WriteAllBytes($firmwarePath, [byte[]](0x68,0x73,0x71,0x73,0,0,0,0))
    $firmware = Invoke-RR -CLIArgs @('firmware','inspect',$firmwarePath)
    Assert-Check ($firmware.report.read_only -and $firmware.report.format -eq 'squashfs') 'firmware inspection classifies immutable bytes without extraction or execution'

    $moduleAfter = Invoke-RR -CLIArgs @('module','status')
    Assert-Check (@($moduleAfter.backends | Where-Object { $_.state -ne 'idle' }).Count -eq 0) 'P2 import/inspect/plan flows leave all analysis/debugger backends idle'

    $passed = $true
} finally {
    Pop-Location
}

$stateAfter = Get-StateSnapshot
$liveHashAfter = if (Test-Path -LiteralPath $liveExe) { (Get-FileHash -LiteralPath $liveExe -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
Assert-Check ($liveHashBefore -eq $liveHashAfter) 'live root executable bytes are unchanged'
Assert-Check ($stateBefore -eq $stateAfter) 'guarded production persistent state is unchanged'

$report = [ordered]@{
    passed = $passed
    candidate = $Executable
    candidate_sha256 = $candidateHash
    candidate_size = $candidateSize
    live_exe_sha256_before = $liveHashBefore
    live_exe_sha256_after = $liveHashAfter
    production_state_unchanged = ($stateBefore -eq $stateAfter)
    checks = @($checks)
    scratch = $scratch
}
$reportPath = Join-Path $scratch 'report.json'
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
$report | ConvertTo-Json -Depth 8
