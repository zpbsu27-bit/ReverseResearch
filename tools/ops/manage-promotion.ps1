[CmdletBinding()]
param(
    [ValidateSet("Status", "Promote", "Rollback")]
    [string]$Action = "Status",
    [string]$Root = "",
    [string]$Candidate = "",
    [string]$TaskName = "ReverseResearch Server"
)

$ErrorActionPreference = "Stop"
$PromotionSchema = "reverseresearch.promotion.v1"
$LayoutMarkerSchema = "reverseresearch.state-layout.v1"
$LayoutCapabilitiesSchema = "reverseresearch.state-layout-capabilities.v1"
$LegacyLayout = 1
$ToolCurrentLayout = 2

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
} else {
    $Root = (Resolve-Path $Root).Path
}

Import-Module (Join-Path $PSScriptRoot "runtime-artifact.psm1") -Force
$productionExe = Resolve-RRInstalledArtifact -Root $Root
$promotionDir = Join-Path $Root ".tmp\promotion"
$previousExe = Join-Path $promotionDir "ReverseResearch.prev.exe"
$manifestPath = Join-Path $promotionDir "promotion.json"
$layoutMarkerPath = Join-Path $Root "state\.layout.json"
$autostartScript = Join-Path $PSScriptRoot "manage-autostart.ps1"
$hardeningScript = Join-Path $PSScriptRoot "harden-local-install.ps1"

function Get-FileSHA256 {
    param([string]$Path)
    return Get-RRFileSHA256 -Path $Path
}

function Get-BinaryLayoutCapability {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    try {
        $output = @(& $Path state-layout capabilities 2>$null)
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) {
            $raw = ($output -join [Environment]::NewLine).Trim()
            $value = $raw | ConvertFrom-Json
            if ([string]$value.schema_version -ne $LayoutCapabilitiesSchema) {
                throw "unexpected state-layout capability schema"
            }
            $maxLayout = [int]$value.max_supported_layout
            $minLayout = [int]$value.min_supported_layout
            if ($minLayout -lt 1 -or $maxLayout -lt $minLayout) {
                throw "invalid state-layout capability range"
            }
            return [ordered]@{
                min_supported_layout = $minLayout
                max_supported_layout = $maxLayout
                writes_layout = [int]$value.writes_layout
                legacy_assumed = $false
            }
        }
    } catch {
    }
    return [ordered]@{
        min_supported_layout = $LegacyLayout
        max_supported_layout = $LegacyLayout
        writes_layout = $LegacyLayout
        legacy_assumed = $true
    }
}

function Get-StateLayoutStatus {
    if (Test-Path -LiteralPath $layoutMarkerPath -PathType Leaf) {
        $marker = Get-Content -Raw -Encoding UTF8 -LiteralPath $layoutMarkerPath | ConvertFrom-Json
        if ([string]$marker.schema_version -ne $LayoutMarkerSchema) {
            throw "invalid state layout marker schema at $layoutMarkerPath"
        }
        $layout = [int]$marker.layout_version
        if ($layout -lt 1) {
            throw "invalid state layout version at $layoutMarkerPath"
        }
        return [ordered]@{
            marker_present = $true
            marker_path = $layoutMarkerPath
            layout_version = $layout
            conservative_inference = $false
        }
    }

    $stateRoot = Join-Path $Root "state"
    $nonEmpty = $false
    if (Test-Path -LiteralPath $stateRoot -PathType Container) {
        $entries = @(Get-ChildItem -LiteralPath $stateRoot -Force -ErrorAction Stop | Where-Object {
            $_.Name -ne ".layout.json" -and $_.Name -ne ".layout.lock"
        })
        $nonEmpty = ($entries.Count -gt 0)
    }
    return [ordered]@{
        marker_present = $false
        marker_path = $layoutMarkerPath
        layout_version = $(if ($nonEmpty) { $ToolCurrentLayout } else { $LegacyLayout })
        conservative_inference = $nonEmpty
    }
}

function Read-PromotionManifest {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return $null
    }
    $value = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
    if ([string]$value.schema_version -ne $PromotionSchema) {
        throw "invalid promotion manifest schema at $manifestPath"
    }
    return $value
}

function Write-JsonAtomic {
    param(
        [string]$Path,
        [object]$Value
    )
    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force $directory | Out-Null
    $temporary = Join-Path $directory (".rr-promotion-" + [Guid]::NewGuid().ToString("N") + ".json")
    try {
        $json = $Value | ConvertTo-Json -Depth 8
        [System.IO.File]::WriteAllText($temporary, $json, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-ManagedTaskInstalled {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        return $false
    }
    return $null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
}

function Wait-ManagedTaskStopped {
    if (-not (Test-ManagedTaskInstalled)) {
        return
    }
    $deadline = (Get-Date).AddSeconds(40)
    do {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        if ([string]$task.State -ne "Running") {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "scheduled task '$TaskName' remained Running after graceful stop"
}

function Stop-ManagedServer {
    if (-not (Test-ManagedTaskInstalled)) {
        return $false
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $autostartScript -Action Stop -Root $Root -TaskName $TaskName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "managed ReverseResearch stop failed with exit $LASTEXITCODE"
    }
    Wait-ManagedTaskStopped
    return $true
}

function Start-ManagedServer {
    param([bool]$WasManaged)
    if (-not $WasManaged) {
        return
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $autostartScript -Action Restart -Root $Root -TaskName $TaskName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "managed ReverseResearch restart failed with exit $LASTEXITCODE"
    }
}

function Apply-InstallHardening {
    param([ValidateSet("Apply", "Repair")][string]$Mode = "Apply")
    if (-not (Test-Path -LiteralPath $hardeningScript -PathType Leaf)) {
        return
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hardeningScript -Action $Mode -Root $Root | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "local install hardening failed with exit $LASTEXITCODE"
    }
}

function Publish-Executable {
    param(
        [string]$Source,
        [string]$Destination
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "publish source executable not found: $Source"
    }
    $directory = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force $directory | Out-Null
    $temporary = Join-Path $directory (".rr-publish-" + [Guid]::NewGuid().ToString("N") + ".exe")
    $backup = Join-Path $directory (".rr-replace-backup-" + [Guid]::NewGuid().ToString("N") + ".exe")
    Copy-Item -LiteralPath $Source -Destination $temporary -Force
    try {
        if (Test-Path -LiteralPath $Destination -PathType Leaf) {
            [System.IO.File]::Replace($temporary, $Destination, $backup, $true)
            Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
        } else {
            [System.IO.File]::Move($temporary, $Destination)
        }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
}

function Get-RollbackDecision {
    $state = Get-StateLayoutStatus
    $manifest = Read-PromotionManifest
    $previousCapability = Get-BinaryLayoutCapability $previousExe
    $previousHash = Get-FileSHA256 $previousExe
    $reason = ""
    $allowed = $true

    if ($null -eq $manifest) {
        $allowed = $false
        $reason = "promotion manifest is missing; previous binary provenance is unknown"
    } elseif ([string]$manifest.promotion_state -notin @("applied", "rolled_back")) {
        $allowed = $false
        $reason = "promotion is not committed; inspect the prepared receipt before attempting rollback"
    } elseif ((Get-ManifestProductionPath $manifest) -ne $productionExe) {
        $allowed = $false
        $reason = "installed artifact selection changed since promotion; rollback destination is not the recorded owner"
    } elseif ((Get-FileSHA256 $productionExe) -ne $(if ([string]$manifest.promotion_state -eq "rolled_back") {
                  [string]$manifest.previous_sha256
              } else { [string]$manifest.candidate_sha256 })) {
        $allowed = $false
        $reason = "installed executable changed since the recorded release; rollback would overwrite an unrelated artifact"
    } elseif (($manifest.PSObject.Properties.Name -contains "previous_present_at_promotion") -and
              -not [bool]$manifest.previous_present_at_promotion) {
        $allowed = $false
        $reason = "promotion did not replace an existing production executable; no rollback target was captured"
    } elseif (-not (Test-Path -LiteralPath $previousExe -PathType Leaf)) {
        $allowed = $false
        $reason = "previous executable is missing"
    } elseif ([string]$manifest.previous_sha256 -eq "" -or $previousHash -ne [string]$manifest.previous_sha256) {
        $allowed = $false
        $reason = "previous executable hash does not match the promotion manifest"
    } elseif ($null -eq $previousCapability) {
        $allowed = $false
        $reason = "previous executable state-layout capability is unavailable"
    } else {
        $manifestMax = [int]$manifest.previous_max_state_layout
        $effectiveMax = [Math]::Min($manifestMax, [int]$previousCapability.max_supported_layout)
        if ([int]$state.layout_version -gt $effectiveMax) {
            $allowed = $false
            $reason = "state layout $($state.layout_version) is newer than previous binary maximum $effectiveMax"
        }
    }
    return [ordered]@{
        allowed = $allowed
        reason = $reason
        state = $state
        previous_sha256 = $previousHash
        previous_capability = $previousCapability
        manifest_present = ($null -ne $manifest)
    }
}

function Get-ManifestProductionPath {
    param([object]$Manifest)
    # Historical v1 receipts always promoted the root CLI executable.
    if (-not ($Manifest.PSObject.Properties.Name -contains "production_path")) {
        return (Join-Path $Root "ReverseResearch.exe")
    }
    $path = [System.IO.Path]::GetFullPath([string]$Manifest.production_path)
    $paths = Get-RRArtifactPaths -Root $Root
    if ($path -notin $paths.InstalledCandidates) {
        throw "promotion receipt has an unsupported artifact destination"
    }
    return $path
}

function Assert-ArtifactSelection {
    if ((Resolve-RRInstalledArtifact -Root $Root) -ne $productionExe) {
        throw "installed artifact selection changed during release; refusing a different destination"
    }
}

function Get-PromotionStatus {
    $state = Get-StateLayoutStatus
    $currentCapability = Get-BinaryLayoutCapability $productionExe
    $previousCapability = Get-BinaryLayoutCapability $previousExe
    $manifest = Read-PromotionManifest
    $decision = Get-RollbackDecision
    return [ordered]@{
        schema_version = $PromotionSchema
        root = $Root
        state = $state
        production = [ordered]@{
            path = $productionExe
            exists = (Test-Path -LiteralPath $productionExe -PathType Leaf)
            sha256 = Get-FileSHA256 $productionExe
            capability = $currentCapability
        }
        previous = [ordered]@{
            path = $previousExe
            exists = (Test-Path -LiteralPath $previousExe -PathType Leaf)
            sha256 = Get-FileSHA256 $previousExe
            capability = $previousCapability
        }
        manifest_present = ($null -ne $manifest)
        promotion_state = $(if ($null -ne $manifest) { [string]$manifest.promotion_state } else { "" })
        rollback_allowed = [bool]$decision.allowed
        rollback_reason = [string]$decision.reason
    }
}

$releaseLock = $null
if ($Action -ne "Status") {
    New-Item -ItemType Directory -Force $promotionDir | Out-Null
    $lockPath = Join-Path $promotionDir ".promotion.lock"
    try {
        $releaseLock = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
        $releaseLock.Lock(0, 1)
    } catch {
        if ($null -ne $releaseLock) { $releaseLock.Dispose(); $releaseLock = $null }
        throw "another release owns the promotion lock; inspect its receipt before retrying"
    }
    $productionExe = Resolve-RRInstalledArtifact -Root $Root
}

try {
switch ($Action) {
    "Status" {
        Get-PromotionStatus | ConvertTo-Json -Depth 8
    }
    "Promote" {
        $pending = Read-PromotionManifest
        if ($null -ne $pending -and [string]$pending.promotion_state -eq "prepared") {
            throw "previous promotion is prepared and uncommitted; inspect its exact destination and hashes before another release"
        }
        if ([string]::IsNullOrWhiteSpace($Candidate)) {
            throw "-Candidate is required for Promote"
        }
        $candidatePath = (Resolve-Path $Candidate).Path
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw "candidate executable not found: $candidatePath"
        }
        $candidateCapability = Get-BinaryLayoutCapability $candidatePath
        if ($null -eq $candidateCapability -or [bool]$candidateCapability.legacy_assumed) {
            throw "candidate does not expose a verifiable state-layout capability"
        }
        $state = Get-StateLayoutStatus
        if ([int]$state.layout_version -gt [int]$candidateCapability.max_supported_layout) {
            throw "candidate maximum state layout $($candidateCapability.max_supported_layout) cannot open state layout $($state.layout_version)"
        }

        $hadProduction = Test-Path -LiteralPath $productionExe -PathType Leaf
        $currentHash = Get-FileSHA256 $productionExe
        $currentCapability = Get-BinaryLayoutCapability $productionExe
        $candidateHash = Get-FileSHA256 $candidatePath
        if ($hadProduction -and $currentHash -eq $candidateHash) {
            $status = Get-PromotionStatus
            $status["already_current"] = $true
            $status | ConvertTo-Json -Depth 8
            break
        }
        # The full tree can be large. Enforce private ACLs while the current
        # server is available, and keep the stopped publication window small.
        Apply-InstallHardening
        $wasManaged = Stop-ManagedServer
        Assert-ArtifactSelection

        $stateAfterStop = Get-StateLayoutStatus
        if ([int]$stateAfterStop.layout_version -gt [int]$candidateCapability.max_supported_layout) {
            throw "state layout advanced while stopping service; refusing promotion"
        }

        New-Item -ItemType Directory -Force $promotionDir | Out-Null
        $previousHash = ""
        $previousCapability = $null
        if ($hadProduction) {
            Copy-Item -LiteralPath $productionExe -Destination $previousExe -Force
            $previousHash = Get-FileSHA256 $previousExe
            $previousCapability = Get-BinaryLayoutCapability $previousExe
        }
        $record = [ordered]@{
            schema_version = $PromotionSchema
            production_path = $productionExe
            promotion_state = "prepared"
            promoted_utc = (Get-Date).ToUniversalTime().ToString("o")
            candidate_sha256 = $candidateHash
            candidate_max_state_layout = [int]$candidateCapability.max_supported_layout
            previous_sha256 = $previousHash
            previous_max_state_layout = $(if ($null -ne $previousCapability) { [int]$previousCapability.max_supported_layout } else { 0 })
            previous_legacy_assumed = $(if ($null -ne $previousCapability) { [bool]$previousCapability.legacy_assumed } else { $false })
            previous_present_at_promotion = $hadProduction
            state_layout_at_promotion = [int]$stateAfterStop.layout_version
            replaced_sha256 = $currentHash
        }
        Write-JsonAtomic -Path $manifestPath -Value $record
        if ((Get-FileSHA256 $candidatePath) -ne $candidateHash -or
            (Get-FileSHA256 $productionExe) -ne $currentHash) {
            throw "candidate or installed executable changed during release; refusing publication"
        }
        Publish-Executable -Source $candidatePath -Destination $productionExe
        if ((Get-FileSHA256 $productionExe) -ne $candidateHash) {
            throw "published executable hash does not match candidate"
        }
        $record["promotion_state"] = "applied"
        $record["applied_utc"] = (Get-Date).ToUniversalTime().ToString("o")
        Write-JsonAtomic -Path $manifestPath -Value $record
        Apply-InstallHardening -Mode Repair
        Start-ManagedServer -WasManaged $wasManaged
        Get-PromotionStatus | ConvertTo-Json -Depth 8
    }
    "Rollback" {
        $decision = Get-RollbackDecision
        if (-not [bool]$decision.allowed) {
            throw "rollback refused: $($decision.reason)"
        }
        Apply-InstallHardening
        $wasManaged = Stop-ManagedServer
        $decisionAfterStop = Get-RollbackDecision
        Assert-ArtifactSelection
        if (-not [bool]$decisionAfterStop.allowed) {
            throw "rollback refused after service stop: $($decisionAfterStop.reason)"
        }
        $rollbackFromHash = Get-FileSHA256 $productionExe
        Publish-Executable -Source $previousExe -Destination $productionExe
        if ((Get-FileSHA256 $productionExe) -ne [string]$decisionAfterStop.previous_sha256) {
            throw "rolled-back executable hash does not match previous candidate"
        }
        Apply-InstallHardening -Mode Repair
        $manifest = Read-PromotionManifest
        $updated = [ordered]@{
            schema_version = $PromotionSchema
            production_path = $productionExe
            promotion_state = "rolled_back"
            promoted_utc = [string]$manifest.promoted_utc
            applied_utc = [string]$manifest.applied_utc
            candidate_sha256 = [string]$manifest.candidate_sha256
            candidate_max_state_layout = [int]$manifest.candidate_max_state_layout
            previous_sha256 = [string]$manifest.previous_sha256
            previous_max_state_layout = [int]$manifest.previous_max_state_layout
            previous_legacy_assumed = [bool]$manifest.previous_legacy_assumed
            previous_present_at_promotion = [bool]$manifest.previous_present_at_promotion
            state_layout_at_promotion = [int]$manifest.state_layout_at_promotion
            replaced_sha256 = [string]$manifest.replaced_sha256
            rolled_back_utc = (Get-Date).ToUniversalTime().ToString("o")
            rollback_from_sha256 = $rollbackFromHash
        }
        Write-JsonAtomic -Path $manifestPath -Value $updated
        Start-ManagedServer -WasManaged $wasManaged
        Get-PromotionStatus | ConvertTo-Json -Depth 8
    }
}
} finally {
    if ($null -ne $releaseLock) {
        try { $releaseLock.Unlock(0, 1) } finally { $releaseLock.Dispose() }
    }
}
