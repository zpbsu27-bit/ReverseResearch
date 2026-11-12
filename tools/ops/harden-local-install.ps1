[CmdletBinding()]
param(
    [ValidateSet("Audit", "Apply", "Repair")]
    [string]$Action = "Audit",
    [string]$Root = ""
)

$ErrorActionPreference = "Stop"

# Resolve the security module from this PowerShell edition, rather than an
# inherited PSModulePath that can select an incompatible PowerShell 7 module
# when the existing release entry point invokes Windows PowerShell 5.1.
Import-Module (Join-Path $PSHOME "Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1") -Force -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
} else {
    $Root = (Resolve-Path $Root).Path
}

$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($currentSid, "S-1-5-18", "S-1-5-32-544")

function Get-SidValue {
    param([System.Security.Principal.IdentityReference]$Identity)
    try {
        return $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $Identity.Value
    }
}

function New-PrivateAcl {
    param([bool]$Directory)
    if ($Directory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidValue in $allowed) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Test-PrivateAcl {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $true
    }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.Access.Count -eq 0) {
        return $false
    }
    if ($Path -eq $Root -and -not $acl.AreAccessRulesProtected) {
        return $false
    }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = Get-SidValue $rule.IdentityReference
        if ($allowed -notcontains $sid) {
            return $false
        }
    }
    return $true
}

function Set-PrivateDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }
    Set-Acl -LiteralPath $Path -AclObject (New-PrivateAcl -Directory $true)
}

function Set-PrivateDirectoryTree {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }
    Set-PrivateDirectory -Path $Path
    # Reset descendants only. Resetting Path itself would restore a possibly
    # public parent DACL for the duration of the entire traversal. /L operates
    # on links themselves rather than a target outside this installation.
    if (@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Select-Object -First 1).Count -gt 0) {
        & icacls.exe (Join-Path $Path '*') /reset /T /C /Q /L | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "icacls descendant reset failed for $Path with exit $LASTEXITCODE"
        }
    }
    if (-not (Test-PrivateAcl $Path)) {
        throw "private root DACL changed during descendant hardening: $Path"
    }
}

function Set-PrivateFile {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Set-Acl -LiteralPath $Path -AclObject (New-PrivateAcl -Directory $false)
    }
}

$rootIsProject = Test-Path -LiteralPath (Join-Path $Root "go.mod")
$directories = New-Object System.Collections.Generic.List[string]
$files = New-Object System.Collections.Generic.List[string]

if ($rootIsProject) {
    $directories.Add($Root)
    foreach ($name in @("config", "runtime", "state", "evidence", ".tmp\promotion")) {
        $directories.Add((Join-Path $Root $name))
    }
    Import-Module (Join-Path $PSScriptRoot "runtime-artifact.psm1") -Force
    $artifactPaths = Get-RRArtifactPaths -Root $Root
    foreach ($path in $artifactPaths.InstalledCandidates) { $files.Add($path) }
    $directories.Add((Join-Path $Root "dist"))

    $tunnelConfig = Join-Path $Root "config\tunnel.json"
    if (Test-Path -LiteralPath $tunnelConfig) {
        try {
            $cfg = Get-Content -Raw -Encoding UTF8 -LiteralPath $tunnelConfig | ConvertFrom-Json
            if ($cfg.api_key_file) {
                $keyPath = [string]$cfg.api_key_file
                $keyPath = $keyPath.Replace('$USERPROFILE', $env:USERPROFILE)
                $keyPath = [Environment]::ExpandEnvironmentVariables($keyPath)
                $files.Add($keyPath)
            }
        } catch {
            throw "failed to resolve tunnel API key file: $($_.Exception.Message)"
        }
    }
} else {
    $directories.Add($Root)
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Directory -ErrorAction SilentlyContinue) {
        $directories.Add($item.FullName)
    }
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -File -ErrorAction SilentlyContinue) {
        $files.Add($item.FullName)
    }
}

if ($Action -eq "Repair") {
    # Recovery/release uses the same private DACL owner on the important paths;
    # it never resets descendants. Windows propagates private inheritable ACEs
    # when repairing Root, while already-private important paths need no write.
    foreach ($path in @($directories | Select-Object -Unique)) {
        if (-not (Test-PrivateAcl $path)) { Set-PrivateDirectory -Path $path }
    }
    foreach ($path in @($files | Select-Object -Unique)) {
        if (-not (Test-PrivateAcl $path)) { Set-PrivateFile -Path $path }
    }
} elseif ($Action -eq "Apply") {
    # Every directory above is already within Root. The recursive root reset
    # applies the same policy to them; repeating it for runtime/state/evidence
    # causes another traversal of large trees without changing the boundary.
    Set-PrivateDirectoryTree -Path $Root
    foreach ($path in @($files | Select-Object -Unique)) {
        Set-PrivateFile -Path $path
    }
}

$important = @($directories + $files | Select-Object -Unique)
$unsafe = @($important | Where-Object { -not (Test-PrivateAcl $_) })
$result = [ordered]@{
    action = $Action
    root = $Root
    current_user_sid = $currentSid
    important_paths_checked = $important.Count
    unsafe_count = $unsafe.Count
    unsafe_sample = @($unsafe | Select-Object -First 20)
    passed = ($unsafe.Count -eq 0)
}
$result | ConvertTo-Json -Depth 4
if (-not $result.passed) {
    exit 3
}

