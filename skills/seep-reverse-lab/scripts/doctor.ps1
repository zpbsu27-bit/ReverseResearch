param(
    [string]$Root,
    [string]$Executable
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
} else {
    $Root = (Resolve-Path -LiteralPath $Root).Path
}
if ([string]::IsNullOrWhiteSpace($Executable)) {
    $Executable = Join-Path $Root 'ReverseResearch.exe'
}

$warnings = New-Object System.Collections.Generic.List[string]
$toolIndex = $null
$backends = @()

if (Test-Path -LiteralPath $Executable) {
    Push-Location $Root
    try {
        $toolLines = @(& $Executable tools scan 2>$null)
        $toolText = [string]::Join([Environment]::NewLine, $toolLines)
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($toolText)) {
            $toolIndex = ConvertFrom-Json -InputObject $toolText
        } else {
            $warnings.Add('ReverseResearch tools scan failed; tool availability is not fully known.')
        }

        $statusLines = @(& $Executable module status 2>$null)
        $statusText = [string]::Join([Environment]::NewLine, $statusLines)
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($statusText)) {
            $statusObject = ConvertFrom-Json -InputObject $statusText
            $backends = @($statusObject.backends)
            foreach ($backend in $backends) {
                if ($backend.state -ne 'idle') {
                    $warnings.Add(('Backend {0} is {1}; preserve the existing session.' -f $backend.name, $backend.state))
                }
            }
        }
    } finally {
        Pop-Location
    }
} else {
    $warnings.Add('ReverseResearch.exe was not found; Core tool/backend status was not queried.')
}

$configuredToolRoots = @()
if (-not [string]::IsNullOrWhiteSpace($env:REVERSERESEARCH_TOOLS)) {
    $configuredToolRoots = @($env:REVERSERESEARCH_TOOLS -split [IO.Path]::PathSeparator | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $warnings.Add('REVERSERESEARCH_TOOLS is configured; tool discovery may resolve executables outside PATH. Preserve the reported source/path in evidence.')
}

$proxyConfigured = -not [string]::IsNullOrWhiteSpace($env:HTTP_PROXY) -or
    -not [string]::IsNullOrWhiteSpace($env:HTTPS_PROXY) -or
    -not [string]::IsNullOrWhiteSpace($env:ALL_PROXY)
if ($proxyConfigured) {
    $warnings.Add('Proxy environment variables are configured; capture/replay observations may be proxy-dependent.')
}

$interestingNames = @('adb','frida','frida-server','x32dbg','x64dbg','java','chrome','msedge','firefox')
$processes = @(
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $interestingNames -contains $_.ProcessName.ToLowerInvariant() } |
        ForEach-Object {
            [ordered]@{
                pid = $_.Id
                name = $_.ProcessName
                path = try { $_.Path } catch { '' }
            }
        }
)
if ($processes.Count -gt 0) {
    $warnings.Add('Existing debugger/Android/Java/browser processes were detected; do not assume they belong to this task.')
}

$ports = @()
foreach ($port in @(19095, 19096)) {
    $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    $ports += [ordered]@{
        port = $port
        listening = ($listeners.Count -gt 0)
        owning_pids = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    }
    if ($listeners.Count -gt 0) {
        $warnings.Add(('ReverseResearch backend port {0} is already listening; reuse only after ownership is proved.' -f $port))
    }
}

[ordered]@{
    checked_utc = [DateTime]::UtcNow.ToString('o')
    root = $Root
    executable = if (Test-Path -LiteralPath $Executable) { (Resolve-Path -LiteralPath $Executable).Path } else { $Executable }
    tool_index = $toolIndex
    backends = $backends
    environment = [ordered]@{
        proxy_configured = $proxyConfigured
        configured_tool_roots = $configuredToolRoots
        adb_server_socket_configured = -not [string]::IsNullOrWhiteSpace($env:ADB_SERVER_SOCKET)
        java_tool_options_configured = -not [string]::IsNullOrWhiteSpace($env:JAVA_TOOL_OPTIONS)
    }
    processes = $processes
    ports = $ports
    warnings = $warnings.ToArray()
} | ConvertTo-Json -Depth 8
