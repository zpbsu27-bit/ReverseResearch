param(
    [ValidatePattern('^[a-z0-9-]{1,80}$')][string]$Operation,
    [ValidatePattern('^[a-z0-9,-]{1,500}$')][string]$Profiles = 'all',
    [switch]$ListProfiles
)
$ErrorActionPreference = 'Stop'
$labRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Push-Location -LiteralPath $labRoot
try {
    if ($ListProfiles) {
        & python -B -X utf8 tools/network-lab/network_lab.py profiles
        exit $LASTEXITCODE
    }
    # Registry admission is the installer's single distro/path binding owner.
    & python -B -X utf8 tools/network-lab/setup_wsl_lab.py --action admit --operation rr-network-lab-admission
    if ($LASTEXITCODE -ne 0) { throw 'The owned Debian laboratory is not ready.' }
    if (-not $Operation) { $Operation = 'rr-network-lab-' + [Guid]::NewGuid().ToString('N') }
    $linuxRoot = & wsl.exe --distribution Debian --user root --exec wslpath -a -u $labRoot
    if ($LASTEXITCODE -ne 0 -or -not $linuxRoot) { throw 'WSL path translation failed.' }
    $linuxRoot = ($linuxRoot -join '').Trim()
    Write-Host "Operation: $Operation"
    Write-Host "Profiles: $Profiles"
    Write-Host 'One reused Linux environment; no copied games or VMs.'
    & wsl.exe --distribution Debian --user root --exec python3 -B "$linuxRoot/tools/network-lab/network_lab.py" smoke --operation $Operation --profiles $Profiles
    $labExitCode = $LASTEXITCODE
    Write-Host "Receipt: $labRoot\evidence\network-lab\$Operation\receipt.json"
    exit $labExitCode
}
finally { Pop-Location }
