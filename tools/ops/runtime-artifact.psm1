# Stateless artifact selection shared by build, launch and release entry points.
# This module does not install files, manage processes or write receipts.
function Get-RRArtifactPaths {
    param([Parameter(Mandatory = $true)][string]$Root)
    $absoluteRoot = [System.IO.Path]::GetFullPath($Root)
    $installed = @(
        (Join-Path $absoluteRoot "dist\ReverseResearch-MCP.exe"),
        (Join-Path $absoluteRoot "ReverseResearch.exe"),
        (Join-Path $absoluteRoot "ReverseResearch-MCP.exe")
    )
    return [pscustomobject]@{
        Root = $absoluteRoot
        InstalledCandidates = $installed
        DefaultInstalled = $installed[0]
        Candidate = (Join-Path $absoluteRoot "dist\candidate\ReverseResearch-MCP.exe")
    }
}

function Resolve-RRInstalledArtifact {
    param([Parameter(Mandatory = $true)][string]$Root)
    $paths = Get-RRArtifactPaths -Root $Root
    foreach ($path in $paths.InstalledCandidates) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    }
    return $paths.DefaultInstalled
}

function Get-RRFileSHA256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
    $stream = [System.IO.File]::OpenRead($Path)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace("-", "").ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

Export-ModuleMember -Function Get-RRArtifactPaths, Resolve-RRInstalledArtifact, Get-RRFileSHA256
