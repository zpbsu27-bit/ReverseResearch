[CmdletBinding()]
param(
    [string]$ProjectRoot = '',
    [switch]$Preview,
    [ValidateSet('Source', 'Full')][string]$Profile = 'Source',
    [string]$Destination = '',
    [switch]$NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

# Single backup-selection/ZIP owner; Full adds installed runtime and user data.
$excludedDirectories = @(
    '.git', '.tmp', 'tmp', 'backups', 'dist', 'runtime', 'state', 'evidence'
)
$excludedDirectoryNames = @(
    '.git', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
    '.cache', '.venv', 'venv', 'node_modules'
)
$retainedFiles = @(
    'runtime/README.md',
    'evidence/.gitkeep'
)
$excludedFilePatterns = @('*.exe~', '*.log', '*.pyc', '*.pyo', '*.tmp')
if ($Profile -eq 'Full') {
    $excludedDirectories = @('.git', '.tmp', 'tmp', 'backups', 'dist', 'evidence')
    $excludedDirectoryNames = @('.git', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.cache')
    $retainedFiles = @('evidence/.gitkeep')
    $excludedFilePatterns = @('*.exe~', '*.pyc', '*.pyo')
}
$partialPath = $null
$createdPartial = $false

try {
    # Windows PowerShell 5 initializes PSScriptRoot after parameter defaults.
    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    $root = (Resolve-Path -LiteralPath $ProjectRoot).Path.TrimEnd('\')
    if (-not (Test-Path -LiteralPath (Join-Path $root 'go.mod') -PathType Leaf)) {
        throw '未找到 go.mod，请从 ReverseResearch 项目根目录启动备份。'
    }
    if ((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw '项目根目录不能是符号链接或目录联接。'
    }

    $files = [Collections.Generic.List[IO.FileInfo]]::new()
    $directories = [Collections.Generic.Stack[string]]::new()
    $directories.Push($root)
    while ($directories.Count -gt 0) {
        $directory = $directories.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            $relative = $item.FullName.Substring($root.Length + 1).Replace('\', '/')
            if ($item.PSIsContainer) {
                if ($relative -in $excludedDirectories -or $item.Name -in $excludedDirectoryNames) { continue }
                $directories.Push($item.FullName)
                continue
            }
            # Submodules/worktrees use a .git pointer file instead of a directory.
            if ($item.Name -eq '.git') { continue }
            if ($Profile -eq 'Source' -and $relative -in @('ReverseResearch.exe', 'ReverseResearch-MCP.exe')) { continue }
            if ($directory -eq $root -and ($item.Name -like 'ReverseResearch-source-*.zip*' -or $item.Name -like 'ReverseResearch-full-*.zip*')) { continue }
            $excluded = $false
            foreach ($pattern in $excludedFilePatterns) {
                if ($item.Name -like $pattern) { $excluded = $true; break }
            }
            if (-not $excluded) { $files.Add($item) }
        }
    }

    if ($Profile -eq 'Full') {
        # These are formal durable receipts/rollback, despite their parent names.
        foreach ($relativeDirectory in @('evidence/network-lab', '.tmp/promotion')) {
            $retainedDirectory = Join-Path $root $relativeDirectory
            if (-not (Test-Path -LiteralPath $retainedDirectory -PathType Container)) { continue }
            foreach ($item in Get-ChildItem -LiteralPath $retainedDirectory -Recurse -File -Force) {
                $ancestor = $item.FullName
                while ($ancestor -ne $root) {
                    if (-not $ancestor.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
                        ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        throw "Retained path is outside the project or traverses a link: $($item.FullName)"
                    }
                    $ancestor = Split-Path -Parent $ancestor
                }
                $files.Add($item)
            }
        }
    }

    foreach ($relative in $retainedFiles) {
        $path = Join-Path $root $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $path -Force
        $ancestor = $item.FullName
        while ($ancestor -ne $root) {
            if (-not $ancestor.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw "保留文件不在项目目录：$relative"
            }
            if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "保留文件路径包含符号链接或目录联接：$relative"
            }
            $ancestor = Split-Path -Parent $ancestor
        }
        $files.Add($item)
    }
    $selected = @($files | Sort-Object FullName)
    $sourceBytes = [long](($selected | Measure-Object Length -Sum).Sum)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $kind = if ($Profile -eq 'Full') { 'full' } else { 'source' }
    $zipPath = if ($Destination) { [IO.Path]::GetFullPath($Destination) } else { Join-Path $root "ReverseResearch-$kind-$stamp.zip" }
    $outputDirectory = Split-Path -Parent $zipPath
    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) { throw 'Archive output directory must already exist.' }
    if (-not $zipPath.EndsWith('.zip', [StringComparison]::OrdinalIgnoreCase)) { throw 'Archive destination must be a .zip file.' }
    if (@($selected | Where-Object FullName -eq $zipPath).Count) { throw 'Archive destination cannot be an input.' }
    $partialPath = "$zipPath.partial"

    if ($Profile -eq 'Full') {
        Write-Host '[完整 ZIP] 保留 RR 工具源码、当前程序、运行环境、模型素材、研究数据和正式操作收据。'
        Write-Host '[排除] Git、开发验收、临时编译、可重建缓存和重复 candidate。'
    } else {
        Write-Host '[源码 ZIP] 保留源码、配置、文档、测试和运维脚本。'
        Write-Host '[排除] 运行时、研究数据、可重建依赖、缓存和既有备份。'
    }
    Write-Host ('文件：{0} 个，源文件大小：{1:N2} MiB' -f $selected.Count, ($sourceBytes / 1MB))
    Write-Host ('目标："{0}"' -f $zipPath)
    if ($Preview) {
        Write-Host '[预览完成] 文件范围已列出。'
        exit 0
    }
    if ((Test-Path -LiteralPath $zipPath) -or (Test-Path -LiteralPath $partialPath)) { throw 'Archive or .partial already exists; inspect the existing result before starting another run.' }

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [IO.FileStream]::new($partialPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $createdPartial = $true
    $archive = $null
    $manifest = [Collections.Generic.List[object]]::new()
    $updatedInputs = [Collections.Generic.List[object]]::new()
    $snapshotStartedUTC = [DateTime]::UtcNow.ToString('o')
    $buffer = [byte[]]::new(131072)
    $archivedBytes = [long]0
    $progressBytes = [long]0
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true, [Text.Encoding]::UTF8)
        foreach ($file in $selected) {
            $relative = $file.FullName.Substring($root.Length + 1).Replace('\', '/')
            $entryName = 'ReverseResearch/' + $relative
            $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
            $input = [IO.FileStream]::new($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $inputLength = $input.Length
            $output = $null
            $hash = [Security.Cryptography.SHA256]::Create()
            $copied = [long]0
            try {
                $output = $entry.Open()
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $output.Write($buffer, 0, $read)
                    [void]$hash.TransformBlock($buffer, 0, $read, $null, 0)
                    $copied += $read
                }
                [void]$hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
                $sha = [BitConverter]::ToString($hash.Hash).Replace('-', '').ToLowerInvariant()
            } finally {
                if ($output) { $output.Dispose() }
                $input.Dispose()
                $hash.Dispose()
            }
            if ($copied -ne $inputLength) { throw "Input changed while being read: $relative" }
            if ($inputLength -ne $file.Length) {
                if ($Profile -ne 'Full') { throw "Input length changed: $relative" }
                $updatedInputs.Add([ordered]@{ path = $relative; selectedBytes = $file.Length; capturedBytes = $inputLength })
                Write-Host ('[捕获更新] {0}' -f $relative)
            }
            $manifest.Add([ordered]@{ path = $relative; bytes = $copied; sha256 = $sha })
            $archivedBytes += $copied
            if ($manifest.Count % 5000 -eq 0 -or $archivedBytes - $progressBytes -ge 512MB) {
                Write-Host ('[压缩] {0}/{1} 文件，已读取 {2:N2} MiB' -f $manifest.Count, $selected.Count, ($archivedBytes / 1MB))
                $progressBytes = $archivedBytes
            }
        }
        $manifestBytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($manifest.ToArray()) -Depth 4 -Compress))
        $manifestEntry = $archive.CreateEntry('ReverseResearch/ARCHIVE-MANIFEST.json', [IO.Compression.CompressionLevel]::Optimal)
        $manifestStream = $manifestEntry.Open()
        try { $manifestStream.Write($manifestBytes, 0, $manifestBytes.Length) } finally { $manifestStream.Dispose() }
    } finally {
        try { if ($null -ne $archive) { $archive.Dispose() } }
        finally { $stream.Dispose() }
    }
    # Read every decompressed byte and compare its full SHA before publication.
    Write-Host '[校验] 正在逐文件解压核对 SHA-256。'
    $verification = [IO.Compression.ZipFile]::OpenRead($partialPath)
    try {
        if ($verification.Entries.Count -ne $manifest.Count + 1) { throw 'ZIP entry count differs from the selected manifest.' }
        $verifiedCount = 0
        foreach ($item in $manifest) {
            $entry = $verification.GetEntry('ReverseResearch/' + $item.path)
            if ($null -eq $entry -or $entry.Length -ne $item.bytes) { throw "ZIP entry/length mismatch: $($item.path)" }
            $entryStream = $entry.Open()
            $hasher = [Security.Cryptography.SHA256]::Create()
            try { $observed = [BitConverter]::ToString($hasher.ComputeHash($entryStream)).Replace('-', '').ToLowerInvariant() }
            finally { $entryStream.Dispose(); $hasher.Dispose() }
            if ($observed -ne $item.sha256) { throw "ZIP content mismatch: $($item.path)" }
            $verifiedCount++
            if ($verifiedCount % 5000 -eq 0) { Write-Host ('[校验] {0}/{1} 文件' -f $verifiedCount, $manifest.Count) }
        }
        $storedManifest = $verification.GetEntry('ReverseResearch/ARCHIVE-MANIFEST.json').Open()
        $reader = [IO.StreamReader]::new($storedManifest, [Text.Encoding]::UTF8)
        try { $stored = $reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($stored -ne [Text.Encoding]::UTF8.GetString($manifestBytes)) { throw 'ZIP manifest differs.' }
    } finally { $verification.Dispose() }
    [IO.File]::Move($partialPath, $zipPath)
    $createdPartial = $false
    $archiveHasher = [Security.Cryptography.SHA256]::Create()
    $archiveStream = [IO.File]::OpenRead($zipPath)
    try { $archiveSHA = [BitConverter]::ToString($archiveHasher.ComputeHash($archiveStream)).Replace('-', '').ToLowerInvariant() }
    finally { $archiveStream.Dispose(); $archiveHasher.Dispose() }
    [ordered]@{ status = 'PASS'; profile = $Profile; path = $zipPath; files = $manifest.Count; sourceBytes = $archivedBytes; archiveBytes = (Get-Item -LiteralPath $zipPath).Length; sha256 = $archiveSHA; allEntrySHA256Verified = $true; snapshotStartedUTC = $snapshotStartedUTC; completedUTC = [DateTime]::UtcNow.ToString('o'); updatedBeforeRead = @($updatedInputs.ToArray()) } |
        ConvertTo-Json | Set-Content -LiteralPath ($zipPath + '.receipt.json') -Encoding UTF8
    Write-Host ('[完成] ZIP 已保存："{0}"' -f $zipPath)
    Write-Host ('ZIP 大小：{0:N2} MiB' -f ((Get-Item -LiteralPath $zipPath).Length / 1MB))
} catch {
    Write-Host ('[失败] {0}' -f $_.Exception.Message)
    if ($createdPartial) { Write-Host ('[保留待核对] 未完成的 ZIP："{0}"' -f $partialPath) }
    exit 1
}

if ($NoOpen) { exit 0 }
try {
    Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"{0}"' -f $zipPath) -ErrorAction Stop
    Write-Host '[完成] 已请求打开文件夹并选中 ZIP。'
} catch {
    Write-Host ('[提示] ZIP 已生成，打开文件夹失败：{0}' -f $_.Exception.Message)
    exit 3
}
exit 0
