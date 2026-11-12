#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $RootPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string] $Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $CommitSha,

    [Parameter(Mandatory)]
    [ValidatePattern('^win-(x64|arm64)$')]
    [string] $RuntimeIdentifier,

    [Parameter(Mandatory)]
    [ValidateSet('Authenticode', 'UnsignedDevelopment')]
    [string] $SignatureMode,

    [datetimeoffset] $CreatedAtUtc = [datetimeoffset]::UtcNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $RootPath).Path
$rootInfo = Get-Item -LiteralPath $root -Force
if (-not $rootInfo.PSIsContainer -or $rootInfo.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
    throw 'The release root must be a regular directory.'
}

$manifestPath = Join-Path $root 'release-manifest.json'
$signaturePath = Join-Path $root 'release-manifest.p7s'
$files = [Collections.Generic.List[object]]::new()
foreach ($file in Get-ChildItem -LiteralPath $root -File -Recurse -Force | Sort-Object FullName) {
    if ($file.FullName -in @($manifestPath, $signaturePath)) {
        continue
    }

    if ($file.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "Release files cannot be reparse points: $($file.FullName)"
    }

    $relative = [IO.Path]::GetRelativePath($root, $file.FullName).Replace('\', '/')
    if ($relative -eq '..' -or $relative.StartsWith('../', [StringComparison]::Ordinal) -or
        [IO.Path]::IsPathRooted($relative)) {
        throw "Release file escaped the package root: $($file.FullName)"
    }

    $files.Add([ordered]@{
        path = $relative
        length = $file.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    })
}

if ($files.Count -eq 0) {
    throw 'The release package cannot be empty.'
}

$manifest = [ordered]@{
    schemaVersion = 1
    product = 'UtoAegis'
    version = $Version
    commitSha = $CommitSha.ToLowerInvariant()
    runtimeIdentifier = $RuntimeIdentifier
    createdAtUtc = $CreatedAtUtc.ToUniversalTime().ToString('o')
    signatureMode = $SignatureMode
    files = @($files | Sort-Object path)
}

$temporaryPath = "$manifestPath.$([Guid]::NewGuid().ToString('N')).tmp"
try {
    [IO.File]::WriteAllText(
        $temporaryPath,
        ($manifest | ConvertTo-Json -Depth 10) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporaryPath, $manifestPath, $true)
} finally {
    if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}

Write-Host "Created release manifest with $($files.Count) files at $manifestPath"
