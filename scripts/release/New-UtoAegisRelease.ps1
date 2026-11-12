#Requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Signed')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string] $Version,

    [Parameter(Mandatory)]
    [string] $OutputDirectory,

    [ValidatePattern('^win-(x64|arm64)$')]
    [string] $RuntimeIdentifier = 'win-x64',

    [Parameter(Mandatory, ParameterSetName = 'Signed')]
    [ValidatePattern('^[0-9a-fA-F ]{40,59}$')]
    [string] $CertificateThumbprint,

    [Parameter(ParameterSetName = 'Signed')]
    [uri] $TimestampServer = 'https://timestamp.digicert.com',

    [Parameter(Mandatory, ParameterSetName = 'UnsignedDevelopment')]
    [switch] $UnsignedDevelopment,

    [Parameter(ParameterSetName = 'UnsignedDevelopment')]
    [switch] $AllowDirtyDevelopment,

    [string] $SignToolPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-DotNet {
    param([string[]] $Arguments, [string] $FailureMessage)

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

function New-DeterministicZip {
    param([string] $SourceRoot, [string] $DestinationPath, [datetimeoffset] $Timestamp)

    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::Open(
        $DestinationPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            $entryTimestamp = $Timestamp.ToUniversalTime()
            if ($entryTimestamp.Year -lt 1980) {
                $entryTimestamp = [datetimeoffset]'1980-01-01T00:00:00Z'
            }

            foreach ($file in Get-ChildItem -LiteralPath $SourceRoot -File -Recurse |
                         Sort-Object FullName) {
                $relative = [IO.Path]::GetRelativePath($SourceRoot, $file.FullName).Replace('\', '/')
                $entry = $archive.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $entryTimestamp
                $input = [IO.File]::OpenRead($file.FullName)
                try {
                    $output = $entry.Open()
                    try {
                        $input.CopyTo($output)
                    } finally {
                        $output.Dispose()
                    }
                } finally {
                    $input.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$status = @(& git -C $repositoryRoot status --porcelain)
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to inspect the Git working tree.'
}

if ($status.Count -gt 0 -and -not $AllowDirtyDevelopment) {
    throw 'Release creation requires a clean Git working tree.'
}

$commitSha = (& git -C $repositoryRoot rev-parse HEAD).Trim()
$commitTimestampText = (& git -C $repositoryRoot show -s --format=%cI HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commitSha -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve the release commit.'
}

$commitTimestamp = [datetimeoffset]::Parse(
    $commitTimestampText,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::RoundtripKind)
$output = [IO.Path]::GetFullPath($OutputDirectory, (Get-Location).Path)
if (-not (Test-Path -LiteralPath $output -PathType Container)) {
    New-Item -ItemType Directory -Path $output -Force | Out-Null
}

$output = (Resolve-Path -LiteralPath $output).Path
$packageName = "UtoAegis-$Version-$RuntimeIdentifier"
$packagePath = Join-Path $output $packageName
$archivePath = Join-Path $output "$packageName.zip"
$checksumPath = Join-Path $output "$packageName.SHA256SUMS"
foreach ($target in @($packagePath, $archivePath, $checksumPath)) {
    if (Test-Path -LiteralPath $target) {
        throw "Release output already exists: $target"
    }
}

$staging = Join-Path $output ".staging-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $staging | Out-Null
try {
    $solution = Join-Path $repositoryRoot 'UtoAegis.slnx'
    Invoke-DotNet @('restore', $solution, '--locked-mode', '--disable-parallel') `
        'Locked dependency restore failed.'
    Invoke-DotNet @(
        'test', $solution, '--configuration', 'Release', '--no-restore',
        '-m:1', '-p:UseSharedCompilation=false', '-p:BuildInParallel=false'
    ) 'Release tests failed.'

    $publications = [ordered]@{
        'services/monitor' = 'src/UtoAegis.Service/UtoAegis.Service.csproj'
        'services/updater' = 'src/UtoAegis.Updater/UtoAegis.Updater.csproj'
        'services/telemetry' = 'src/UtoAegis.Telemetry/UtoAegis.Telemetry.csproj'
        'tools' = 'src/UtoAegis.Cli/UtoAegis.Cli.csproj'
        'tools/guard' = 'src/UtoAegis.Guard/UtoAegis.Guard.csproj'
    }
    foreach ($publication in $publications.GetEnumerator()) {
        $project = Join-Path $repositoryRoot $publication.Value
        $destination = Join-Path $staging $publication.Key
        Invoke-DotNet @(
            'publish', $project, '--configuration', 'Release',
            '--runtime', $RuntimeIdentifier, '--self-contained', 'false',
            '--output', $destination, '-p:RestoreLockedMode=true',
            "-p:Version=$Version", '-p:ContinuousIntegrationBuild=true',
            '-p:UseSharedCompilation=false'
        ) "Publication failed for $($publication.Value)."
    }

    $deploymentPath = Join-Path $staging 'deployment'
    New-Item -ItemType Directory -Path $deploymentPath | Out-Null
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'scripts/windows') `
        -Destination $deploymentPath -Recurse
    foreach ($releaseScript in @(
            'Test-UtoAegisRelease.ps1',
            'Install-UtoAegisRelease.ps1',
            'Restore-UtoAegisRelease.ps1',
            'Test-UtoAegisServiceRecovery.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $releaseScript) `
            -Destination $deploymentPath
    }
    foreach ($document in @('LICENSE', 'THIRD-PARTY-NOTICES.md', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $document) -Destination $staging
    }

    & (Join-Path $PSScriptRoot 'New-UtoAegisSbom.ps1') `
        -Version $Version `
        -CommitSha $commitSha `
        -TimestampUtc $commitTimestamp `
        -RepositoryRoot $repositoryRoot `
        -OutputPath (Join-Path $staging 'sbom.cdx.json')

    if ($UnsignedDevelopment) {
        & (Join-Path $PSScriptRoot 'New-UtoAegisReleaseManifest.ps1') `
            -RootPath $staging `
            -Version $Version `
            -CommitSha $commitSha `
            -RuntimeIdentifier $RuntimeIdentifier `
            -SignatureMode UnsignedDevelopment `
            -CreatedAtUtc $commitTimestamp
        & (Join-Path $PSScriptRoot 'Test-UtoAegisRelease.ps1') `
            -RootPath $staging `
            -AllowUnsignedDevelopment
    } else {
        & (Join-Path $PSScriptRoot 'Protect-UtoAegisRelease.ps1') `
            -RootPath $staging `
            -Version $Version `
            -CommitSha $commitSha `
            -RuntimeIdentifier $RuntimeIdentifier `
            -CertificateThumbprint $CertificateThumbprint `
            -TimestampServer $TimestampServer `
            -CreatedAtUtc $commitTimestamp `
            -SignToolPath $SignToolPath
    }

    Move-Item -LiteralPath $staging -Destination $packagePath
    New-DeterministicZip $packagePath $archivePath $commitTimestamp
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        $checksumPath,
        "$archiveHash  $([IO.Path]::GetFileName($archivePath))$([Environment]::NewLine)",
        [Text.UTF8Encoding]::new($false))
} finally {
    if (Test-Path -LiteralPath $staging -PathType Container) {
        $resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
        $outputPrefix = [IO.Path]::TrimEndingDirectorySeparator($output) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedStaging.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a staging directory outside the release output.'
        }

        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}

Write-Host "Created release directory: $packagePath"
Write-Host "Created release archive: $archivePath"
Write-Host "Created archive checksum: $checksumPath"
