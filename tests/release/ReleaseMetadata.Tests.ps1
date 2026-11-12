#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "UtoAegis.Release.Tests.$([Guid]::NewGuid().ToString('N'))"
try {
    New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'monitor') -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $temporaryRoot 'monitor/utoaegis-service.exe'),
        'harmless release fixture',
        [Text.UTF8Encoding]::new($false))
    $commit = '0123456789abcdef0123456789abcdef01234567'
    $timestamp = [datetimeoffset]'2026-11-11T18:00:00Z'

    & (Join-Path $repositoryRoot 'scripts/release/New-UtoAegisSbom.ps1') `
        -Version '13.0.0' `
        -CommitSha $commit `
        -TimestampUtc $timestamp `
        -RepositoryRoot $repositoryRoot `
        -OutputPath (Join-Path $temporaryRoot 'sbom.cdx.json')
    & (Join-Path $repositoryRoot 'scripts/release/New-UtoAegisReleaseManifest.ps1') `
        -RootPath $temporaryRoot `
        -Version '13.0.0' `
        -CommitSha $commit `
        -RuntimeIdentifier 'win-x64' `
        -SignatureMode UnsignedDevelopment `
        -CreatedAtUtc $timestamp
    & (Join-Path $repositoryRoot 'scripts/release/Test-UtoAegisRelease.ps1') `
        -RootPath $temporaryRoot `
        -AllowUnsignedDevelopment

    Add-Content -LiteralPath (Join-Path $temporaryRoot 'monitor/utoaegis-service.exe') 'tampered'
    $rejected = $false
    try {
        & (Join-Path $repositoryRoot 'scripts/release/Test-UtoAegisRelease.ps1') `
            -RootPath $temporaryRoot `
            -AllowUnsignedDevelopment
    } catch {
        $rejected = $true
    }

    if (-not $rejected) {
        throw 'The release verifier accepted a modified file.'
    }

    Write-Host 'Release metadata tests passed.'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
        $resolved = (Resolve-Path -LiteralPath $temporaryRoot).Path
        $tempPrefix = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetTempPath()) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a release test directory outside the temporary root.'
        }

        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
