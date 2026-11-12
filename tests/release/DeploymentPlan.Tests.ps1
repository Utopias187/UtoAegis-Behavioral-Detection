#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "UtoAegis.Deployment.Tests.$([Guid]::NewGuid().ToString('N'))"
try {
    $release = Join-Path $temporaryRoot 'release'
    $old = Join-Path $temporaryRoot 'old'
    $installation = Join-Path $temporaryRoot 'installation'
    foreach ($relative in @(
            'services/monitor', 'services/updater', 'services/telemetry')) {
        New-Item -ItemType Directory -Path (Join-Path $release $relative) -Force | Out-Null
    }
    New-Item -ItemType Directory -Path $old -Force | Out-Null

    $payloads = [ordered]@{
        'services/monitor/utoaegis-service.exe' = 'monitor'
        'services/updater/utoaegis-updater.exe' = 'updater'
        'services/telemetry/utoaegis-telemetry.exe' = 'telemetry'
    }
    foreach ($payload in $payloads.GetEnumerator()) {
        [IO.File]::WriteAllText(
            (Join-Path $release $payload.Key),
            $payload.Value,
            [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText(
            (Join-Path ([IO.Path]::GetDirectoryName((Join-Path $release $payload.Key))) 'appsettings.json'),
            '{}',
            [Text.UTF8Encoding]::new($false))
    }

    $oldExecutable = Join-Path $old 'utoaegis-service.exe'
    [IO.File]::WriteAllText($oldExecutable, 'old monitor', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $old 'appsettings.json'),
        '{}',
        [Text.UTF8Encoding]::new($false))
    $commit = '0123456789abcdef0123456789abcdef01234567'
    $timestamp = [datetimeoffset]'2026-11-11T18:00:00Z'
    & (Join-Path $repositoryRoot 'scripts/release/New-UtoAegisSbom.ps1') `
        -Version '13.0.0' `
        -CommitSha $commit `
        -TimestampUtc $timestamp `
        -RepositoryRoot $repositoryRoot `
        -OutputPath (Join-Path $release 'sbom.cdx.json')
    & (Join-Path $repositoryRoot 'scripts/release/New-UtoAegisReleaseManifest.ps1') `
        -RootPath $release `
        -Version '13.0.0' `
        -CommitSha $commit `
        -RuntimeIdentifier win-x64 `
        -SignatureMode UnsignedDevelopment `
        -CreatedAtUtc $timestamp

    $snapshotPath = Join-Path $temporaryRoot 'services.json'
    $snapshot = [ordered]@{
        services = @(
            [ordered]@{
                name = 'UtoAegis'
                pathName = '"' + $oldExecutable + '"'
                state = 'Running'
            }
        )
    }
    [IO.File]::WriteAllText(
        $snapshotPath,
        ($snapshot | ConvertTo-Json -Depth 5),
        [Text.UTF8Encoding]::new($false))
    $json = & (Join-Path $repositoryRoot 'scripts/release/Install-UtoAegisRelease.ps1') `
        -ReleaseRoot $release `
        -InstallationRoot $installation `
        -AllowUnsignedDevelopment `
        -PlanOnly `
        -ServiceSnapshotPath $snapshotPath
    $plan = $json | ConvertFrom-Json
    if ($plan.releaseVersion -ne '13.0.0' -or
        @($plan.services).Count -ne 1 -or
        $plan.services[0].name -ne 'UtoAegis' -or
        -not $plan.services[0].targetExecutable.EndsWith(
            'releases\13.0.0\services\monitor\utoaegis-service.exe',
            [StringComparison]::OrdinalIgnoreCase) -or
        (Test-Path -LiteralPath $installation)) {
        throw 'The deployment plan is invalid or PlanOnly changed the filesystem.'
    }

    Write-Host 'Deployment plan tests passed.'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
        $resolved = (Resolve-Path -LiteralPath $temporaryRoot).Path
        $tempPrefix = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetTempPath()) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a deployment test directory outside the temporary root.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
