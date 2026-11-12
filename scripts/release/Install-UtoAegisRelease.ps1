#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ReleaseRoot,

    [Parameter(Mandatory)]
    [string] $InstallationRoot,

    [string[]] $AllowedSignerThumbprint = @(),

    [switch] $AllowUnsignedDevelopment,

    [ValidateRange(2, 10)]
    [int] $RetainVersions = 3,

    [switch] $PlanOnly,

    [string] $ServiceSnapshotPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Release installation requires an elevated PowerShell session.'
    }
}

function Get-ServiceExecutablePath {
    param([string] $PathName)

    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"', [StringComparison]::Ordinal)) {
        $closing = $trimmed.IndexOf('"', 1)
        if ($closing -lt 2) {
            throw "Service binary path is malformed: $PathName"
        }

        return [IO.Path]::GetFullPath($trimmed.Substring(1, $closing - 1))
    }

    $match = [regex]::Match($trimmed, '^(.+?\.exe)(?:\s|$)', 'IgnoreCase')
    if (-not $match.Success) {
        throw "Service binary path is malformed: $PathName"
    }

    return [IO.Path]::GetFullPath($match.Groups[1].Value)
}

function Invoke-Sc {
    param([string[]] $Arguments)

    & "$env:SystemRoot\System32\sc.exe" @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed with exit code $LASTEXITCODE."
    }
}

function Set-ServiceBinary {
    param([string] $Name, [string] $PathName)

    Invoke-Sc @('config', $Name, 'binPath=', $PathName)
}

function Write-AtomicJson {
    param([string] $Path, [object] $Value)

    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($Value | ConvertTo-Json -Depth 10) + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary, $Path, $true)
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($ServiceSnapshotPath) -and -not $PlanOnly) {
    throw 'ServiceSnapshotPath is accepted only with -PlanOnly.'
}

$release = (Resolve-Path -LiteralPath $ReleaseRoot).Path
& (Join-Path $PSScriptRoot 'Test-UtoAegisRelease.ps1') `
    -RootPath $release `
    -AllowedSignerThumbprint $AllowedSignerThumbprint `
    -AllowUnsignedDevelopment:$AllowUnsignedDevelopment
$manifest = Get-Content -LiteralPath (Join-Path $release 'release-manifest.json') -Raw |
    ConvertFrom-Json
$installation = [IO.Path]::GetFullPath($InstallationRoot, (Get-Location).Path)
if ($installation -eq [IO.Path]::GetPathRoot($installation)) {
    throw 'InstallationRoot cannot be a filesystem root.'
}

$releaseStore = Join-Path $installation 'releases'
$targetRoot = Join-Path $releaseStore ([string]$manifest.version)
if (Test-Path -LiteralPath $targetRoot) {
    throw "The target release is already staged: $targetRoot"
}

$componentDefinitions = [ordered]@{
    UtoAegis = [pscustomobject]@{
        RelativeBinary = 'services/monitor/utoaegis-service.exe'
        RelativeConfiguration = 'services/monitor/appsettings.json'
    }
    UtoAegisUpdater = [pscustomobject]@{
        RelativeBinary = 'services/updater/utoaegis-updater.exe'
        RelativeConfiguration = 'services/updater/appsettings.json'
    }
    UtoAegisTelemetry = [pscustomobject]@{
        RelativeBinary = 'services/telemetry/utoaegis-telemetry.exe'
        RelativeConfiguration = 'services/telemetry/appsettings.json'
    }
}
foreach ($definition in $componentDefinitions.Values) {
    foreach ($relative in @($definition.RelativeBinary, $definition.RelativeConfiguration)) {
        if (-not (Test-Path -LiteralPath (Join-Path $release $relative) -PathType Leaf)) {
            throw "The release is missing deployment component: $relative"
        }
    }
}

$inventory = if (-not [string]::IsNullOrWhiteSpace($ServiceSnapshotPath)) {
    $snapshot = Get-Content -LiteralPath $ServiceSnapshotPath -Raw | ConvertFrom-Json
    @($snapshot.services)
} else {
    @(
        foreach ($name in $componentDefinitions.Keys) {
            $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
            if ($null -ne $service) {
                [pscustomobject]@{
                    name = $service.Name
                    pathName = $service.PathName
                    state = $service.State
                }
            }
        }
    )
}

if ($inventory.Count -eq 0) {
    throw 'No installed UtoAegis services were found.'
}

$planItems = [Collections.Generic.List[object]]::new()
foreach ($service in $inventory) {
    $name = [string]$service.name
    if (-not $componentDefinitions.Contains($name)) {
        throw "The service snapshot contains an unsupported service: $name"
    }

    $currentExecutable = Get-ServiceExecutablePath ([string]$service.pathName)
    $currentConfiguration = Join-Path ([IO.Path]::GetDirectoryName($currentExecutable)) 'appsettings.json'
    if (-not (Test-Path -LiteralPath $currentExecutable -PathType Leaf) -or
        -not (Test-Path -LiteralPath $currentConfiguration -PathType Leaf)) {
        throw "The current binary or configuration is missing for service $name."
    }

    $definition = $componentDefinitions[$name]
    $planItems.Add([pscustomobject]@{
        name = $name
        currentPathName = [string]$service.pathName
        currentExecutable = $currentExecutable
        currentConfiguration = $currentConfiguration
        targetExecutable = Join-Path $targetRoot $definition.RelativeBinary
        targetConfiguration = Join-Path $targetRoot $definition.RelativeConfiguration
        relativeBinary = $definition.RelativeBinary
        relativeConfiguration = $definition.RelativeConfiguration
        wasRunning = ([string]$service.state -eq 'Running')
    })
}

$plan = [ordered]@{
    schemaVersion = 1
    releaseVersion = [string]$manifest.version
    signatureMode = [string]$manifest.signatureMode
    installationRoot = $installation
    targetRoot = $targetRoot
    retainVersions = $RetainVersions
    services = $planItems
}
if ($PlanOnly) {
    Write-Output ($plan | ConvertTo-Json -Depth 10)
    return
}

Assert-Administrator
if (Test-Path -LiteralPath $installation -PathType Container) {
    $installationInfo = Get-Item -LiteralPath $installation -Force
    if ($installationInfo.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw 'InstallationRoot cannot be a reparse point.'
    }
} else {
    New-Item -ItemType Directory -Path $installation -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $releaseStore -PathType Container)) {
    New-Item -ItemType Directory -Path $releaseStore -Force | Out-Null
}

$staging = Join-Path $releaseStore ".staging-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $staging | Out-Null
$changed = [Collections.Generic.List[object]]::new()
$targetCreated = $false
try {
    foreach ($item in Get-ChildItem -LiteralPath $release -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $staging -Recurse
    }

    foreach ($item in $planItems) {
        $stagedConfiguration = Join-Path $staging $item.relativeConfiguration
        Copy-Item -LiteralPath $item.currentConfiguration -Destination $stagedConfiguration -Force
        $stagedExecutable = Join-Path $staging $item.relativeBinary
        & $stagedExecutable --validate-config
        if ($LASTEXITCODE -ne 0) {
            throw "The staged configuration is invalid for service $($item.name)."
        }
    }

    Move-Item -LiteralPath $staging -Destination $targetRoot
    $targetCreated = $true
    foreach ($item in @($planItems | Sort-Object name -Descending)) {
        if ($item.wasRunning) {
            Stop-Service -Name $item.name -Force
            (Get-Service -Name $item.name).WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(30))
        }
    }

    foreach ($item in $planItems) {
        Set-ServiceBinary $item.name ('"' + $item.targetExecutable + '"')
        $changed.Add($item)
    }

    foreach ($item in $planItems) {
        if ($item.wasRunning) {
            Start-Service -Name $item.name
            (Get-Service -Name $item.name).WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(30))
        }
    }

    $statePath = Join-Path $installation 'deployment-state.json'
    $oldState = if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    } else {
        $null
    }
    $state = [ordered]@{
        schemaVersion = 1
        currentVersion = [string]$manifest.version
        currentRoot = $targetRoot
        previousVersion = $(if ($null -eq $oldState) { $null } else { $oldState.currentVersion })
        previousRoot = $(if ($null -eq $oldState) { $null } else { $oldState.currentRoot })
        signatureMode = [string]$manifest.signatureMode
        installedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
        services = @(
            $planItems | ForEach-Object {
                [ordered]@{
                    name = $_.name
                    currentPathName = '"' + $_.targetExecutable + '"'
                    previousPathName = $_.currentPathName
                    wasRunning = $_.wasRunning
                }
            }
        )
    }
    Write-AtomicJson $statePath $state

    $protected = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    [void]$protected.Add($targetRoot)
    if ($null -ne $state.previousRoot) {
        [void]$protected.Add([IO.Path]::GetFullPath([string]$state.previousRoot))
    }

    $versions = @(
        Get-ChildItem -LiteralPath $releaseStore -Directory |
            Where-Object {
                -not $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -and
                $_.Name -match '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$' -and
                -not $protected.Contains($_.FullName)
            } |
            Sort-Object LastWriteTimeUtc -Descending
    )
    $keepAdditional = [Math]::Max(0, $RetainVersions - $protected.Count)
    foreach ($oldVersion in @($versions | Select-Object -Skip $keepAdditional)) {
        $releasePrefix = [IO.Path]::TrimEndingDirectorySeparator($releaseStore) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $oldVersion.FullName.StartsWith(
                $releasePrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to prune a release outside the release store.'
        }

        Remove-Item -LiteralPath $oldVersion.FullName -Recurse -Force
    }
} catch {
    $rollbackFailed = $false
    foreach ($item in @($changed | Sort-Object name -Descending)) {
        try {
            $service = Get-Service -Name $item.name -ErrorAction SilentlyContinue
            if ($null -ne $service -and $service.Status -ne 'Stopped') {
                Stop-Service -Name $item.name -Force -ErrorAction SilentlyContinue
            }
            Set-ServiceBinary $item.name $item.currentPathName
        } catch {
            $rollbackFailed = $true
            Write-Warning "Automatic rollback failed for service $($item.name): $_"
        }
    }

    foreach ($item in $planItems) {
        if ($item.wasRunning) {
            try {
                $service = Get-Service -Name $item.name -ErrorAction SilentlyContinue
                if ($null -ne $service -and $service.Status -ne 'Running') {
                    Start-Service -Name $item.name
                }
            } catch {
                $rollbackFailed = $true
                Write-Warning "Automatic service restart failed for $($item.name): $_"
            }
        }
    }

    if ($targetCreated -and -not $rollbackFailed -and
        (Test-Path -LiteralPath $targetRoot -PathType Container)) {
        Remove-Item -LiteralPath $targetRoot -Recurse -Force
    }
    throw
} finally {
    if (Test-Path -LiteralPath $staging -PathType Container) {
        $resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
        $storePrefix = [IO.Path]::TrimEndingDirectorySeparator($releaseStore) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedStaging.StartsWith($storePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a staging directory outside the release store.'
        }

        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}

Write-Host "Installed UtoAegis $($manifest.version). Rollback state: $(Join-Path $installation 'deployment-state.json')"
