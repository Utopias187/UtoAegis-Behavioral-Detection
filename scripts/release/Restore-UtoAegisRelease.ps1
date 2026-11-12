#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $InstallationRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Sc {
    param([string[]] $Arguments)

    & "$env:SystemRoot\System32\sc.exe" @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed with exit code $LASTEXITCODE."
    }
}

function Get-ExecutablePath {
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

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Release rollback requires an elevated PowerShell session.'
}

$installation = (Resolve-Path -LiteralPath $InstallationRoot).Path
$statePath = Join-Path $installation 'deployment-state.json'
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw 'Deployment state is missing.'
}

$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.schemaVersion -ne 1 -or @($state.services).Count -eq 0) {
    throw 'Deployment state is invalid.'
}

foreach ($service in @($state.services)) {
    $previousExecutable = Get-ExecutablePath ([string]$service.previousPathName)
    if (-not (Test-Path -LiteralPath $previousExecutable -PathType Leaf) -or
        -not (Test-Path -LiteralPath (
                Join-Path ([IO.Path]::GetDirectoryName($previousExecutable)) 'appsettings.json') `
            -PathType Leaf)) {
        throw "Rollback target is missing for service $($service.name)."
    }
}

if (-not $PSCmdlet.ShouldProcess(
        "UtoAegis $($state.currentVersion)",
        "Restore previous release $($state.previousVersion)")) {
    return
}

$changed = [Collections.Generic.List[object]]::new()
try {
    foreach ($service in @($state.services | Sort-Object name -Descending)) {
        $controller = Get-Service -Name $service.name
        if ($controller.Status -ne 'Stopped') {
            Stop-Service -Name $service.name -Force
            $controller.WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(30))
        }
    }

    foreach ($service in @($state.services)) {
        Invoke-Sc @('config', [string]$service.name, 'binPath=', [string]$service.previousPathName)
        $changed.Add($service)
    }

    foreach ($service in @($state.services)) {
        if ([bool]$service.wasRunning) {
            Start-Service -Name $service.name
            (Get-Service -Name $service.name).WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(30))
        }
    }
} catch {
    foreach ($service in @($changed | Sort-Object name -Descending)) {
        try {
            Invoke-Sc @('config', [string]$service.name, 'binPath=', [string]$service.currentPathName)
        } catch {
            Write-Warning "Failed to restore current service path for $($service.name): $_"
        }
    }

    foreach ($service in @($state.services)) {
        if ([bool]$service.wasRunning) {
            Start-Service -Name $service.name -ErrorAction SilentlyContinue
        }
    }
    throw
}

$newState = [ordered]@{
    schemaVersion = 1
    currentVersion = $state.previousVersion
    currentRoot = $state.previousRoot
    previousVersion = $state.currentVersion
    previousRoot = $state.currentRoot
    signatureMode = $state.signatureMode
    installedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
    services = @(
        $state.services | ForEach-Object {
            [ordered]@{
                name = $_.name
                currentPathName = $_.previousPathName
                previousPathName = $_.currentPathName
                wasRunning = $_.wasRunning
            }
        }
    )
}
$temporary = "$statePath.$([Guid]::NewGuid().ToString('N')).tmp"
try {
    [IO.File]::WriteAllText(
        $temporary,
        ($newState | ConvertTo-Json -Depth 10) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary, $statePath, $true)
} finally {
    if (Test-Path -LiteralPath $temporary -PathType Leaf) {
        Remove-Item -LiteralPath $temporary -Force
    }
}

Write-Host "Restored UtoAegis $($newState.currentVersion)."
