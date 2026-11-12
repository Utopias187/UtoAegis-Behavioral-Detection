#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $PublishDirectory,

    [ValidatePattern('^[A-Za-z0-9 _.-]{1,120}$')]
    [string] $TaskName = 'UtoAegis Integrity Guard',

    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string] $MonitorServiceName = 'UtoAegis',

    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string] $TelemetryServiceName = 'UtoAegisTelemetry',

    [ValidateRange(5, 1440)]
    [int] $IntervalMinutes = 5,

    [switch] $EnableRecovery,

    [switch] $Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ConfiguredPath {
    param([string] $Value, [string] $BaseDirectory)

    return [IO.Path]::GetFullPath(
        [Environment]::ExpandEnvironmentVariables($Value.Trim()),
        $BaseDirectory)
}

function Set-ProtectedDirectoryAcl {
    param([string] $Path, [string[]] $AdditionalGrant, [switch] $Create)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -eq [IO.Path]::GetPathRoot($fullPath)) {
        throw "Refusing to modify ACLs on filesystem root $fullPath"
    }

    if ($Create -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "Required directory does not exist: $fullPath"
    }

    $arguments = @($fullPath, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F') + $AdditionalGrant
    & "$env:SystemRoot\System32\icacls.exe" @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to protect directory $fullPath"
    }
}

function Set-ProtectedFileAcl {
    param([string] $Path, [string[]] $AdditionalGrant)

    $fullPath = (Resolve-Path -LiteralPath $Path).Path
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.PSIsContainer -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "Protected policy keys must be regular files: $fullPath"
    }

    $arguments = @($fullPath, '/inheritance:r', '/grant:r',
        '*S-1-5-18:F', '*S-1-5-32-544:F') + $AdditionalGrant
    & "$env:SystemRoot\System32\icacls.exe" @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to protect file $fullPath"
    }
}

$publish = (Resolve-Path -LiteralPath $PublishDirectory).Path
$executable = Join-Path $publish 'utoaegis-guard.exe'
$settingsPath = Join-Path $publish 'appsettings.json'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf) -or
    -not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw 'The guard executable and appsettings.json must exist in PublishDirectory.'
}

if ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
    throw "Scheduled task '$TaskName' already exists."
}

$settings = (Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json).UtoAegisGuard
$policyBundle = Resolve-ConfiguredPath ([string]$settings.PolicyBundlePath) $publish
$policyState = Resolve-ConfiguredPath ([string]$settings.PolicyStatePath) $publish
$recoveryState = Resolve-ConfiguredPath ([string]$settings.RecoveryStatePath) $publish
$telemetrySpool = Resolve-ConfiguredPath ([string]$settings.SecurityTelemetrySpoolPath) $publish
$policyKeys = @($settings.TrustedSigningKeys | ForEach-Object {
    Resolve-ConfiguredPath ([string]$_.PublicKeyPath) $publish
})
$monitorIdentity = "NT SERVICE\$MonitorServiceName"
$telemetryIdentity = "NT SERVICE\$TelemetryServiceName"

if (-not $PSCmdlet.ShouldProcess($TaskName, 'Protect guard files and register scheduled integrity audits')) {
    return
}

Set-ProtectedDirectoryAcl $publish @()
Set-ProtectedDirectoryAcl $policyBundle @("${monitorIdentity}:(OI)(CI)RX")
Set-ProtectedDirectoryAcl ([IO.Path]::GetDirectoryName($policyState)) `
    @("${monitorIdentity}:(OI)(CI)M") -Create
Set-ProtectedDirectoryAcl ([IO.Path]::GetDirectoryName($recoveryState)) @() -Create
Set-ProtectedDirectoryAcl $telemetrySpool @("${telemetryIdentity}:(OI)(CI)RX") -Create
foreach ($policyKey in $policyKeys) {
    Set-ProtectedFileAcl $policyKey @("${monitorIdentity}:R")
}

& $executable --validate-config
if ($LASTEXITCODE -ne 0) {
    throw 'Integrity guard configuration or signed policy validation failed.'
}

$actionArguments = if ($EnableRecovery) { '--recover' } else { '' }
$action = New-ScheduledTaskAction `
    -Execute $executable `
    -Argument $actionArguments `
    -WorkingDirectory $publish
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At ([datetime]::Now.AddMinutes(1)) `
    -RepetitionInterval ([timespan]::FromMinutes($IntervalMinutes))
$principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([timespan]::FromMinutes(10)) `
    -StartWhenAvailable
$task = New-ScheduledTask `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $taskSettings `
    -Description 'Audits UtoAegis service configuration, executable hashes, and protected ACLs against authenticated runtime policy.'
Register-ScheduledTask -TaskName $TaskName -InputObject $task | Out-Null
if ($Start) {
    Start-ScheduledTask -TaskName $TaskName
}

$mode = if ($EnableRecovery) { 'bounded recovery' } else { 'audit only' }
Write-Host "Installed scheduled task '$TaskName' in $mode mode at a $IntervalMinutes-minute interval."
