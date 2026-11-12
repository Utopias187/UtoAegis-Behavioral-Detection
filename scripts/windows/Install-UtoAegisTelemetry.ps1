#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $PublishDirectory,

    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string] $ServiceName = 'UtoAegisTelemetry',

    [switch] $Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ConfiguredPath {
    param(
        [Parameter(Mandatory)][string] $Value,
        [Parameter(Mandatory)][string] $BaseDirectory
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Value.Trim())
    if ([IO.Path]::IsPathRooted($expanded)) {
        return [IO.Path]::GetFullPath($expanded)
    }

    return [IO.Path]::GetFullPath($expanded, $BaseDirectory)
}

function Assert-SafeStateDirectory {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $InstallationDirectory
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -eq [IO.Path]::GetPathRoot($fullPath)) {
        throw "Refusing to use a filesystem root as telemetry state: $fullPath"
    }

    foreach ($relative in @(
        [IO.Path]::GetRelativePath($InstallationDirectory, $fullPath),
        [IO.Path]::GetRelativePath($fullPath, $InstallationDirectory))) {
        if ($relative -eq '.' -or
            (-not [IO.Path]::IsPathRooted($relative) -and
             $relative -ne '..' -and
             -not $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)"))) {
            throw "Telemetry state must be separate from the installation directory: $fullPath"
        }
    }
}

function Invoke-Sc {
    param([Parameter(ValueFromRemainingArguments)][string[]] $Arguments)

    & "$env:SystemRoot\System32\sc.exe" @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed with exit code $LASTEXITCODE."
    }
}

function Set-DirectoryGrant {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Identity,
        [Parameter(Mandatory)][ValidateSet('RX', 'M')][string] $Rights
    )

    $permission = if ($Rights -eq 'M') { '(OI)(CI)M' } else { '(OI)(CI)RX' }
    & "$env:SystemRoot\System32\icacls.exe" $Path /grant "${Identity}:$permission"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to grant $Rights access to $Path"
    }
}

$publish = (Resolve-Path -LiteralPath $PublishDirectory).Path
$executable = Join-Path $publish 'utoaegis-telemetry.exe'
$settingsPath = Join-Path $publish 'appsettings.json'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Telemetry executable not found: $executable"
}

if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw "Telemetry configuration not found: $settingsPath"
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service '$ServiceName' already exists. Remove it before reinstalling."
}

$settings = (Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json).UtoAegisTelemetry
$statePath = Resolve-ConfiguredPath ([string]$settings.StatePath) $publish
$keyPath = Resolve-ConfiguredPath ([string]$settings.AuthenticationKeyPath) $publish
$sourcePaths = @(
    $settings.Sources | ForEach-Object {
        Resolve-ConfiguredPath ([string]$_.SpoolPath) $publish
    }
)
Assert-SafeStateDirectory $statePath $publish
if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
    throw "Collector authentication key not found: $keyPath"
}

foreach ($sourcePath in $sourcePaths) {
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
        throw "Telemetry source spool not found: $sourcePath"
    }
}

if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Install authenticated telemetry forwarder service')) {
    return
}

if (-not (Test-Path -LiteralPath $statePath -PathType Container)) {
    New-Item -ItemType Directory -Path $statePath -Force | Out-Null
}

& $executable --validate-config
if ($LASTEXITCODE -ne 0) {
    throw 'Telemetry configuration validation failed.'
}

$serviceIdentity = "NT SERVICE\$ServiceName"
$binaryPath = '"' + $executable + '"'
$created = $false
try {
    Invoke-Sc create $ServiceName 'binPath=' $binaryPath 'start=' 'delayed-auto' `
        'error=' 'normal' 'obj=' $serviceIdentity 'DisplayName=' 'UtoAegis Telemetry Forwarder'
    $created = $true
    Invoke-Sc description $ServiceName 'Authenticated forwarding of bounded tamper-evident UtoAegis security telemetry.'
    Invoke-Sc failure $ServiceName 'reset=' '86400' 'actions=' 'restart/60000/restart/300000'
    Invoke-Sc failureflag $ServiceName '1'

    Set-DirectoryGrant $publish $serviceIdentity 'RX'
    Set-DirectoryGrant $statePath $serviceIdentity 'M'
    foreach ($sourcePath in $sourcePaths) {
        Set-DirectoryGrant $sourcePath $serviceIdentity 'RX'
    }

    & "$env:SystemRoot\System32\icacls.exe" $keyPath /grant "${serviceIdentity}:R"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to grant read access to $keyPath"
    }

    if (-not [Diagnostics.EventLog]::SourceExists('UtoAegisTelemetry')) {
        New-EventLog -LogName Application -Source UtoAegisTelemetry
    }

    if ($Start) {
        Start-Service -Name $ServiceName
    }
} catch {
    if ($created) {
        & "$env:SystemRoot\System32\sc.exe" delete $ServiceName | Out-Null
    }

    throw
}

Write-Host "Installed $ServiceName as $serviceIdentity."
if (-not $Start) {
    Write-Host "Start it with: Start-Service -Name '$ServiceName'"
}
