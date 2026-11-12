#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $PublishDirectory,

    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string] $ServiceName = 'UtoAegisUpdater',

    [switch] $Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ConfiguredPath {
    param(
        [Parameter(Mandatory)]
        [string] $Value,
        [Parameter(Mandatory)]
        [string] $BaseDirectory
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Value.Trim())
    if ([IO.Path]::IsPathRooted($expanded)) {
        return [IO.Path]::GetFullPath($expanded)
    }

    return [IO.Path]::GetFullPath($expanded, $BaseDirectory)
}

function Assert-SafeDirectory {
    param(
        [Parameter(Mandatory)]
        [string] $Path,
        [Parameter(Mandatory)]
        [string] $InstallationDirectory
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -eq [IO.Path]::GetPathRoot($fullPath)) {
        throw "Refusing to use filesystem root as updater-writable storage: $fullPath"
    }

    $relativeToInstall = [IO.Path]::GetRelativePath($InstallationDirectory, $fullPath)
    $relativeToWritable = [IO.Path]::GetRelativePath($fullPath, $InstallationDirectory)
    foreach ($relative in @($relativeToInstall, $relativeToWritable)) {
        if ($relative -eq '.' -or
            (-not [IO.Path]::IsPathRooted($relative) -and
             $relative -ne '..' -and
             -not $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)"))) {
            throw "Updater-writable storage must be separate from the installation directory: $fullPath"
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
        [Parameter(Mandatory)]
        [string] $Path,
        [Parameter(Mandatory)]
        [string] $Identity,
        [Parameter(Mandatory)]
        [ValidateSet('RX', 'M')]
        [string] $Rights
    )

    $permission = if ($Rights -eq 'M') { '(OI)(CI)M' } else { '(OI)(CI)RX' }
    & "$env:SystemRoot\System32\icacls.exe" $Path /grant "${Identity}:$permission"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to grant $Rights access to $Path"
    }
}

$publish = (Resolve-Path -LiteralPath $PublishDirectory).Path
$executable = Join-Path $publish 'utoaegis-updater.exe'
$settingsPath = Join-Path $publish 'appsettings.json'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Updater executable not found: $executable"
}

if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw "Updater configuration not found: $settingsPath"
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service '$ServiceName' already exists. Remove it before reinstalling."
}

$document = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
$settings = $document.UtoAegisUpdater
$contentStore = Resolve-ConfiguredPath ([string]$settings.ContentStorePath) $publish
$downloadPath = Resolve-ConfiguredPath ([string]$settings.DownloadPath) $publish
$telemetryPath = Resolve-ConfiguredPath ([string]$settings.TelemetryPath) $publish
$telemetryDirectory = [IO.Path]::GetDirectoryName($telemetryPath)
$securityTelemetrySpool = Resolve-ConfiguredPath `
    ([string]$settings.SecurityTelemetrySpoolPath) $publish
$writableDirectories = @(
    $contentStore,
    $downloadPath,
    $telemetryDirectory,
    $securityTelemetrySpool
) | Where-Object { $null -ne $_ }
foreach ($directory in $writableDirectories) {
    Assert-SafeDirectory $directory $publish
}

$keyPaths = @(
    $settings.SigningKeys |
        ForEach-Object {
            Resolve-ConfiguredPath ([string]$_.PublicKeyPath) $publish
        }
)
foreach ($keyPath in $keyPaths) {
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        throw "Configured public key does not exist: $keyPath"
    }
}

if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Install and configure threat updater service')) {
    return
}

foreach ($directory in $writableDirectories) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

& $executable --validate-config
if ($LASTEXITCODE -ne 0) {
    throw 'Updater configuration validation failed.'
}

$serviceIdentity = "NT SERVICE\$ServiceName"
$binaryPath = '"' + $executable + '"'
$created = $false
try {
    Invoke-Sc create $ServiceName 'binPath=' $binaryPath 'start=' 'delayed-auto' `
        'error=' 'normal' 'obj=' $serviceIdentity 'DisplayName=' 'UtoAegis Threat Updater'
    $created = $true
    Invoke-Sc description $ServiceName 'Authenticated, rollback-protected UtoAegis threat-content retrieval and activation.'
    Invoke-Sc failure $ServiceName 'reset=' '86400' 'actions=' 'restart/60000/restart/300000'
    Invoke-Sc failureflag $ServiceName '1'

    Set-DirectoryGrant $publish $serviceIdentity 'RX'
    foreach ($directory in $writableDirectories) {
        Set-DirectoryGrant $directory $serviceIdentity 'M'
    }

    foreach ($keyPath in $keyPaths) {
        & "$env:SystemRoot\System32\icacls.exe" $keyPath /grant "${serviceIdentity}:R"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to grant read access to $keyPath"
        }
    }

    if (-not [Diagnostics.EventLog]::SourceExists('UtoAegisUpdater')) {
        New-EventLog -LogName Application -Source UtoAegisUpdater
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
