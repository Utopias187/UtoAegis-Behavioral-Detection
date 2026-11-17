#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Install', 'Repair', 'Rotate', 'Remove')]
    [string] $Action,

    [Parameter(Mandatory)]
    [string] $AssemblyDirectory,

    [string] $StateDirectory = (Join-Path $env:ProgramData 'UtoAegis\Management'),

    [ValidatePattern('^[A-Za-z0-9_.:-]{1,128}$')]
    [string] $KeyName = 'UtoAegis.Device.Identity',

    [ValidatePattern('^[A-Fa-f0-9]{32}$')]
    [string] $ExpectedDeviceId,

    [string] $ArchiveDirectory,

    [ValidatePattern('^[A-Za-z0-9_.\\ -]{1,256}$')]
    [string] $StateConsumerIdentity = 'SYSTEM'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-SafeDirectory {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Description,
        [switch] $MustExist
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -eq [IO.Path]::GetPathRoot($fullPath)) {
        throw "$Description cannot be a filesystem root."
    }

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "$Description does not exist: $fullPath"
    }

    if (Test-Path -LiteralPath $fullPath) {
        $item = Get-Item -LiteralPath $fullPath -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "$Description must be a regular directory without a reparse point."
        }
    }

    return $fullPath
}

function Set-EnrollmentDirectoryAcl {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $ConsumerIdentity
    )

    & "$env:SystemRoot\System32\icacls.exe" $Path /inheritance:r /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to disable inherited ACLs on $Path"
    }

    $arguments = @(
        $Path,
        '/grant:r',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F'
    )
    if ($ConsumerIdentity -notin @('SYSTEM', 'NT AUTHORITY\SYSTEM', '*S-1-5-18')) {
        $arguments += "${ConsumerIdentity}:(OI)(CI)M"
    }
    $arguments += @('/T', '/C')
    & "$env:SystemRoot\System32\icacls.exe" @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to apply enrollment ACLs to $Path"
    }
}

if ($Action -in @('Rotate', 'Remove') -and [string]::IsNullOrWhiteSpace($ExpectedDeviceId)) {
    throw "$Action requires -ExpectedDeviceId with the exact current device ID."
}

$assemblies = Resolve-SafeDirectory $AssemblyDirectory 'AssemblyDirectory' -MustExist
$coreAssembly = Join-Path $assemblies 'UtoAegis.Core.dll'
$infrastructureAssembly = Join-Path $assemblies 'UtoAegis.Infrastructure.dll'
foreach ($assembly in @($coreAssembly, $infrastructureAssembly)) {
    if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) {
        throw "Required assembly not found: $assembly"
    }
}

$stateRoot = Resolve-SafeDirectory $StateDirectory 'StateDirectory'
$archiveRoot = if ([string]::IsNullOrWhiteSpace($ArchiveDirectory)) {
    Join-Path $stateRoot 'Archive'
} else {
    Resolve-SafeDirectory $ArchiveDirectory 'ArchiveDirectory'
}
$relativeArchive = [IO.Path]::GetRelativePath($stateRoot, $archiveRoot)
if ([IO.Path]::IsPathRooted($relativeArchive) -or
    $relativeArchive -eq '..' -or
    $relativeArchive.StartsWith('..' + [IO.Path]::DirectorySeparatorChar)) {
    throw 'ArchiveDirectory must be inside StateDirectory.'
}

if (-not $PSCmdlet.ShouldProcess($stateRoot, "$Action UtoAegis endpoint identity")) {
    return
}

[IO.Directory]::CreateDirectory($stateRoot) | Out-Null
[IO.Directory]::CreateDirectory($archiveRoot) | Out-Null
Set-EnrollmentDirectoryAcl $stateRoot $StateConsumerIdentity

Add-Type -Path $coreAssembly
Add-Type -Path $infrastructureAssembly

$statePath = Join-Path $stateRoot 'identity.json'
$stateStore = [UtoAegis.Infrastructure.Management.DeviceIdentityStateStore]::new($statePath)
$keyStore = [UtoAegis.Infrastructure.Management.WindowsDeviceIdentityKeyStore]::new($KeyName)
$context = $null
$archivePath = $null
$identity = $null
try {
    switch ($Action) {
        'Install' {
            $operation = $keyStore.CreateOrLoadAsync(
                $stateStore,
                $null,
                [Threading.CancellationToken]::None)
            $context = $operation.AsTask().GetAwaiter().GetResult()
            $identity = $context.Identity
        }
        'Repair' {
            $operation = $keyStore.ValidateAsync(
                $stateStore,
                [Threading.CancellationToken]::None)
            $context = $operation.AsTask().GetAwaiter().GetResult()
            $identity = $context.Identity
        }
        'Rotate' {
            $archivePath = Join-Path $archiveRoot (
                'identity-' + $ExpectedDeviceId.ToLowerInvariant() + '-' +
                [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.json')
            $operation = $keyStore.RotateAsync(
                $stateStore,
                $ExpectedDeviceId,
                $archivePath,
                $null,
                [Threading.CancellationToken]::None)
            $context = $operation.AsTask().GetAwaiter().GetResult()
            $identity = $context.Identity
        }
        'Remove' {
            $archivePath = Join-Path $archiveRoot (
                'identity-' + $ExpectedDeviceId.ToLowerInvariant() + '-' +
                [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.json')
            $operation = $keyStore.RemoveAsync(
                $stateStore,
                $ExpectedDeviceId,
                $archivePath,
                [Threading.CancellationToken]::None)
            $identity = $operation.AsTask().GetAwaiter().GetResult()
        }
    }
} finally {
    if ($null -ne $context) {
        $context.Dispose()
    }
}

[pscustomobject]@{
    action = $Action
    deviceId = $identity.DeviceId
    publicKeySha256 = $identity.PublicKeySha256
    keyName = $identity.KeyName
    statePath = $statePath
    archivePath = $archivePath
    reEnrollmentRequired = $Action -in @('Rotate', 'Remove')
}
