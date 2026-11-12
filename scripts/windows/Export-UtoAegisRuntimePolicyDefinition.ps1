#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$')]
    [string] $PolicyId,

    [Parameter(Mandatory)]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $Sequence,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$')]
    [string] $KeyId,

    [Parameter(Mandatory)]
    [string] $OutputPath,

    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string[]] $ServiceName = @('UtoAegis', 'UtoAegisUpdater', 'UtoAegisTelemetry'),

    [string[]] $ProtectedPath = @(),

    [ValidateSet('ObserveOnly', 'DryRunQuarantine', 'Quarantine')]
    [string] $ResponseMode = 'ObserveOnly',

    [string[]] $AllowlistedPathPrefix = @(),

    [string[]] $AllowlistedSha256 = @(),

    [ValidateRange(1, 100)]
    [int] $MaxActionsPerWindow = 3,

    [ValidateRange(1, 86400)]
    [int] $RateLimitWindowSeconds = 300,

    [ValidateRange(1, 366)]
    [int] $ValidityDays = 30,

    [ValidateRange(1, 1440)]
    [int] $AuditIntervalMinutes = 5,

    [ValidateRange(0, 100)]
    [int] $MaximumRecoveriesPerWindow = 2,

    [ValidateRange(1, 10080)]
    [int] $RecoveryWindowMinutes = 60,

    [switch] $EnableServiceRecovery,

    [switch] $EnableAclRecovery,

    [switch] $AllowQuarantineResponse
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ServiceExecutable {
    param([string] $PathName, [string] $Name)

    $text = $PathName.Trim()
    if ($text.StartsWith('"', [StringComparison]::Ordinal)) {
        if ($text -notmatch '^"([^"]+)"\s*$') {
            throw "Service '$Name' must not have command-line arguments in its protected binary path."
        }

        return [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Matches[1]))
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($text)
    if (-not [IO.Path]::IsPathFullyQualified($expanded) -or $expanded.Contains(' ')) {
        throw "Service '$Name' has an ambiguous or non-absolute binary path."
    }

    return [IO.Path]::GetFullPath($expanded)
}

if ($ResponseMode -eq 'Quarantine' -and -not $AllowQuarantineResponse) {
    throw 'Quarantine response requires the explicit -AllowQuarantineResponse switch.'
}

$services = [Collections.Generic.List[object]]::new()
foreach ($name in @($ServiceName | Sort-Object -Unique)) {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
    if ($null -eq $service) {
        throw "Protected service '$name' is not installed."
    }

    $executable = Resolve-ServiceExecutable ([string]$service.PathName) $name
    $item = Get-Item -LiteralPath $executable -Force
    if ($item.PSIsContainer -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "Service '$name' executable must be a regular file."
    }

    $delayed = $false
    if ([string]$service.StartMode -eq 'Auto') {
        $registry = Get-ItemProperty `
            -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name" `
            -Name DelayedAutoStart `
            -ErrorAction SilentlyContinue
        $delayed = $null -ne $registry -and [int]$registry.DelayedAutoStart -eq 1
    }

    $startMode = switch ([string]$service.StartMode) {
        'Auto' { if ($delayed) { 'DelayedAutomatic' } else { 'Automatic' } }
        'Manual' { 'Manual' }
        'Disabled' { 'Disabled' }
        default { throw "Service '$name' uses unsupported start mode '$($service.StartMode)'." }
    }
    $account = [string]$service.StartName
    $passwordlessAccounts = @(
        'LocalSystem',
        'NT AUTHORITY\SYSTEM',
        'NT AUTHORITY\LocalService',
        'NT AUTHORITY\NetworkService',
        "NT SERVICE\$name")
    if ($EnableServiceRecovery -and $account -notin $passwordlessAccounts) {
        throw "Service '$name' uses account '$account'; automatic recovery supports only passwordless built-in or matching virtual service accounts."
    }

    $services.Add([ordered]@{
        name = $name
        executablePath = $executable
        executableSha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
        account = $account
        startMode = $startMode
        recover = [bool]$EnableServiceRecovery
    })
}

$paths = [Collections.Generic.List[object]]::new()
foreach ($path in @($ProtectedPath | Sort-Object -Unique)) {
    $resolved = (Resolve-Path -LiteralPath $path).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "Protected paths cannot be reparse points: $resolved"
    }

    $paths.Add([ordered]@{
        path = $resolved
        expectedSddl = (Get-Acl -LiteralPath $resolved).Sddl
        recover = [bool]$EnableAclRecovery
    })
}

$hashes = @($AllowlistedSha256 | ForEach-Object {
    $value = $_.Trim().ToLowerInvariant()
    if ($value -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid allowlisted SHA-256: $_"
    }

    $value
} | Sort-Object -Unique)
$allowlistedPaths = @($AllowlistedPathPrefix | ForEach-Object {
    [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($_.Trim()))
} | Sort-Object -Unique)
$issuedUtc = [DateTimeOffset]::UtcNow
$manifest = [ordered]@{
    schemaVersion = 1
    algorithm = 'ecdsa-p256-sha256'
    sequence = $Sequence
    policyId = $PolicyId
    keyId = $KeyId
    issuedUtc = $issuedUtc.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    expiresUtc = $issuedUtc.AddDays($ValidityDays).ToString(
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    response = [ordered]@{
        mode = $ResponseMode
        allowlistedPathPrefixes = $allowlistedPaths
        allowlistedSha256 = $hashes
        maxActionsPerWindow = $MaxActionsPerWindow
        rateLimitWindowSeconds = $RateLimitWindowSeconds
    }
    integrity = [ordered]@{
        auditIntervalSeconds = $AuditIntervalMinutes * 60
        maximumRecoveriesPerWindow = $MaximumRecoveriesPerWindow
        recoveryWindowSeconds = $RecoveryWindowMinutes * 60
        services = @($services)
        paths = @($paths)
    }
}

$destination = [IO.Path]::GetFullPath($OutputPath, (Get-Location).Path)
if (Test-Path -LiteralPath $destination) {
    throw "OutputPath already exists: $destination"
}

$parent = [IO.Path]::GetDirectoryName($destination)
if ([string]::IsNullOrWhiteSpace($parent) -or
    [IO.Path]::TrimEndingDirectorySeparator($parent) -eq
        [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetPathRoot($parent))) {
    throw 'OutputPath must have a non-root parent directory.'
}

[IO.Directory]::CreateDirectory($parent) | Out-Null
[IO.File]::WriteAllText(
    $destination,
    ($manifest | ConvertTo-Json -Depth 8 -Compress),
    [Text.UTF8Encoding]::new($false, $true))
Write-Host "Exported unsigned runtime policy definition to $destination"
Write-Host 'Transfer it to the offline signing environment; do not place a policy private key on the endpoint.'
