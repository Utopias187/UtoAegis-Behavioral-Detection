#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $DefinitionPath,

    [Parameter(Mandatory)]
    [string] $PrivateKeyPath,

    [Parameter(Mandatory)]
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RegularFile {
    param([string] $Path, [string] $Label, [long] $MaximumLength)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumLength) {
        throw "$Label must be a non-empty regular file no larger than $MaximumLength bytes."
    }

    return $item.FullName
}

$definition = Resolve-RegularFile $DefinitionPath 'DefinitionPath' 262144
$privateKey = Resolve-RegularFile $PrivateKeyPath 'PrivateKeyPath' 16384
$bytes = [IO.File]::ReadAllBytes($definition)
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and
    $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf) {
    throw 'DefinitionPath must be UTF-8 without a byte-order mark.'
}

$document = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json
if ($document.schemaVersion -ne 1 -or $document.algorithm -cne 'ecdsa-p256-sha256' -or
    [long]$document.sequence -le 0 -or
    [string]$document.policyId -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$' -or
    [string]$document.keyId -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$' -or
    $null -eq $document.response -or $null -eq $document.integrity -or
    @($document.integrity.services).Count -eq 0) {
    throw 'DefinitionPath does not contain a supported runtime policy document.'
}

$issuedUtc = [datetimeoffset]::MinValue
$expiresUtc = [datetimeoffset]::MinValue
if (-not [datetimeoffset]::TryParse([string]$document.issuedUtc, [ref]$issuedUtc) -or
    -not [datetimeoffset]::TryParse([string]$document.expiresUtc, [ref]$expiresUtc) -or
    $expiresUtc -le $issuedUtc -or $expiresUtc - $issuedUtc -gt [timespan]::FromDays(366)) {
    throw 'Runtime policy validity timestamps are invalid.'
}

$output = [IO.Path]::GetFullPath($OutputDirectory, (Get-Location).Path)
if (Test-Path -LiteralPath $output) {
    throw "OutputDirectory already exists: $output"
}

$parent = [IO.Path]::GetDirectoryName($output)
if ([string]::IsNullOrWhiteSpace($parent) -or
    [IO.Path]::TrimEndingDirectorySeparator($parent) -eq
        [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetPathRoot($parent))) {
    throw 'OutputDirectory must have a non-root parent directory.'
}

[IO.Directory]::CreateDirectory($parent) | Out-Null
$staging = Join-Path $parent ('.utoaegis-policy-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging) | Out-Null
try {
    [IO.File]::WriteAllBytes((Join-Path $staging 'policy.json'), $bytes)
    $pem = [IO.File]::ReadAllText($privateKey, [Text.UTF8Encoding]::new($false, $true))
    $key = [Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportFromPem($pem)
        $parameters = $key.ExportParameters($true)
        if ($parameters.Curve.Oid.Value -ne '1.2.840.10045.3.1.7' -or $null -eq $parameters.D) {
            throw 'PrivateKeyPath must contain an ECDSA NIST P-256 private key.'
        }

        $signature = $key.SignData(
            $bytes,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        [IO.File]::WriteAllText(
            (Join-Path $staging 'policy.sig'),
            [Convert]::ToBase64String($signature),
            [Text.UTF8Encoding]::new($false, $true))
    } finally {
        $key.Dispose()
    }

    [IO.Directory]::Move($staging, $output)
} catch {
    if (Test-Path -LiteralPath $staging -PathType Container) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }

    throw
}

Write-Host "Created signed runtime policy bundle $output"
Write-Host "Policy $($document.policyId); sequence $($document.sequence); signing key $($document.keyId)."
