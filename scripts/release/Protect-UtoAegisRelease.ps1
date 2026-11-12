#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $RootPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string] $Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $CommitSha,

    [Parameter(Mandatory)]
    [ValidatePattern('^win-(x64|arm64)$')]
    [string] $RuntimeIdentifier,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F ]{40,59}$')]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory)]
    [uri] $TimestampServer,

    [datetimeoffset] $CreatedAtUtc = [datetimeoffset]::UtcNow,

    [string] $SignToolPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-SignTool {
    param([string] $RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        return (Resolve-Path -LiteralPath $RequestedPath).Path
    }

    $command = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    if (Test-Path -LiteralPath $sdkRoot -PathType Container) {
        $candidate = Get-ChildItem -LiteralPath $sdkRoot -Directory |
            Sort-Object { [version]$_.Name } -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64/signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
        if ($null -ne $candidate) {
            return $candidate
        }
    }

    throw 'SignTool.exe was not found. Install the Windows SDK or pass -SignToolPath.'
}

function Invoke-SignTool {
    param([string] $Tool, [string[]] $Arguments)

    & $Tool @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "SignTool failed with exit code $LASTEXITCODE."
    }
}

if ($TimestampServer.Scheme -cne 'https' -or
    -not [string]::IsNullOrEmpty($TimestampServer.UserInfo) -or
    -not [string]::IsNullOrEmpty($TimestampServer.Fragment)) {
    throw 'TimestampServer must be an HTTPS URI without user information or a fragment.'
}

$root = (Resolve-Path -LiteralPath $RootPath).Path
$thumbprint = $CertificateThumbprint.Replace(' ', '').ToUpperInvariant()
$matches = [Collections.Generic.List[object]]::new()
foreach ($location in @('CurrentUser', 'LocalMachine')) {
    $certificate = Get-Item -LiteralPath "Cert:\$location\My\$thumbprint" -ErrorAction SilentlyContinue
    if ($null -ne $certificate) {
        $matches.Add([pscustomobject]@{ Certificate = $certificate; Location = $location })
    }
}

if ($matches.Count -ne 1) {
    throw 'The signing certificate must exist in exactly one CurrentUser or LocalMachine personal store.'
}

$selection = $matches[0]
$certificate = $selection.Certificate
if (-not $certificate.HasPrivateKey -or
    $certificate.NotBefore.ToUniversalTime() -gt [datetime]::UtcNow -or
    $certificate.NotAfter.ToUniversalTime() -lt [datetime]::UtcNow) {
    throw 'The signing certificate must have an accessible private key and be currently valid.'
}

$enhancedKeyUsage = $certificate.Extensions |
    Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
    Select-Object -First 1
if ($null -eq $enhancedKeyUsage -or
    @($enhancedKeyUsage.EnhancedKeyUsages | Where-Object {
            $_.Value -eq '1.3.6.1.5.5.7.3.3'
        }).Count -ne 1) {
    throw 'The signing certificate must include the Code Signing enhanced key usage.'
}

$signTool = Resolve-SignTool $SignToolPath
$storeArguments = @('/sha1', $thumbprint, '/s', 'My')
if ($selection.Location -eq 'LocalMachine') {
    $storeArguments += '/sm'
}

$ownedBinaries = @(
    Get-ChildItem -LiteralPath $root -File -Recurse |
        Where-Object {
            $_.Name -match '^utoaegis.*\.(exe|dll)$' -or
            $_.Name -match '^UtoAegis.*\.(exe|dll)$'
        } |
        Sort-Object FullName
)
if ($ownedBinaries.Count -eq 0) {
    throw 'No UtoAegis binaries were found to sign.'
}

foreach ($binary in $ownedBinaries) {
    Invoke-SignTool $signTool (@(
            'sign', '/fd', 'SHA256', '/tr', $TimestampServer.AbsoluteUri,
            '/td', 'SHA256', '/d', 'UtoAegis', '/v'
        ) + $storeArguments + @($binary.FullName))
    Invoke-SignTool $signTool @('verify', '/pa', '/all', '/tw', '/v', $binary.FullName)
}

& (Join-Path $PSScriptRoot 'New-UtoAegisReleaseManifest.ps1') `
    -RootPath $root `
    -Version $Version `
    -CommitSha $CommitSha `
    -RuntimeIdentifier $RuntimeIdentifier `
    -SignatureMode Authenticode `
    -CreatedAtUtc $CreatedAtUtc

$signaturePath = Join-Path $root 'release-manifest.p7s'
if (Test-Path -LiteralPath $signaturePath -PathType Leaf) {
    Remove-Item -LiteralPath $signaturePath -Force
}

$signatureDirectory = Join-Path $root ".signing-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $signatureDirectory | Out-Null
try {
    $manifestPath = Join-Path $root 'release-manifest.json'
    Invoke-SignTool $signTool (@(
            'sign', '/fd', 'SHA256', '/p7', $signatureDirectory,
            '/p7ce', 'DetachedSignedData', '/v'
        ) + $storeArguments + @($manifestPath))
    $generatedSignature = Join-Path $signatureDirectory 'release-manifest.json.p7'
    if (-not (Test-Path -LiteralPath $generatedSignature -PathType Leaf)) {
        throw 'SignTool did not create the detached release-manifest signature.'
    }

    Invoke-SignTool $signTool @(
        'timestamp', '/p7', '/tr', $TimestampServer.AbsoluteUri,
        '/td', 'SHA256', '/v', $generatedSignature)
    Invoke-SignTool $signTool @('verify', '/p7', '/tw', '/v', $generatedSignature)
    Move-Item -LiteralPath $generatedSignature -Destination $signaturePath
} finally {
    if (Test-Path -LiteralPath $signatureDirectory -PathType Container) {
        $resolvedSignatureDirectory = (Resolve-Path -LiteralPath $signatureDirectory).Path
        $rootPrefix = [IO.Path]::TrimEndingDirectorySeparator($root) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedSignatureDirectory.StartsWith(
                $rootPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a signing directory outside the release root.'
        }

        Remove-Item -LiteralPath $resolvedSignatureDirectory -Recurse -Force
    }
}

& (Join-Path $PSScriptRoot 'Test-UtoAegisRelease.ps1') `
    -RootPath $root `
    -AllowedSignerThumbprint $thumbprint
Write-Host "Signed and verified $($ownedBinaries.Count) UtoAegis binaries and the release manifest."
