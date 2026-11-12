#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $RootPath,

    [string[]] $AllowedSignerThumbprint = @(),

    [switch] $AllowUnsignedDevelopment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ExactProperties {
    param([object] $Value, [string[]] $Names, [string] $Label)

    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if ([string]::Join('|', $actual) -cne [string]::Join('|', $expected)) {
        throw "$Label contains missing or unknown properties."
    }
}

function Test-HexDigest {
    param([string] $Value, [int] $Length)

    return $Value.Length -eq $Length -and $Value -cmatch '^[0-9a-f]+$'
}

$root = (Resolve-Path -LiteralPath $RootPath).Path
$rootInfo = Get-Item -LiteralPath $root -Force
if (-not $rootInfo.PSIsContainer -or $rootInfo.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
    throw 'The release root must be a regular directory.'
}

$manifestPath = Join-Path $root 'release-manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'release-manifest.json is missing.'
}

$manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
$manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
Assert-ExactProperties $manifest @(
    'schemaVersion', 'product', 'version', 'commitSha', 'runtimeIdentifier',
    'createdAtUtc', 'signatureMode', 'files') 'Release manifest'
if ($manifest.schemaVersion -ne 1 -or $manifest.product -cne 'UtoAegis' -or
    [string]$manifest.version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$' -or
    -not (Test-HexDigest ([string]$manifest.commitSha) 40) -or
    [string]$manifest.runtimeIdentifier -notmatch '^win-(x64|arm64)$' -or
    [string]$manifest.signatureMode -notin @('Authenticode', 'UnsignedDevelopment')) {
    throw 'Release manifest metadata is invalid.'
}

$createdAt = [datetimeoffset]::MinValue
if (-not [datetimeoffset]::TryParse(
        [string]$manifest.createdAtUtc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$createdAt)) {
    throw 'Release manifest createdAtUtc is invalid.'
}

$declared = [Collections.Generic.Dictionary[string, object]]::new(
    [StringComparer]::OrdinalIgnoreCase)
foreach ($entry in @($manifest.files)) {
    Assert-ExactProperties $entry @('path', 'length', 'sha256') "File entry '$($entry.path)'"
    $relative = [string]$entry.path
    if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains('\') -or
        $relative -eq '..' -or $relative.StartsWith('../', [StringComparison]::Ordinal) -or
        [IO.Path]::IsPathRooted($relative) -or -not (Test-HexDigest ([string]$entry.sha256) 64) -or
        [long]$entry.length -lt 0 -or -not $declared.TryAdd($relative, $entry)) {
        throw "Release manifest file entry is invalid: $relative"
    }

    $path = [IO.Path]::GetFullPath($relative.Replace('/', [IO.Path]::DirectorySeparatorChar), $root)
    $rootPrefix = [IO.Path]::TrimEndingDirectorySeparator($root) + [IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Release file is missing or outside the package: $relative"
    }

    $file = Get-Item -LiteralPath $path -Force
    if ($file.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
        $file.Length -ne [long]$entry.length -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            [string]$entry.sha256) {
        throw "Release file failed integrity verification: $relative"
    }
}

$actual = @(
    Get-ChildItem -LiteralPath $root -File -Recurse -Force |
        Where-Object { $_.FullName -notin @(
                $manifestPath,
                (Join-Path $root 'release-manifest.p7s')) } |
        ForEach-Object { [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/') }
)
if ($actual.Count -ne $declared.Count -or
    @($actual | Where-Object { -not $declared.ContainsKey($_) }).Count -ne 0) {
    throw 'The release package contains files that are missing from its manifest.'
}

$sbomPath = Join-Path $root 'sbom.cdx.json'
if (-not (Test-Path -LiteralPath $sbomPath -PathType Leaf)) {
    throw 'sbom.cdx.json is missing.'
}

$sbom = Get-Content -LiteralPath $sbomPath -Raw | ConvertFrom-Json
if ($sbom.bomFormat -cne 'CycloneDX' -or $sbom.specVersion -cne '1.7' -or
    $sbom.metadata.component.name -cne 'UtoAegis' -or
    [string]$sbom.metadata.component.version -cne [string]$manifest.version -or
    @($sbom.components).Count -eq 0) {
    throw 'The CycloneDX SBOM is invalid or does not describe this release.'
}

if ($manifest.signatureMode -ceq 'UnsignedDevelopment') {
    if (-not $AllowUnsignedDevelopment) {
        throw 'Unsigned development releases require -AllowUnsignedDevelopment.'
    }
} else {
    if ($AllowedSignerThumbprint.Count -eq 0) {
        throw 'Signed releases require at least one allowlisted signer thumbprint.'
    }

    $signaturePath = Join-Path $root 'release-manifest.p7s'
    if (-not (Test-Path -LiteralPath $signaturePath -PathType Leaf)) {
        throw 'The detached release-manifest.p7s signature is missing.'
    }

    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $content = [Security.Cryptography.Pkcs.ContentInfo]::new($manifestBytes)
    $signed = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
    $signed.Decode([IO.File]::ReadAllBytes($signaturePath))
    $signed.CheckSignature($true)
    if ($signed.SignerInfos.Count -ne 1) {
        throw 'The release manifest must have exactly one CMS signer.'
    }

    $signerThumbprint = $signed.SignerInfos[0].Certificate.Thumbprint
    if ($signerThumbprint -notin @($AllowedSignerThumbprint | ForEach-Object {
                $_.Replace(' ', '').ToUpperInvariant()
            })) {
        throw "The release manifest signer is not allowlisted: $signerThumbprint"
    }

    foreach ($binary in Get-ChildItem -LiteralPath $root -File -Recurse |
                 Where-Object { $_.Extension -in @('.exe', '.dll') }) {
        $authenticode = Get-AuthenticodeSignature -LiteralPath $binary.FullName
        if ($authenticode.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            ($AllowedSignerThumbprint.Count -gt 0 -and
             $authenticode.SignerCertificate.Thumbprint -notin
                @($AllowedSignerThumbprint | ForEach-Object {
                        $_.Replace(' ', '').ToUpperInvariant()
                    }))) {
            throw "Authenticode verification failed: $($binary.FullName)"
        }
    }
}

Write-Host "Verified UtoAegis $($manifest.version) release with $($declared.Count) files."
