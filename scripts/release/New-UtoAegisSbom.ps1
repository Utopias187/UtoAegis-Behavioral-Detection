#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string] $Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $CommitSha,

    [Parameter(Mandatory)]
    [string] $OutputPath,

    [string] $RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),

    [datetimeoffset] $TimestampUtc = [datetimeoffset]::UtcNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PackageReference {
    param([string] $Name, [string] $ResolvedVersion)

    $encodedName = [Uri]::EscapeDataString($Name)
    $encodedVersion = [Uri]::EscapeDataString($ResolvedVersion)
    return "pkg:nuget/$encodedName@$encodedVersion"
}

function New-DeterministicGuid {
    param([string] $Material)

    $bytes = [Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($Material))[0..15]
    $bytes[6] = ($bytes[6] -band 0x0f) -bor 0x50
    $bytes[8] = ($bytes[8] -band 0x3f) -bor 0x80
    return [Guid]::new([byte[]]$bytes)
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$sourceRoot = Join-Path $root 'src'
$lockFiles = @(Get-ChildItem -LiteralPath $sourceRoot -Filter 'packages.lock.json' -File -Recurse |
    Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' } |
    Sort-Object FullName)
if ($lockFiles.Count -eq 0) {
    throw "No production packages.lock.json files were found beneath $sourceRoot"
}

$packages = @{}
foreach ($lockFile in $lockFiles) {
    $projectName = Split-Path -Leaf $lockFile.DirectoryName
    $document = Get-Content -LiteralPath $lockFile.FullName -Raw | ConvertFrom-Json
    if ($document.version -ne 2) {
        throw "Unsupported lock-file version in $($lockFile.FullName)"
    }

    foreach ($framework in $document.dependencies.PSObject.Properties) {
        foreach ($dependency in $framework.Value.PSObject.Properties) {
            if ([string]$dependency.Value.type -eq 'Project') {
                continue
            }

            $name = $dependency.Name
            $resolved = [string]$dependency.Value.resolved
            if ([string]::IsNullOrWhiteSpace($resolved)) {
                throw "Package $name does not have a resolved version in $($lockFile.FullName)"
            }

            $key = $name.ToLowerInvariant()
            if ($packages.ContainsKey($key)) {
                $existing = $packages[$key]
                if ($existing.Version -ne $resolved -or
                    $existing.ContentHash -ne [string]$dependency.Value.contentHash) {
                    throw "Package $name resolves inconsistently across production lock files."
                }

                [void]$existing.Projects.Add($projectName)
                if ([string]$dependency.Value.type -eq 'Direct') {
                    $existing.Direct = $true
                }
            } else {
                $projects = [Collections.Generic.SortedSet[string]]::new(
                    [StringComparer]::Ordinal)
                [void]$projects.Add($projectName)
                $dependencies = [Collections.Generic.SortedSet[string]]::new(
                    [StringComparer]::OrdinalIgnoreCase)
                $dependencyProperty = $dependency.Value.PSObject.Properties['dependencies']
                if ($null -ne $dependencyProperty) {
                    foreach ($child in $dependencyProperty.Value.PSObject.Properties) {
                        [void]$dependencies.Add($child.Name)
                    }
                }

                $packages[$key] = [pscustomobject]@{
                    Name = $name
                    Version = $resolved
                    ContentHash = [string]$dependency.Value.contentHash
                    Direct = ([string]$dependency.Value.type -eq 'Direct')
                    Projects = $projects
                    Dependencies = $dependencies
                }
            }
        }
    }
}

$components = [Collections.Generic.List[object]]::new()
foreach ($package in @($packages.Values | Sort-Object Name, Version)) {
    $hashBytes = [Convert]::FromBase64String($package.ContentHash)
    $reference = Get-PackageReference $package.Name $package.Version
    $components.Add([ordered]@{
        type = 'library'
        'bom-ref' = $reference
        name = $package.Name
        version = $package.Version
        hashes = @(
            [ordered]@{
                alg = 'SHA-512'
                content = [Convert]::ToHexString($hashBytes).ToLowerInvariant()
            }
        )
        purl = $reference
        properties = @(
            [ordered]@{
                name = 'utoaegis:dependencyType'
                value = $(if ($package.Direct) { 'direct' } else { 'transitive' })
            },
            [ordered]@{
                name = 'utoaegis:projects'
                value = [string]::Join(',', $package.Projects)
            }
        )
    })
}

$rootReference = "pkg:generic/utoaegis@$([Uri]::EscapeDataString($Version))"
$dependencyGraph = [Collections.Generic.List[object]]::new()
$dependencyGraph.Add([ordered]@{
    ref = $rootReference
    dependsOn = @($components | ForEach-Object { $_.'bom-ref' } | Sort-Object)
})
foreach ($package in @($packages.Values | Sort-Object Name, Version)) {
    $childReferences = @(
        $package.Dependencies |
            Where-Object { $packages.ContainsKey($_.ToLowerInvariant()) } |
            ForEach-Object {
                $child = $packages[$_.ToLowerInvariant()]
                Get-PackageReference $child.Name $child.Version
            } |
            Sort-Object -Unique
    )
    $dependencyGraph.Add([ordered]@{
        ref = Get-PackageReference $package.Name $package.Version
        dependsOn = $childReferences
    })
}

$serial = New-DeterministicGuid "UtoAegis`n$Version`n$($CommitSha.ToLowerInvariant())"
$bom = [ordered]@{
    '$schema' = 'https://cyclonedx.org/schema/bom-1.7.schema.json'
    bomFormat = 'CycloneDX'
    specVersion = '1.7'
    serialNumber = "urn:uuid:$serial"
    version = 1
    metadata = [ordered]@{
        timestamp = $TimestampUtc.ToUniversalTime().ToString('o')
        lifecycles = @([ordered]@{ phase = 'build' })
        component = [ordered]@{
            type = 'application'
            'bom-ref' = $rootReference
            name = 'UtoAegis'
            version = $Version
            properties = @(
                [ordered]@{
                    name = 'utoaegis:commitSha'
                    value = $CommitSha.ToLowerInvariant()
                }
            )
        }
    }
    components = $components
    dependencies = $dependencyGraph
}

$destination = [IO.Path]::GetFullPath($OutputPath, (Get-Location).Path)
$parent = [IO.Path]::GetDirectoryName($destination)
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

[IO.File]::WriteAllText(
    $destination,
    ($bom | ConvertTo-Json -Depth 20) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false))
Write-Host "Created CycloneDX 1.7 SBOM with $($components.Count) components at $destination"
