#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$builderPath = Join-Path $repositoryRoot 'scripts/release/New-UtoAegisRelease.ps1'
$builder = Get-Content -LiteralPath $builderPath -Raw
$requiredBuilderEntries = @(
    "'tools' = 'src/UtoAegis.Cli/UtoAegis.Cli.csproj'",
    "'scripts/windows'",
    "'endpoint-enrollment-and-policy-distribution.md'"
)
foreach ($entry in $requiredBuilderEntries) {
    if (-not $builder.Contains($entry, [StringComparison]::Ordinal)) {
        throw "Release builder does not package enrollment requirement: $entry"
    }
}

$requiredDeploymentFiles = @(
    'Install-UtoAegisEnrollment.ps1',
    'Repair-UtoAegisEnrollment.ps1',
    'Rotate-UtoAegisEnrollment.ps1',
    'Remove-UtoAegisEnrollment.ps1',
    'Invoke-UtoAegisEnrollmentLifecycle.ps1'
)
foreach ($file in $requiredDeploymentFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot "scripts/windows/$file") -PathType Leaf)) {
        throw "Release enrollment deployment file is missing: $file"
    }
}

$cliProject = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src/UtoAegis.Cli/UtoAegis.Cli.csproj') -Raw
if (-not $cliProject.Contains(
        '../UtoAegis.Infrastructure/UtoAegis.Infrastructure.csproj',
        [StringComparison]::Ordinal)) {
    throw 'The packaged tools publication does not include the enrollment infrastructure assembly.'
}

Write-Host 'Enrollment release packaging tests passed.'
