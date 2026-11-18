#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$builder = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'scripts/release/New-UtoAegisRelease.ps1') -Raw
if (-not $builder.Contains(
        "'behavioral-telemetry-and-detection.md'",
        [StringComparison]::Ordinal)) {
    throw 'The release builder does not package the behavioral detection guide.'
}

$guide = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'docs/behavioral-telemetry-and-detection.md') -Raw
foreach ($requiredSection in @(
        '## Enabling collection safely',
        '## Operations and recovery',
        '## Validation and release gates')) {
    if (-not $guide.Contains($requiredSection, [StringComparison]::Ordinal)) {
        throw "The behavioral detection guide is missing required section: $requiredSection"
    }
}

$corpusPath = Join-Path $repositoryRoot `
    'tests/UtoAegis.Core.Tests/Fixtures/Behavior/behavior-calibration-corpus.json'
$corpus = @(Get-Content -LiteralPath $corpusPath -Raw | ConvertFrom-Json)
if ($corpus.Count -lt 8) {
    throw 'The behavioral calibration corpus is incomplete.'
}

$installer = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'scripts/windows/Install-UtoAegisService.ps1') -Raw
if (-not $installer.Contains('$behaviorHistoryPath', [StringComparison]::Ordinal)) {
    throw 'The service installer does not provision behavioral history access.'
}

$lock = Get-Content -LiteralPath (
    Join-Path $repositoryRoot 'src/UtoAegis.Infrastructure/packages.lock.json') -Raw
if (-not $lock.Contains(
        'Microsoft.Diagnostics.Tracing.TraceEvent',
        [StringComparison]::Ordinal)) {
    throw 'The production lock graph does not include the Windows ETW dependency.'
}

$readme = Get-Content -LiteralPath (Join-Path $repositoryRoot 'README.md') -Raw
$milestoneStart = $readme.IndexOf(
    '### Milestone 18 — Behavioral telemetry and detection',
    [StringComparison]::Ordinal)
$milestoneEnd = $readme.IndexOf(
    '### Remaining product roadmap',
    $milestoneStart,
    [StringComparison]::Ordinal)
if ($milestoneStart -lt 0 -or $milestoneEnd -le $milestoneStart) {
    throw 'The Milestone 18 checklist boundary is missing.'
}

$milestoneChecklist = $readme.Substring(
    $milestoneStart,
    $milestoneEnd - $milestoneStart)
if ($milestoneChecklist.Contains('- [ ]', [StringComparison]::Ordinal)) {
    throw 'The Milestone 18 release checklist is not complete.'
}

Write-Host 'Behavioral detection release packaging tests passed.'
