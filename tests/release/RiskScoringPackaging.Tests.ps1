#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$builderPath = Join-Path $repositoryRoot 'scripts/release/New-UtoAegisRelease.ps1'
$builder = Get-Content -LiteralPath $builderPath -Raw
if (-not $builder.Contains(
        "'explainable-risk-scoring.md'",
        [StringComparison]::Ordinal)) {
    throw 'The release builder does not package the explainable risk scoring guide.'
}

$guidePath = Join-Path $repositoryRoot 'docs/explainable-risk-scoring.md'
$guide = Get-Content -LiteralPath $guidePath -Raw
foreach ($requiredSection in @(
        '## Operator interpretation',
        '## Default policy version 1',
        '## Calibration and policy maintenance')) {
    if (-not $guide.Contains($requiredSection, [StringComparison]::Ordinal)) {
        throw "The risk scoring guide is missing required section: $requiredSection"
    }
}

$corpusPath = Join-Path $repositoryRoot `
    'tests/UtoAegis.Core.Tests/Fixtures/RiskScoring/calibration-corpus.json'
$corpus = @(Get-Content -LiteralPath $corpusPath -Raw | ConvertFrom-Json)
if ($corpus.Count -lt 6) {
    throw 'The risk scoring calibration corpus is incomplete.'
}

$readme = Get-Content -LiteralPath (Join-Path $repositoryRoot 'README.md') -Raw
$milestoneStart = $readme.IndexOf(
    '### Milestone 17 — Explainable risk scoring and verdict aggregation',
    [StringComparison]::Ordinal)
$milestoneEnd = $readme.IndexOf(
    '### Milestone 18 —',
    $milestoneStart,
    [StringComparison]::Ordinal)
if ($milestoneStart -lt 0 -or $milestoneEnd -le $milestoneStart) {
    throw 'The Milestone 17 checklist boundary is missing.'
}

$milestoneChecklist = $readme.Substring(
    $milestoneStart,
    $milestoneEnd - $milestoneStart)
if ($milestoneChecklist.Contains('- [ ]', [StringComparison]::Ordinal)) {
    throw 'The Milestone 17 release checklist is not complete.'
}

Write-Host 'Risk scoring release packaging tests passed.'
