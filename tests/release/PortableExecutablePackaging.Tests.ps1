#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$builderPath = Join-Path $repositoryRoot 'scripts/release/New-UtoAegisRelease.ps1'
$builder = Get-Content -LiteralPath $builderPath -Raw
if (-not $builder.Contains(
        "'static-pe-executable-analysis.md'",
        [StringComparison]::Ordinal)) {
    throw 'The release builder does not package the static PE analysis guide.'
}

$guidePath = Join-Path $repositoryRoot 'docs/static-pe-executable-analysis.md'
if (-not (Test-Path -LiteralPath $guidePath -PathType Leaf)) {
    throw 'The static PE analysis operator guide is missing.'
}

$corpusPath = Join-Path $repositoryRoot `
    'tests/UtoAegis.Core.Tests/Fixtures/PortableExecutable/malformed-corpus.json'
$corpus = @(Get-Content -LiteralPath $corpusPath -Raw | ConvertFrom-Json)
if ($corpus.Count -lt 9) {
    throw 'The malformed PE regression corpus is incomplete.'
}

$readme = Get-Content -LiteralPath (Join-Path $repositoryRoot 'README.md') -Raw
if ($readme.Contains(
        '- [ ] Add malformed corpus, regression coverage, packaging, and documentation.',
        [StringComparison]::Ordinal)) {
    throw 'The Milestone 16 release checklist is not complete.'
}

Write-Host 'Portable executable release packaging tests passed.'
