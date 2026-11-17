#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptDirectory = Join-Path $repositoryRoot 'scripts/windows'
$scripts = @(
    'Invoke-UtoAegisEnrollmentLifecycle.ps1',
    'Install-UtoAegisEnrollment.ps1',
    'Repair-UtoAegisEnrollment.ps1',
    'Rotate-UtoAegisEnrollment.ps1',
    'Remove-UtoAegisEnrollment.ps1'
)

foreach ($name in $scripts) {
    $path = Join-Path $scriptDirectory $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Enrollment lifecycle script is missing: $name"
    }

    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "Enrollment lifecycle script has parser errors: $name"
    }
}

$lifecyclePath = Join-Path $scriptDirectory 'Invoke-UtoAegisEnrollmentLifecycle.ps1'
$lifecycle = Get-Content -LiteralPath $lifecyclePath -Raw
$requiredControls = @(
    'SupportsShouldProcess',
    'ExpectedDeviceId',
    'ArchiveDirectory must be inside StateDirectory',
    '/inheritance:r',
    '*S-1-5-18:(OI)(CI)F',
    '*S-1-5-32-544:(OI)(CI)F',
    'CreateOrLoadAsync',
    'ValidateAsync',
    'RotateAsync',
    'RemoveAsync',
    'reEnrollmentRequired'
)
foreach ($control in $requiredControls) {
    if (-not $lifecycle.Contains($control, [StringComparison]::Ordinal)) {
        throw "Enrollment lifecycle control is missing: $control"
    }
}

if ($lifecycle.Contains('Remove-Item', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Enrollment lifecycle must archive state rather than deleting it from PowerShell.'
}

$wrapperActions = @{
    'Install-UtoAegisEnrollment.ps1' = 'Install'
    'Repair-UtoAegisEnrollment.ps1' = 'Repair'
    'Rotate-UtoAegisEnrollment.ps1' = 'Rotate'
    'Remove-UtoAegisEnrollment.ps1' = 'Remove'
}
foreach ($entry in $wrapperActions.GetEnumerator()) {
    $content = Get-Content -LiteralPath (Join-Path $scriptDirectory $entry.Key) -Raw
    if (-not $content.Contains("-Action $($entry.Value)", [StringComparison]::Ordinal)) {
        throw "$($entry.Key) does not invoke the expected lifecycle action."
    }
}

Write-Host 'Enrollment lifecycle script tests passed.'
