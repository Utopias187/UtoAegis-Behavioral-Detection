#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string] $AssemblyDirectory,
    [string] $StateDirectory = (Join-Path $env:ProgramData 'UtoAegis\Management'),
    [ValidatePattern('^[A-Za-z0-9_.:-]{1,128}$')][string] $KeyName = 'UtoAegis.Device.Identity',
    [ValidatePattern('^[A-Za-z0-9_.\\ -]{1,256}$')][string] $StateConsumerIdentity = 'SYSTEM'
)

& (Join-Path $PSScriptRoot 'Invoke-UtoAegisEnrollmentLifecycle.ps1') `
    -Action Repair @PSBoundParameters
