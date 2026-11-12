#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidatePattern('^[A-Za-z0-9 _.-]{1,120}$')]
    [string] $TaskName = 'UtoAegis Integrity Guard'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    Write-Host "Scheduled task '$TaskName' is not installed."
    return
}

if (-not $PSCmdlet.ShouldProcess($TaskName, 'Remove integrity guard scheduled task')) {
    return
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Host 'Integrity guard task removed. Policy bundles, state, telemetry, published files, and ACLs were preserved.'
