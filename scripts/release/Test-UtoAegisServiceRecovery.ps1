#Requires -Version 7.0
[CmdletBinding()]
param(
    [string[]] $ServiceName = @('UtoAegis', 'UtoAegisUpdater', 'UtoAegisTelemetry'),

    [ValidateRange(10, 300)]
    [int] $TimeoutSeconds = 60,

    [Parameter(Mandatory)]
    [switch] $Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Service recovery testing requires an elevated PowerShell session.'
}

$results = [Collections.Generic.List[object]]::new()
foreach ($name in $ServiceName) {
    $controller = Get-Service -Name $name -ErrorAction Stop
    if ($controller.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        throw "Service $name must be running before the recovery test."
    }

    $before = Get-CimInstance Win32_Service -Filter "Name='$name'"
    $startedAt = [datetimeoffset]::UtcNow
    try {
        Stop-Service -Name $name -Force
        $controller.WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds($TimeoutSeconds))
        Start-Service -Name $name
        $controller.WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds($TimeoutSeconds))
        $after = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ($after.ProcessId -eq 0 -or $after.ProcessId -eq $before.ProcessId) {
            throw "Service $name did not start in a new process."
        }

        $results.Add([ordered]@{
            serviceName = $name
            previousProcessId = $before.ProcessId
            recoveredProcessId = $after.ProcessId
            durationMilliseconds = [long]([datetimeoffset]::UtcNow - $startedAt).TotalMilliseconds
            status = 'Passed'
        })
    } catch {
        Start-Service -Name $name -ErrorAction SilentlyContinue
        throw
    }
}

$results | ConvertTo-Json -Depth 5
