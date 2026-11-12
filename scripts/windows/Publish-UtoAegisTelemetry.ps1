#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$project = Join-Path $repositoryRoot 'src/UtoAegis.Telemetry/UtoAegis.Telemetry.csproj'
$solution = Join-Path $repositoryRoot 'UtoAegis.slnx'
$output = [IO.Path]::GetFullPath($OutputDirectory, (Get-Location).Path)

dotnet restore $solution --locked-mode
if ($LASTEXITCODE -ne 0) {
    throw 'Locked dependency restore failed.'
}

dotnet test $solution --configuration Release --no-restore
if ($LASTEXITCODE -ne 0) {
    throw 'Release tests failed.'
}

dotnet publish $project --configuration Release --no-restore --output $output
if ($LASTEXITCODE -ne 0) {
    throw 'Telemetry forwarder publication failed.'
}

Write-Host "Published the framework-dependent telemetry forwarder to $output"
Write-Host 'Edit appsettings.json, provision the collector key, and run the installer as administrator.'
