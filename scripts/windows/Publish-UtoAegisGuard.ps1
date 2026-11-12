#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$project = Join-Path $repositoryRoot 'src/UtoAegis.Guard/UtoAegis.Guard.csproj'
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
    throw 'Integrity guard publication failed.'
}

Write-Host "Published the framework-dependent integrity guard to $output"
Write-Host 'Edit appsettings.json, deploy a signed policy, and run the installer as administrator.'
