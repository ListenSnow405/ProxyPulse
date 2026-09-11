[CmdletBinding()]
param(
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'dist\client\index.html'))) {
    throw "The dashboard has not been built. Run .\setup.ps1 first."
}

$arguments = @('-m', 'monitor')
if (-not $NoBrowser) { $arguments += '--open-browser' }
& python @arguments
