[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

$pythonCommand = Get-Command python -ErrorAction Stop
$pythonVersion = & $pythonCommand.Source -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
if ([version]$pythonVersion -lt [version]'3.11') {
    throw "ProxyPulse requires Python 3.11 or newer. Found $pythonVersion."
}

$nodeCommand = Get-Command node -ErrorAction Stop
$nodeVersion = (& $nodeCommand.Source --version).Trim().TrimStart('v')
if ([version]$nodeVersion -lt [version]'22.13') {
    throw "ProxyPulse requires Node.js 22.13 or newer for setup. Found $nodeVersion."
}

$npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if ($null -eq $npmCommand) {
    $npmCommand = Get-Command npm -ErrorAction Stop
}

Write-Host "Installing the locked dashboard dependencies..." -ForegroundColor Cyan
& $npmCommand.Source --offline=false run install:ci
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

Write-Host "Building the local dashboard..." -ForegroundColor Cyan
& $npmCommand.Source run build
if ($LASTEXITCODE -ne 0) { throw "Dashboard build failed." }

Write-Host "`nSetup complete. Run .\start.ps1 to open ProxyPulse." -ForegroundColor Green
