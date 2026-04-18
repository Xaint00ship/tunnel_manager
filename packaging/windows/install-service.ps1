<#
.SYNOPSIS
    Install tunnel_manager as a Windows service via NSSM.

.DESCRIPTION
    Wraps the Python entry point with NSSM (https://nssm.cc) so the manager
    starts at boot and restarts on failure. NSSM must be on PATH.

.EXAMPLE
    # Run elevated PowerShell:
    .\install-service.ps1 -RepoPath "C:\Proxyyy\tunnel_manager"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$RepoPath,

    [string]$ServiceName = "TunnelManager",

    [string]$Python = ""
)

if (-not (Test-Path $RepoPath)) {
    throw "RepoPath '$RepoPath' does not exist."
}

if (-not $Python) {
    $venvPython = Join-Path $RepoPath ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        $Python = $venvPython
    } else {
        throw "No -Python provided and no .venv at $venvPython"
    }
}

if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    throw "NSSM not found on PATH. Install from https://nssm.cc and retry."
}

$mainScript = Join-Path $RepoPath "main.py"
if (-not (Test-Path $mainScript)) { throw "main.py not found at $mainScript" }

Write-Host "Installing service '$ServiceName' ..."
nssm install $ServiceName $Python $mainScript --no-tui
nssm set $ServiceName AppDirectory $RepoPath
nssm set $ServiceName Start SERVICE_AUTO_START
nssm set $ServiceName AppStdout (Join-Path $RepoPath "tunnel-manager.out.log")
nssm set $ServiceName AppStderr (Join-Path $RepoPath "tunnel-manager.err.log")
nssm set $ServiceName AppRotateFiles 1
nssm set $ServiceName AppRotateBytes 1048576

Write-Host "Service installed. Start it with:"
Write-Host "  nssm start $ServiceName"
Write-Host "Uninstall with:"
Write-Host "  nssm stop $ServiceName; nssm remove $ServiceName confirm"
