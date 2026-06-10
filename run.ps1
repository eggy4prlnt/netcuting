# NetCut CLI launcher (Windows)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

function Ensure-Venv {
    if (-not (Test-Path $python)) {
        python -m venv .venv
        return
    }
    & $python -m pip --version *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[run.ps1] Virtualenv rusak, membuat ulang..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force .venv
        python -m venv .venv
    }
}

Ensure-Venv
& $python -m pip install --upgrade pip -q
& $python -m pip install -r requirements.txt -q

& $python netcut.py @args
