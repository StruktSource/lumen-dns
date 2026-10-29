[CmdletBinding()]
param([ValidateSet('check', 'build', 'image', 'release')][string]$Command)

$ErrorActionPreference = 'Stop'
if (-not $Command) { throw 'Usage: .\scripts\dev.ps1 <check|build|image|release>' }

function Invoke-Native {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed with exit code $LASTEXITCODE" }
}

function Invoke-Check {
    Invoke-Native -Executable 'cargo' -Arguments @('fmt', '--check')
    Invoke-Native -Executable 'cargo' -Arguments @('clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings')
    Invoke-Native -Executable 'cargo' -Arguments @('test', '--workspace', '--locked')
}

function Invoke-Image {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Missing required command: docker' }
    Invoke-Native -Executable 'docker' -Arguments @('build', '--tag', 'lumen:local', '.')
    Write-Output 'Local image ready: lumen:local'
}

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    switch ($Command) {
        'check' { Invoke-Check }
        'build' { Invoke-Native -Executable 'cargo' -Arguments @('build', '--workspace', '--locked') }
        'image' { Invoke-Image }
        'release' { Invoke-Check; Invoke-Native -Executable 'cargo' -Arguments @('build', '--workspace', '--release', '--locked'); Invoke-Image }
    }
} finally {
    Pop-Location
}
