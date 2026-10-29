[CmdletBinding()]
param([ValidateSet('check', 'build', 'image', 'release')][string]$Command)

$ErrorActionPreference = 'Stop'

function Invoke-Check {
    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
}

function Invoke-Image {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Missing required command: docker' }
    docker build --tag lumen:local .
    Write-Output 'Local image ready: lumen:local'
}

switch ($Command) {
    'check' { Invoke-Check }
    'build' { cargo build --workspace }
    'image' { Invoke-Image }
    'release' { Invoke-Check; cargo build --workspace --release; Invoke-Image }
}
