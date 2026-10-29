#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/dev-macos.sh <check|build|image|release>

check    Format, lint, and test workspace.
build    Build macOS development binaries.
image    Build local Docker image for OrbStack: lumen:local.
release  Run checks, create optimized binaries, then build image.
EOF
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

check() {
  cargo fmt --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
}

build() {
  cargo build --workspace
}

image() {
  need_command docker
  docker build --tag lumen:local .
  echo "OrbStack image ready: lumen:local"
}

case "${1:-}" in
  check)
    check
    ;;
  build)
    build
    ;;
  image)
    image
    ;;
  release)
    check
    cargo build --workspace --release
    image
    ;;
  *)
    usage
    exit 2
    ;;
esac
