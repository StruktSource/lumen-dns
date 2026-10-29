#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

usage() {
  cat <<'EOF'
Usage: ./scripts/dev.sh <check|build|image|release>

check    Format, lint, and test workspace.
build    Build development binaries.
image    Build local OCI image: lumen:local.
release  Run checks, create optimized binaries, then build image.
EOF
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }
}

check() {
  cargo fmt --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
}

image() {
  need_command docker
  docker build --tag lumen:local .
  echo "Local image ready: lumen:local"
}

case "${1:-}" in
  check) check ;;
  build) cargo build --workspace --locked ;;
  image) image ;;
  release) check; cargo build --workspace --release --locked; image ;;
  *) usage; exit 2 ;;
esac
