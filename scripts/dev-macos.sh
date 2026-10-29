#!/usr/bin/env bash
# Compatibility wrapper. Use dev.sh on macOS and Linux.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/dev.sh" "$@"
