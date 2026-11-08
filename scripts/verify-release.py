#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail when release metadata does not match the requested tag."""

import argparse
from pathlib import Path
import re
import tomllib


SEMVER = re.compile(r"v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)")


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="v-prefixed release tag")
    args = parser.parse_args()
    match = SEMVER.fullmatch(args.version)
    if not match:
        parser.error("version must be a v-prefixed semantic version")
    version = match.group(1)
    root = Path(__file__).resolve().parent.parent
    errors: list[str] = []

    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text(encoding="utf-8"))
    chart = (root / "deploy/helm/lumen/Chart.yaml").read_text(encoding="utf-8")
    values = (root / "deploy/helm/lumen/values.yaml").read_text(encoding="utf-8")
    compose = (root / "deploy/docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    notes = (root / "RELEASE_NOTES.md").read_text(encoding="utf-8")

    rust_version = toolchain["toolchain"]["channel"]
    require(cargo["workspace"]["package"]["version"] == version, "Cargo.toml version differs", errors)
    require(f"version: {version}" in chart, "Helm chart version differs", errors)
    require(f'appVersion: "{version}"' in chart, "Helm appVersion differs", errors)
    require(f'tag: "{version}"' in values, "Helm image tag differs", errors)
    require(f"ghcr.io/struktsource/lumen-dns:{version}" in compose, "Compose image tag differs", errors)
    require(f"FROM rust:{rust_version}-slim-bookworm" in dockerfile, "Docker Rust version differs", errors)
    require(f"RUST_VERSION: {rust_version}" in workflow, "release workflow Rust version differs", errors)
    require(f"# Lumen {version}" in notes, "release notes heading differs", errors)

    if errors:
        parser.error("; ".join(errors))
    print(f"release metadata is consistent for {args.version}")


if __name__ == "__main__":
    main()
