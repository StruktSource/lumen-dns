#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build one checked, reproducible Lumen release archive."""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import zipfile


PLATFORMS = {
    "Linux-X64": ("linux-amd64", ".tar.gz"),
    "Linux-ARM64": ("linux-arm64", ".tar.gz"),
    "macOS-X64": ("macos-amd64", ".tar.gz"),
    "macOS-ARM64": ("macos-arm64", ".tar.gz"),
    "Windows-X64": ("windows-amd64", ".zip"),
    "Windows-ARM64": ("windows-arm64", ".zip"),
}
SEMVER = re.compile(r"v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)")
SOURCE_DIRS = ("config", "deploy", "docs")
ROOT_FILES = ("CHANGELOG.md", "LICENSE", "README.md", "RELEASE_NOTES.md", "SECURITY.md")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def release_files(root: Path) -> list[Path]:
    files = [root / name for name in ROOT_FILES]
    for directory in SOURCE_DIRS:
        files.extend(path for path in sorted((root / directory).rglob("*")) if path.is_file())
    missing = [path for path in files if not path.is_file()]
    if missing:
        raise ValueError(f"missing package input: {missing[0].relative_to(root)}")
    return files


def verify_binary(binary: Path, expected_version: str) -> None:
    try:
        result = subprocess.run(
            [binary, "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"could not verify {binary.name}: {error}") from error
    actual = result.stdout.strip().split()[-1] if result.stdout.strip() else ""
    if actual != expected_version:
        raise ValueError(
            f"{binary.name} reports version {actual or '<empty>'}; expected {expected_version}"
        )


def archive_name(root: Path, binaries: list[Path], path: Path) -> PurePosixPath:
    return PurePosixPath(path.name if path in binaries else path.relative_to(root).as_posix())


def manifest(prefix: str, entries: list[tuple[PurePosixPath, Path]]) -> bytes:
    lines = [f"Lumen release package {prefix.removeprefix('lumen-')}", "", "SHA-256  FILE"]
    lines.extend(f"{digest(path)}  {name}" for name, path in entries)
    return ("\n".join(lines) + "\n").encode()


def add_tar_file(package: tarfile.TarFile, source: Path, name: PurePosixPath, epoch: int) -> None:
    info = tarfile.TarInfo(str(name))
    info.size = source.stat().st_size
    info.mode = 0o755 if os.access(source, os.X_OK) else 0o644
    info.mtime = epoch
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    with source.open("rb") as stream:
        package.addfile(info, stream)


def build_tar(
    archive: Path,
    prefix: str,
    entries: list[tuple[PurePosixPath, Path]],
    package_manifest: bytes,
    epoch: int,
) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as package:
                for name, path in entries:
                    add_tar_file(package, path, PurePosixPath(prefix) / name, epoch)
                info = tarfile.TarInfo(f"{prefix}/PACKAGE-MANIFEST.txt")
                info.size = len(package_manifest)
                info.mode = 0o644
                info.mtime = epoch
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                package.addfile(info, io.BytesIO(package_manifest))


def zip_info(name: PurePosixPath, executable: bool, epoch: int) -> zipfile.ZipInfo:
    # ZIP cannot store dates before 1980 and stores seconds in two-second units.
    import datetime

    timestamp = datetime.datetime.fromtimestamp(max(epoch, 315532800), datetime.UTC)
    info = zipfile.ZipInfo(str(name), timestamp.timetuple()[:6])
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    mode = stat.S_IFREG | (0o755 if executable else 0o644)
    info.external_attr = mode << 16
    return info


def build_zip(
    archive: Path,
    prefix: str,
    entries: list[tuple[PurePosixPath, Path]],
    package_manifest: bytes,
    epoch: int,
) -> None:
    with zipfile.ZipFile(archive, "w") as package:
        for name, path in entries:
            info = zip_info(PurePosixPath(prefix) / name, os.access(path, os.X_OK), epoch)
            package.writestr(info, path.read_bytes())
        info = zip_info(PurePosixPath(prefix) / "PACKAGE-MANIFEST.txt", False, epoch)
        package.writestr(info, package_manifest)


def verify_archive(archive: Path, expected_names: set[str]) -> None:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            if package.testzip() is not None:
                raise ValueError("ZIP integrity check failed")
            actual_names = set(package.namelist())
    else:
        with tarfile.open(archive, "r:gz") as package:
            if any(not member.isfile() for member in package.getmembers()):
                raise ValueError("release archive contains a non-file entry")
            actual_names = set(package.getnames())
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise ValueError(f"archive contents differ: missing={missing}, extra={extra}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    match = SEMVER.fullmatch(args.version)
    if not match:
        parser.error("version must be a v-prefixed semantic version")
    version = match.group(1)
    root = Path(__file__).resolve().parent.parent
    suffix = ".exe" if args.platform.startswith("Windows-") else ""
    binaries = [root / "target" / "release" / f"{name}{suffix}" for name in ("lumen", "lumenctl")]
    for binary in binaries:
        if not binary.is_file():
            parser.error(f"missing release binary: {binary.name}")
    if os.name == "nt" or suffix == "":
        for binary in binaries:
            try:
                verify_binary(binary, version)
            except ValueError as error:
                parser.error(str(error))

    files = release_files(root)
    entries = [(archive_name(root, binaries, path), path) for path in binaries + files]
    platform, extension = PLATFORMS[args.platform]
    output = root / "release"
    output.mkdir(exist_ok=True)
    archive = output / f"lumen-{args.version}-{platform}{extension}"
    prefix = f"lumen-{args.version}"
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
    package_manifest = manifest(prefix, entries)
    if extension == ".zip":
        build_zip(archive, prefix, entries, package_manifest, epoch)
    else:
        build_tar(archive, prefix, entries, package_manifest, epoch)
    expected_names = {str(PurePosixPath(prefix) / name) for name, _ in entries}
    expected_names.add(f"{prefix}/PACKAGE-MANIFEST.txt")
    try:
        verify_archive(archive, expected_names)
    except ValueError as error:
        parser.error(str(error))
    checksum = archive.with_name(f"{archive.name}.sha256")
    checksum.write_text(f"{digest(archive)}  {archive.name}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
