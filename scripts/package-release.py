#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep each platform's binaries together; never merge files with the same name."""
import argparse
import hashlib
from pathlib import Path
import re
import tarfile
import zipfile


PLATFORMS = {
    'Linux-X64': ('linux-amd64', '.tar.gz'),
    'Linux-ARM64': ('linux-arm64', '.tar.gz'),
    'macOS-X64': ('macos-amd64', '.tar.gz'),
    'macOS-ARM64': ('macos-arm64', '.tar.gz'),
    'Windows-X64': ('windows-amd64', '.zip'),
    'Windows-ARM64': ('windows-arm64', '.zip'),
}


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=PLATFORMS)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?', args.version):
        parser.error('version must be a v-prefixed semantic version')
    root = Path(__file__).resolve().parent.parent
    suffix = '.exe' if args.platform.startswith('Windows-') else ''
    binaries = [root / 'target' / 'release' / f'{name}{suffix}' for name in ('lumen', 'lumenctl')]
    for binary in binaries:
        if not binary.is_file():
            parser.error(f'missing release binary: {binary.name}')
    output = root / 'release'
    output.mkdir(exist_ok=True)
    platform, extension = PLATFORMS[args.platform]
    archive = output / f'lumen-{args.version}-{platform}{extension}'
    prefix = f'lumen-{args.version}'
    files = [root / name for name in ('LICENSE', 'README.md', 'SECURITY.md')]
    files += sorted((root / 'docs').rglob('*.md'))
    files += sorted((root / 'config').rglob('*.toml'))
    if extension == '.zip':
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as package:
            for path in binaries + files:
                name = path.name if path in binaries else path.relative_to(root)
                package.write(path, Path(prefix) / name)
        with zipfile.ZipFile(archive) as package:
            if package.testzip() is not None:
                parser.error('ZIP integrity check failed')
    else:
        with tarfile.open(archive, 'w:gz') as package:
            for path in binaries + files:
                name = path.name if path in binaries else path.relative_to(root)
                package.add(path, arcname=Path(prefix) / name, recursive=False)
        with tarfile.open(archive, 'r:gz') as package:
            package.getmembers()
    checksum = archive.with_name(f'{archive.name}.sha256')
    checksum.write_text(f'{digest(archive)}  {archive.name}\n', encoding='utf-8')


if __name__ == '__main__':
    main()
