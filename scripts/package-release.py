#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep each platform's binaries together; never merge files with the same name."""
import argparse
import hashlib
from pathlib import Path
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=['Linux-X64', 'Linux-ARM64', 'macOS-X64', 'macOS-ARM64', 'Windows-X64', 'Windows-ARM64'])
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    suffix = '.exe' if args.platform.startswith('Windows-') else ''
    binaries = [root / 'target' / 'release' / f'{name}{suffix}' for name in ('lumen', 'lumenctl')]
    for binary in binaries:
        if not binary.is_file():
            parser.error(f'missing release binary: {binary.name}')
    output = root / 'release'
    output.mkdir(exist_ok=True)
    archive = output / f'lumen-{args.platform}.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as package:
        for binary in binaries:
            package.write(binary, binary.name)
        files = [root / name for name in ('LICENSE', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md')]
        files += sorted((root / 'docs').glob('*.md'))
        files += sorted((root / 'config').glob('*.toml'))
        for path in files:
            package.write(path, path.relative_to(root))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(f'{digest}  {archive.name}\n', encoding='utf-8')


if __name__ == '__main__':
    main()
