"""Release-gate consistency checks for a tag such as ``v0.2.0`` or ``v0.2.0-rc.1``.

* the tag version matches ``insight.__version__`` (release candidates: the part before ``-rc``);
* ``CHANGELOG.md`` has a section for the version;
* ``docs/VALIDATION.md`` names the version;
* a database fixture for the release is committed (final releases only), so future versions keep proving
  that they can upgrade it (``tests/fixtures/releases/insight-<version>.sqlite3``).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAG = re.compile(r'^v(?P<version>\d+\.\d+\.\d+)(?:-rc\.(?P<rc>\d+))?$')


def package_version(root: Path = ROOT) -> str:
    match = re.search(r"__version__ = '([^']+)'", (root / 'src/insight/__init__.py').read_text())
    if not match:
        raise ValueError('Cannot find __version__ in src/insight/__init__.py')
    return match.group(1)


def problems(tag: str, root: Path = ROOT) -> list[str]:
    match = TAG.match(tag)
    if not match:
        return [f'{tag!r} is not a release tag (expected vX.Y.Z or vX.Y.Z-rc.N)']
    version, is_rc = match.group('version'), match.group('rc') is not None
    found: list[str] = []
    if package_version(root) != version:
        found.append(f'tag {tag} does not match insight.__version__ {package_version(root)}')
    changelog = (root / 'CHANGELOG.md').read_text()
    if not re.search(rf'^## {re.escape(version)}\b', changelog, re.MULTILINE):
        found.append(f'CHANGELOG.md has no "## {version}" section')
    if version not in (root / 'docs/VALIDATION.md').read_text():
        found.append(f'docs/VALIDATION.md does not mention {version}')
    fixture = root / 'tests/fixtures/releases' / f'insight-{version}.sqlite3'
    if not is_rc and not fixture.exists():
        found.append(f'missing upgrade fixture {fixture.relative_to(root)} (see docs/RELEASING.md)')
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('tag')
    args = parser.parse_args(argv)
    found = problems(args.tag)
    for problem in found:
        print(f'::error::{problem}')
    if not found:
        print(f'{args.tag}: release metadata is consistent.')
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main())
