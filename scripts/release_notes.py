"""Print the CHANGELOG.md section for a version (used as the GitHub Release body).

python scripts/release_notes.py 0.2.0
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def section(changelog: str, version: str) -> str:
    match = re.search(
        rf'^## {re.escape(version)}\b.*?$(?P<body>.*?)(?=^## |\Z)', changelog, re.MULTILINE | re.DOTALL
    )
    if not match:
        raise ValueError(f'CHANGELOG.md has no section for {version}')
    return match.group('body').strip()


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print('usage: release_notes.py VERSION', file=sys.stderr)
        return 2
    print(section((ROOT / 'CHANGELOG.md').read_text(), args[0].removeprefix('v')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
