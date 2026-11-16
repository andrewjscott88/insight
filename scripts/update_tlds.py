"""Regenerate ``src/insight/data/tlds.txt`` from a Public Suffix List file.

    curl -sSfO https://publicsuffix.org/list/public_suffix_list.dat
    python scripts/update_tlds.py public_suffix_list.dat

Keeps only the top-level labels of the ICANN section (punycode for internationalised TLDs). Review the diff: a
removed TLD means names under it stop being extracted as domains. Re-run the extraction benchmark afterwards.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'src' / 'insight' / 'data' / 'tlds.txt'


def icann_tlds(psl_text: str) -> tuple[list[str], str, str]:
    """``(sorted ASCII TLDs, version, commit)`` from the text of ``public_suffix_list.dat``."""
    lines = psl_text.splitlines()
    version = next(
        (line.split(':', 1)[1].strip() for line in lines if line.startswith('// VERSION')), 'unknown'
    )
    commit = next(
        (line.split(':', 1)[1].strip() for line in lines if line.startswith('// COMMIT')), 'unknown'
    )
    try:
        section = lines[
            lines.index('// ===BEGIN ICANN DOMAINS===') : lines.index('// ===END ICANN DOMAINS===')
        ]
    except ValueError as exc:
        raise ValueError('Not a Public Suffix List file (ICANN section markers missing)') from exc
    tlds: set[str] = set()
    for raw in section:
        line = raw.strip()
        if not line or line.startswith('//'):
            continue
        label = line.lstrip('*.!').split('.')[-1].lower()
        tlds.add(label if label.isascii() else label.encode('idna').decode('ascii'))
    return sorted(tlds), version, commit


def render(tlds: list[str], version: str, commit: str) -> str:
    header = (
        '# Top-level domains (ICANN section) used to validate extracted domain names.\n'
        '# Derived from the Public Suffix List, https://publicsuffix.org/ '
        f'(VERSION {version}, COMMIT {commit}).\n'
        '# The Public Suffix List is licensed under the Mozilla Public License 2.0: https://mozilla.org/MPL/2.0/\n'
        '# Only the top-level labels are kept (punycode for internationalised TLDs). Regenerate with\n'
        '# `python scripts/update_tlds.py path/to/public_suffix_list.dat` - see docs/EXTRACTION.md.\n'
    )
    return header + '\n'.join(tlds) + '\n'


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('psl', type=Path, help='path to public_suffix_list.dat')
    parser.add_argument('--output', type=Path, default=TARGET)
    args = parser.parse_args(argv)
    tlds, version, commit = icann_tlds(args.psl.read_text(encoding='utf-8'))
    if len(tlds) < 1000:
        print(f'Refusing to write only {len(tlds)} TLDs: is this the full list?', file=sys.stderr)
        return 1
    args.output.write_text(render(tlds, version, commit), encoding='utf-8')
    print(f'Wrote {len(tlds)} TLDs (PSL {version}) to {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
