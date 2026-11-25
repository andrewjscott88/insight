"""Block files that must never be committed: credentials, databases and private keys.

Checks tracked files (``git ls-files``) plus staged additions. The test fixtures directory is exempt for
database files because release upgrade fixtures are synthetic by construction.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_NAMES = re.compile(r'(^|/)(\.env(\..*)?|.*\.(db|sqlite3?|pem|key|p12|pfx))$')
#: Where `make backup` and `make export-iocs` write: database copies and TLP-labelled exports. Records of real
#: deployments stay outside this public repository too (AGENTS.md).
FORBIDDEN_DIRECTORIES = re.compile(r'^(backups|exports|docs/deployments)/')
ALLOWED = re.compile(r'^(\.env\.example|tests/fixtures/.*\.sqlite3)$')
SECRET_CONTENT = [
    (re.compile(r'-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----'), 'private key'),
    (
        re.compile(r'^\s*INSIGHT_(PASSWORD|SESSION_SECRET)\s*=\s*(?!replace-with)\S{12,}', re.MULTILINE),
        'credential',
    ),
    (re.compile(r'\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b'), 'GitHub token'),
    (re.compile(r'\binsk_[0-9a-f]{12}_[A-Za-z0-9_-]{43}'), 'Insight API key'),
]


def tracked_files(root: Path = ROOT) -> list[str]:
    result = subprocess.run(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def problems(paths: Iterable[str], root: Path = ROOT) -> list[str]:
    found = []
    for path in paths:
        if FORBIDDEN_DIRECTORIES.match(path) or (FORBIDDEN_NAMES.search(path) and not ALLOWED.match(path)):
            found.append(f'{path}: this kind of file must not be committed')
            continue
        file = root / path
        if not file.is_file() or file.stat().st_size > 1_000_000:
            continue
        try:
            text = file.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            continue
        found.extend(
            f'{path}: looks like it contains a {label}'
            for pattern, label in SECRET_CONTENT
            if pattern.search(text)
        )
    return found


def main(argv: Sequence[str] | None = None) -> int:
    paths = list(argv) if argv else tracked_files()
    found = problems(paths)
    for problem in found:
        print(f'::error::{problem}')
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
