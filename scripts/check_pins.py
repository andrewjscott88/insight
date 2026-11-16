"""Supply-chain pin check: container base images by digest and GitHub Actions by full commit SHA.

python scripts/check_pins.py            # report (GitHub warning annotations), exit 0
python scripts/check_pins.py --strict   # release gate: exit 1 if anything is pinned only by tag
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FROM = re.compile(r'^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)', re.IGNORECASE | re.MULTILINE)
USES = re.compile(r'^\s*-?\s*uses:\s*(?P<ref>\S+)', re.MULTILINE)
SHA = re.compile(r'@[0-9a-f]{40}$')


def unpinned_images(dockerfile: Path) -> list[str]:
    stages = {m.group(1).lower() for m in re.finditer(r'\bAS\s+(\S+)', dockerfile.read_text(), re.IGNORECASE)}
    found = []
    for match in FROM.finditer(dockerfile.read_text()):
        image = match.group('image')
        if image.lower() in stages or image.startswith('$'):
            continue
        if '@sha256:' not in image:
            found.append(f'{dockerfile.name}: base image {image} is not pinned by digest')
    return found


def unpinned_actions(workflow: Path) -> list[str]:
    found = []
    for match in USES.finditer(workflow.read_text()):
        ref = match.group('ref').strip('\'"')
        if ref.startswith(('./', 'docker://')):
            continue
        if not SHA.search(ref):
            found.append(f'{workflow.name}: {ref} is not pinned to a commit SHA')
    return found


def problems(root: Path = ROOT) -> list[str]:
    found = unpinned_images(root / 'Dockerfile')
    for workflow in sorted((root / '.github' / 'workflows').glob('*.y*ml')):
        found += unpinned_actions(workflow)
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--strict', action='store_true')
    args = parser.parse_args(argv)
    found = problems()
    level = 'error' if args.strict else 'warning'
    for problem in found:
        print(f'::{level}::{problem}')
    if not found:
        print('All base images and actions are pinned.')
    return 1 if found and args.strict else 0


if __name__ == '__main__':
    sys.exit(main())
