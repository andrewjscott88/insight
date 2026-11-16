"""Regenerate or verify the hash-pinned lock files from ``pyproject.toml`` (requires ``uv``).

    python scripts/lock.py             # refresh locks after editing pyproject.toml (keeps existing pins)
    python scripts/lock.py --upgrade   # move every pin to the newest allowed version (weekly job)
    python scripts/lock.py --check     # CI: fail if a lock file is out of date with pyproject.toml

The ``--check`` mode exists because the 0.1.0 lock file pinned versions that did not exist and did not match
``pyproject.toml``; that drift made the project uninstallable and nothing caught it.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON_FLOOR = '3.11'


@dataclass(frozen=True)
class Lock:
    output: str
    source: str
    extras: tuple[str, ...] = ()


LOCKS = (
    Lock('requirements.lock', 'pyproject.toml'),
    Lock('requirements-dev.lock', 'pyproject.toml', ('dev',)),
    Lock('requirements-e2e.lock', 'pyproject.toml', ('dev', 'e2e')),
    Lock('requirements-build.lock', 'requirements-build.in'),
)


def compile_command(lock: Lock, output: Path, *, upgrade: bool) -> list[str]:
    command = ['uv', 'pip', 'compile', str(ROOT / lock.source), '--universal', '--generate-hashes']
    command += ['--python-version', PYTHON_FLOOR, '--no-header', '--quiet', '-o', str(output)]
    for extra in lock.extras:
        command += ['--extra', extra]
    if upgrade:
        command.append('--upgrade')
    return command


def pins(text: str) -> set[str]:
    """The ``name==version`` lines of a lock file, ignoring hashes, comments and layout."""
    return {line.split(' ')[0].split(';')[0].lower() for line in text.splitlines() if '==' in line}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='verify locks are current; change nothing')
    mode.add_argument('--upgrade', action='store_true', help='upgrade all pins')
    args = parser.parse_args(argv)
    if shutil.which('uv') is None:
        print('uv is required: https://docs.astral.sh/uv/', file=sys.stderr)
        return 2
    stale: list[str] = []
    for lock in LOCKS:
        target = ROOT / lock.output
        if not args.check:
            subprocess.run(compile_command(lock, target, upgrade=args.upgrade), check=True)
            print(f'wrote {lock.output}')
            continue
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / lock.output
            if target.exists():
                shutil.copyfile(target, candidate)  # uv keeps existing pins, so only real drift shows up
            subprocess.run(compile_command(lock, candidate, upgrade=False), check=True)
            if not target.exists() or pins(candidate.read_text()) != pins(target.read_text()):
                stale.append(lock.output)
    if stale:
        print(f'Out of date: {", ".join(stale)}. Run: python scripts/lock.py', file=sys.stderr)
        return 1
    if args.check:
        print('All lock files match pyproject.toml.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
