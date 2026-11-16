"""Licence gate for the *runtime* dependency set (what ships in the container image).

Reads package names from ``requirements.lock``, looks up installed metadata and evaluates SPDX expressions
(``AND``/``OR``/parentheses), falling back to the legacy ``License`` field and trove classifiers. Copyleft or
unknown licences fail the gate unless listed in ``REVIEWED`` with a justification.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ALLOWED = {
    'MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'ISC', 'PSF-2.0', 'Python-2.0', 'MPL-2.0', '0BSD',
    'Unlicense', 'CC0-1.0', 'Zlib', 'HPND', 'Public-Domain',
}  # fmt: skip
ALIASES = {
    'mit license': 'MIT',
    'mit': 'MIT',
    'apache 2.0': 'Apache-2.0',
    'apache-2.0': 'Apache-2.0',
    'apache software license': 'Apache-2.0',
    'apache license 2.0': 'Apache-2.0',
    'bsd license': 'BSD-3-Clause',
    'bsd': 'BSD-3-Clause',
    'bsd-3-clause': 'BSD-3-Clause',
    'bsd-2-clause': 'BSD-2-Clause',
    'psfl': 'PSF-2.0',
    'psf-2.0': 'PSF-2.0',
    'python software foundation license': 'PSF-2.0',
    'mpl-2.0': 'MPL-2.0',
    'mozilla public license 2.0 (mpl 2.0)': 'MPL-2.0',
    'isc license (iscl)': 'ISC',
    'isc': 'ISC',
    'public domain': 'Public-Domain',
    'gnu general public license (gpl)': 'GPL',
}
#: Packages whose metadata is ambiguous, with the human review that cleared them.
REVIEWED: dict[str, str] = {}


@dataclass(frozen=True)
class Verdict:
    package: str
    licence: str
    allowed: bool
    source: str


def evaluate_spdx(expression: str, is_allowed: Callable[[str], bool]) -> bool:
    """Evaluate an SPDX expression: ``A OR B`` needs one allowed side, ``A AND B`` needs both."""
    tokens = re.findall(r'\(|\)|[^\s()]+', expression)
    position = 0

    def parse_or() -> bool:
        nonlocal position
        result = parse_and()
        while position < len(tokens) and tokens[position].upper() == 'OR':
            position += 1
            right = parse_and()
            result = result or right
        return result

    def parse_and() -> bool:
        nonlocal position
        result = parse_atom()
        while position < len(tokens) and tokens[position].upper() == 'AND':
            position += 1
            right = parse_atom()
            result = result and right
        return result

    def parse_atom() -> bool:
        nonlocal position
        token = tokens[position]
        position += 1
        if token == '(':  # noqa: S105 - an SPDX token, not a secret
            result = parse_or()
            position += 1  # ')'
            return result
        if position < len(tokens) and tokens[position].upper() == 'WITH':
            position += 2  # licence exceptions only ever relax terms
        return is_allowed(token)

    return parse_or()


def normalise(name: str) -> str:
    return ALIASES.get(name.strip().lower(), name.strip())


def verdict(package: str, meta: metadata.PackageMetadata) -> Verdict:
    fields = meta.json  # normalised keys: license_expression, license, classifier
    if package in REVIEWED:
        return Verdict(package, f'reviewed: {REVIEWED[package]}', True, 'review')
    if expression := str(fields.get('license_expression') or ''):
        return Verdict(package, expression, evaluate_spdx(expression, lambda t: t in ALLOWED), 'spdx')
    legacy = str(fields.get('license') or '').strip()
    if legacy and len(legacy) < 80 and '\n' not in legacy:
        name = normalise(legacy)
        return Verdict(package, name, name in ALLOWED, 'license-field')
    raw_classifiers = fields.get('classifier') or []
    classifiers = [
        normalise(c.split('::')[-1])
        for c in ([raw_classifiers] if isinstance(raw_classifiers, str) else raw_classifiers)
        if c.startswith('License ::')
    ]
    if classifiers:
        # Trove classifiers do not say AND/OR; multi-licensed packages list alternatives, so one allowed
        # licence suffices. Mixed lists are still printed for a human to see.
        return Verdict(
            package, ' | '.join(classifiers), any(c in ALLOWED for c in classifiers), 'classifiers'
        )
    return Verdict(package, 'UNKNOWN', False, 'none')


def locked_packages(lock: Path) -> list[str]:
    return sorted({line.split('==')[0].strip() for line in lock.read_text().splitlines() if '==' in line})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--lock', type=Path, default=ROOT / 'requirements.lock')
    args = parser.parse_args(argv)
    failures = 0
    for package in locked_packages(args.lock):
        try:
            meta = metadata.metadata(package)
        except metadata.PackageNotFoundError:
            continue  # platform-specific pin (e.g. uvloop on Windows) not installed here
        result = verdict(package, meta)
        failures += not result.allowed
        print(f'{"ok  " if result.allowed else "FAIL"} {package:24} {result.licence}  [{result.source}]')
    if failures:
        print(f'{failures} package(s) need licence review (add to REVIEWED with a justification).')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
