"""Regenerate ``src/insight/data/actors.json``, the bundled threat-group library (TIP 2.10, ADR 0024).

    curl -sSfO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/<commit>/enterprise-attack/enterprise-attack-<version>.json
    curl -sSfO https://raw.githubusercontent.com/MISP/misp-galaxy/<commit>/clusters/threat-actor.json
    python scripts/update_actors.py enterprise-attack-<version>.json threat-actor.json

Use the releases pinned in ``insight.threat_library_sync.PINNED`` (``--pinned`` checks the files' SHA-256
against them), so the bundled edition and ``insight threat-library-sync`` describe the same data. To move to a
new ATT&CK or MISP galaxy release, update ``PINNED`` first, then run this, ``scripts/update_attack.py`` and
the tests, and review the diff: every new or changed industry claim quotes its source, so read them.

MITRE ATT&CK is reproduced under MITRE's terms of use; the MISP galaxy is CC0-1.0 (or BSD-2-Clause).
See NOTICE.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from insight.threat_library_build import build, check_sentences, sha256
from insight.threat_library_sync import PINNED, render

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'src' / 'insight' / 'data' / 'actors.json'


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'attack', type=Path, help='enterprise-attack-<version>.json from MITRE attack-stix-data'
    )
    parser.add_argument('misp', type=Path, help='clusters/threat-actor.json from MISP misp-galaxy')
    parser.add_argument('--output', type=Path, default=TARGET)
    parser.add_argument(
        '--full', action='store_true', help='write the full edition instead of the bundled one'
    )
    parser.add_argument(
        '--pinned', action='store_true', help='refuse files that differ from the pinned releases'
    )
    args = parser.parse_args(argv)
    try:
        payloads = {'attack': args.attack.read_bytes(), 'misp-galaxy': args.misp.read_bytes()}
        if args.pinned:
            for key, payload in payloads.items():
                if sha256(payload) != PINNED[key].sha256:
                    raise ValueError(f'{key}: SHA-256 differs from the pinned release {PINNED[key].version}')
        bundle: dict[str, Any] = json.loads(payloads['attack'])
        cluster: dict[str, Any] = json.loads(payloads['misp-galaxy'])
        library = build(
            bundle,
            cluster,
            full=args.full,
            attack_source=PINNED['attack'].describe(sha256(payloads['attack'])),
            misp_source=PINNED['misp-galaxy'].describe(sha256(payloads['misp-galaxy'])),
        )
        problems = check_sentences(library, bundle)
        if problems:
            raise ValueError('; '.join(problems[:5]))
    except (OSError, ValueError, KeyError) as exc:
        print(f'update_actors: {exc}', file=sys.stderr)
        return 1
    args.output.write_text(render(library), encoding='utf-8')
    claims = sum(len(c['industries']) for g in library['groups'] for c in g['industries'])
    print(
        f'wrote {args.output}: {library["edition"]} edition, '
        f'ATT&CK {library["sources"]["attack"]["version"]}, '
        f'{len(library["groups"])} groups, {claims} industry claims, {len(library["techniques"])} techniques'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
