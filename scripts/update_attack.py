"""Regenerate ``src/insight/data/attack-enterprise.json`` from MITRE's Enterprise ATT&CK STIX bundle.

    curl -sSfO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python scripts/update_attack.py enterprise-attack.json

Keeps what Insight needs to tag reports: every current technique and sub-technique (ID, name, tactics)
and the tactics in matrix order. Revoked and deprecated techniques are left out, so a report that names one
is not tagged with it. Review the diff: a technique that disappears stops being suggested, and existing
tags on it stay but show as "not in the current catalog".

MITRE ATT&CK is reproduced under MITRE's terms of use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/);
the generated file carries MITRE's copyright notice.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'src' / 'insight' / 'data' / 'attack-enterprise.json'
SOURCE = 'https://github.com/mitre-attack/attack-stix-data (enterprise-attack)'
TERMS = 'https://attack.mitre.org/resources/legal-and-branding/terms-of-use/'


def _attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack' and ref.get('external_id'):
            return str(ref['external_id'])
    return None


def _current(obj: dict[str, Any]) -> bool:
    return not obj.get('revoked') and not obj.get('x_mitre_deprecated')


def compact(bundle: dict[str, Any]) -> dict[str, Any]:
    """The catalog Insight ships, from a parsed ``enterprise-attack.json`` STIX bundle."""
    objects = bundle.get('objects')
    if bundle.get('type') != 'bundle' or not isinstance(objects, list):
        raise ValueError('Not a STIX bundle')
    collection = next((o for o in objects if o.get('type') == 'x-mitre-collection'), None)
    matrix = next((o for o in objects if o.get('type') == 'x-mitre-matrix' and _current(o)), None)
    if collection is None or matrix is None:
        raise ValueError('Not an ATT&CK bundle (collection or matrix missing)')
    tactics_by_ref = {o['id']: o for o in objects if o.get('type') == 'x-mitre-tactic' and _current(o)}
    tactics = []
    for ref in matrix['tactic_refs']:
        tactic = tactics_by_ref.get(ref)
        tactic_id = _attack_id(tactic) if tactic else None
        if tactic is None or tactic_id is None:
            continue
        tactics.append({'id': tactic_id, 'shortname': tactic['x_mitre_shortname'], 'name': tactic['name']})
    known = {t['shortname'] for t in tactics}
    techniques = []
    for obj in objects:
        if obj.get('type') != 'attack-pattern' or not _current(obj):
            continue
        technique_id = _attack_id(obj)
        if technique_id is None or not technique_id.startswith('T'):
            continue
        phases = [
            p['phase_name']
            for p in obj.get('kill_chain_phases', [])
            if p.get('kill_chain_name') == 'mitre-attack' and p.get('phase_name') in known
        ]
        techniques.append({'id': technique_id, 'name': obj['name'], 'tactics': phases})
    techniques.sort(key=lambda t: t['id'])
    if not techniques or not tactics:
        raise ValueError('No current techniques or tactics in the bundle')
    year = str(collection.get('modified', ''))[:4] or 'unknown'
    return {
        'notice': (
            f'© {year} The MITRE Corporation. '
            'This work is reproduced and distributed with the permission of The MITRE Corporation.'
        ),
        'terms': TERMS,
        'source': SOURCE,
        'version': str(collection.get('x_mitre_version', 'unknown')),
        'tactics': tactics,
        'techniques': techniques,
    }


def render(catalog: dict[str, Any]) -> str:
    """Stable JSON with one tactic or technique per line, so updates review as small diffs."""
    head = {k: v for k, v in catalog.items() if k not in ('tactics', 'techniques')}
    lines = ['{']
    lines += [f'  {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)},' for k, v in head.items()]
    for key in ('tactics', 'techniques'):
        items = [f'    {json.dumps(item, ensure_ascii=False)}' for item in catalog[key]]
        lines.append(f'  "{key}": [')
        lines.append(',\n'.join(items))
        lines.append('  ],' if key == 'tactics' else '  ]')
    lines.append('}')
    return '\n'.join(lines) + '\n'


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('bundle', type=Path, help='enterprise-attack.json from MITRE attack-stix-data')
    parser.add_argument('--output', type=Path, default=TARGET)
    args = parser.parse_args(argv)
    try:
        catalog = compact(json.loads(args.bundle.read_text(encoding='utf-8')))
    except (OSError, ValueError, KeyError) as exc:
        print(f'update_attack: {exc}', file=sys.stderr)
        return 1
    args.output.write_text(render(catalog), encoding='utf-8')
    print(
        f'wrote {args.output}: ATT&CK {catalog["version"]}, {len(catalog["tactics"])} tactics, '
        f'{len(catalog["techniques"])} techniques'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
