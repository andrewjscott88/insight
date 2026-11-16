"""Regenerate ``docs/examples/insight-iocs-example.json`` from the synthetic demo data.

    python scripts/make_ioc_example.py          # rewrite the example after changing the export format
    python scripts/make_ioc_example.py --check  # exit 1 if the committed example is out of date (CI, tests)

The scenario is fixed: load the demo reports, accept ``relay.example.org`` and ``192.0.2.44`` in the first
report, reject ``2001:db8::42`` in the second, mark the first report as reviewed, then export with the default
filters. The reports get fixed ingestion times, and random IDs and the export time are replaced with stable
placeholders, so the file only changes when the export itself changes. docs/IOC_EXPORT.md quotes this file.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from insight import services
from insight.demo import REPORTS, seed
from insight.models import database
from insight.schemas import IocExportQuery

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / 'docs' / 'examples' / 'insight-iocs-example.json'
EDGE = 'Training scenario: edge appliance activity'
PIVOT = 'Training scenario: shared infrastructure pivot'
EPOCH = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)


def build_export() -> dict[str, Any]:
    """Run the fixed scenario in a throwaway in-memory database and return the raw export."""
    engine, sessions = database('sqlite://')
    try:
        with sessions.begin() as db:
            seed(db)
            docs = {d.title: d for d in services.search_documents(db, services.DocumentQuery(limit=10))}
            for n, (title, *_rest) in enumerate(REPORTS):  # fixed ingestion times: stable source order
                docs[title].created_at = (EPOCH + timedelta(minutes=5 * n)).isoformat()
            db.flush()
            for obs in services.detail(db, docs[EDGE])['observations']:
                if obs['value'] in ('relay.example.org', '192.0.2.44'):
                    services.set_observation_status(db, obs['id'], 'accepted')
            for obs in services.detail(db, docs[PIVOT])['observations']:
                if obs['value'] == '2001:db8::42':
                    services.set_observation_status(db, obs['id'], 'rejected')
            services.set_document_status(db, docs[EDGE].id, 'reviewed')
            return services.export_iocs(db, IocExportQuery())
    finally:
        engine.dispose()


def normalise(export: dict[str, Any]) -> dict[str, Any]:
    """Replace random IDs and the export time with stable placeholders (IDs keep first-seen order)."""
    ids: dict[str, str] = {}

    def stable_id(value: str) -> str:
        return ids.setdefault(value, f'00000000-0000-4000-8000-{len(ids) + 1:012d}')

    result: dict[str, Any] = json.loads(json.dumps(export))  # a deep copy
    result['export_id'] = stable_id(export['export_id'])
    result['generated_at'] = (EPOCH + timedelta(days=1)).isoformat()
    for ioc in result['iocs']:
        ioc['entity_id'] = stable_id(ioc['entity_id'])
        for source in ioc['sources']:
            source['document_id'] = stable_id(source['document_id'])
    return result


def render(export: dict[str, Any]) -> str:
    return json.dumps(export, indent=2, ensure_ascii=False) + '\n'


def main(argv: Sequence[str] | None = None, *, target: Path = EXAMPLE) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--check', action='store_true', help='verify the committed example; change nothing')
    args = parser.parse_args(argv)
    logging.getLogger('insight.migrations').setLevel(logging.ERROR)  # the throwaway database is always new
    expected = render(normalise(build_export()))
    if args.check:
        if not target.is_file() or target.read_text(encoding='utf-8') != expected:
            print(f'{target} is out of date. Run: python scripts/make_ioc_example.py', file=sys.stderr)
            return 1
        print(f'{target.name} is current.')
        return 0
    target.write_text(expected, encoding='utf-8')
    print(f'wrote {target}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
