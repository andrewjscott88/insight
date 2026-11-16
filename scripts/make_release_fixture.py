"""Create the upgrade fixture for the current version: ``tests/fixtures/releases/insight-<version>.sqlite3``.

Run once per final release (see docs/RELEASING.md). Future versions' test suites upgrade every committed
fixture, so a migration that breaks real user data fails CI long before it reaches anyone.

The database is written through the normal services (not raw SQL) and exercises every table: demo reports,
a KEV entry with a publisher edit (revisions), an RSS item, a reviewed manual report with an accepted
observation and a note, a watch term, a source run and a cached enrichment. All data is synthetic.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import select

from insight import __version__, services
from insight.connectors import SOURCES, import_kev, parse_feed
from insight.demo import seed
from insight.models import Enrichment, Observation, SourceRun, database
from insight.schemas import DocumentInput

ROOT = Path(__file__).resolve().parent.parent


def kev(description: str) -> bytes:
    row = {
        'cveID': 'CVE-2024-3400',
        'vendorProject': 'Palo Alto Networks',
        'product': 'PAN-OS',
        'dateAdded': '2024-04-12',
        'dueDate': '2024-04-19',
        'requiredAction': 'Apply mitigations per vendor instructions.',
        'shortDescription': description,
    }
    return json.dumps({'vulnerabilities': [row]}).encode()


def build(path: Path) -> None:
    engine, sessions = database(f'sqlite:///{path}')
    try:
        with sessions.begin() as db:
            seed(db)
            import_kev(db, kev('Command injection in GlobalProtect.'))
        with sessions.begin() as db:
            import_kev(db, kev('OS command injection in the GlobalProtect feature of PAN-OS.'))
            feed = (
                b'<rss><channel><item><title>ISC Diary: Scanning for 192.0.2.10</title>'
                b'<link>https://isc.sans.edu/diary/1</link><description>Scans.</description></item></channel></rss>'
            )
            for item in parse_feed(feed, SOURCES['sans-isc']):
                services.ingest(
                    db,
                    item.document,
                    ref=services.SourceRef('sans-isc', item.external_id or ''),
                    truncated=item.truncated,
                )
            manual, _ = services.ingest(
                db,
                DocumentInput(
                    title='Analyst paste',
                    body='Seen CVE-2024-3400 exploited; beacon to 198.51.100.7',
                    source_name='IR team',
                    tlp='AMBER',
                ),
            )
            services.set_document_status(db, manual.id, 'reviewed')
            services.add_note(db, manual.id, 'Escalated to SOC lead.')
            observation = db.scalars(select(Observation).where(Observation.document_id == manual.id)).first()
            if observation is None:
                raise RuntimeError('fixture report produced no observations')
            services.set_observation_status(db, observation.id, 'accepted')
            services.add_watch_term(db, 'GlobalProtect')
            db.add(SourceRun(source_key='cisa-kev', status='success', message='fixture'))
            db.add(Enrichment(cve='CVE-2024-3400', provider='epss', payload='{"data": []}'))
    finally:
        engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    target = ROOT / 'tests' / 'fixtures' / 'releases' / f'insight-{__version__}.sqlite3'
    if target.exists() and '--force' not in (argv or sys.argv[1:]):
        print(f'{target.relative_to(ROOT)} already exists (use --force to rebuild).', file=sys.stderr)
        return 1
    target.unlink(missing_ok=True)
    build(target)
    print(f'Wrote {target.relative_to(ROOT)}. Commit it with the release.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
