"""A local PDF goes through the same report and TLP flow as a workspace upload."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from sqlalchemy import select

from insight import cli
from insight.models import AuditEvent, Document, database

FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'advisory.pdf'


@pytest.mark.skipif(sys.platform != 'linux', reason='PDF extraction requires the Linux sandbox')
def test_cli_imports_pdf_with_provenance_and_honors_instance_limit(
    monkeypatch: pytest.MonkeyPatch, database_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv('INSIGHT_DATABASE_URL', database_url)
    monkeypatch.setenv('INSIGHT_MAX_TLP', 'AMBER')
    assert cli.main(['import-pdf', str(FIXTURE)]) == 0
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() in capsys.readouterr().out
    assert cli.main(['import-pdf', str(FIXTURE)]) == 0
    assert 'Already imported' in capsys.readouterr().out
    assert cli.main(['import-pdf', str(FIXTURE), '--tlp', 'RED', '--title', 'Private report']) == 1
    assert 'TLP' in capsys.readouterr().err

    engine, sessions = database(database_url, migrate=False)
    try:
        with sessions() as db:
            doc = db.scalars(select(Document)).one()
            assert (doc.title, doc.source_name, doc.tlp) == ('advisory', 'Local PDF', 'AMBER')
            assert 'cli' in db.scalars(select(AuditEvent.actor)).all()
    finally:
        engine.dispose()


def test_cli_parses_before_opening_the_database(
    monkeypatch: pytest.MonkeyPatch, database_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The sandboxed parse can take 10 s, so the database is opened only after it (review note)."""
    from collections.abc import Iterator
    from contextlib import contextmanager
    from typing import Any

    from insight import cli_pdf
    from insight.cli import _current_database as real
    from insight.pdf_import import ParsedPdf
    from insight.services import pdf_reports

    monkeypatch.setenv('INSIGHT_DATABASE_URL', database_url)
    order: list[str] = []

    def parse(data: bytes) -> ParsedPdf:
        order.append('parse')
        return ParsedPdf('Advisory text about 192.0.2.45.', hashlib.sha256(data).hexdigest(), len(data), 1)

    @contextmanager
    def current_database() -> Iterator[Any]:
        order.append('database')
        with real() as sessions:
            yield sessions

    monkeypatch.setattr(pdf_reports, 'parse_pdf', parse)
    monkeypatch.setattr(cli_pdf, '_current_database', current_database)
    assert cli.main(['import-pdf', str(FIXTURE)]) == 0
    assert 'Imported PDF as report' in capsys.readouterr().out
    assert order == ['parse', 'database']
