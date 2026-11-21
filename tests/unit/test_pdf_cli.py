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
