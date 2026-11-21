"""The rows the threat landscape is built from: theme words, techniques, KEV, history and the TLP limit."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from insight import services
from insight.brief import DEMO
from insight.demo import seed
from insight.models import Document, KEVRecord
from insight.schemas import DocumentInput
from insight.services import ingest, landscape_data

START = '2000-01-01T00:00:00+00:00'


def report(db: Session, title: str, body: str, *, tlp: str = 'GREEN', created: str | None = None) -> Document:
    doc, _ = ingest(db, DocumentInput(title=title, body=body, source_name='Feed', tlp=tlp))
    if created:
        doc.created_at = created
        db.flush()
    return doc


def test_themes_techniques_and_watch_terms_are_matched(db: Session) -> None:
    ransom = report(db, 'Ransomware wave', 'The gang left a RANSOM NOTE on each server.')
    phish = report(db, 'Lure', 'Spearphishing attachment (T1566.001) with a macro.')
    report(db, 'Advisory', 'An attacker could cause a denial of service condition in a 30-day window.')
    services.add_watch_term(db, 'macro')
    data = landscape_data(db, start=START)
    assert data.theme_words['ransomware'] == {ransom.id}
    assert data.theme_words['phishing'] == {phish.id}
    assert data.theme_words['ddos'] == set()
    assert data.techniques == [(phish.id, 'T1566.001')]
    assert data.watch == {'macro': {phish.id}}
    assert len(data.documents) == 3
    assert set(data.tlp.values()) == {'GREEN'}
    assert not data.truncated


def test_reports_above_the_limit_add_nothing(db: Session) -> None:
    green = report(db, 'Public', 'Phishing kit seen.', tlp='GREEN')
    report(db, 'Restricted', 'Ransomware with T1486, also phishing.', tlp='AMBER')
    data = landscape_data(db, start=START, max_tlp='GREEN')
    assert [d.id for d in data.documents] == [green.id]
    assert data.theme_words['phishing'] == {green.id}
    assert data.theme_words['ransomware'] == set()
    assert data.techniques == []
    assert data.tlp == {green.id: 'GREEN'}


def test_history_starts_at_the_first_real_report(db: Session) -> None:
    seed(db)
    for doc in db.query(Document):
        doc.created_at = '2026-01-01T00:00:00+00:00'  # the demo was loaded long ago
    real = report(db, 'Real', 'Botnet traffic.', created='2026-11-01T00:00:00+00:00')
    assert landscape_data(db, start=START, ignore=DEMO).first_received == real.created_at
    assert landscape_data(db, start=START).first_received == '2026-01-01T00:00:00+00:00'


def test_only_reports_from_the_start_are_read(db: Session) -> None:
    report(db, 'Old', 'Ransomware.', created='2026-01-01T00:00:00+00:00')
    new = report(db, 'New', 'Ransomware.', created='2026-11-20T00:00:00+00:00')
    data = landscape_data(db, start='2026-10-01T00:00:00+00:00')
    assert [d.id for d in data.documents] == [new.id]
    assert data.theme_words['ransomware'] == {new.id}
    assert data.first_received == '2026-01-01T00:00:00+00:00'


def test_kev_entries_from_the_start_date(db: Session) -> None:
    for cve, added in (('CVE-2026-0001', '2026-11-18'), ('CVE-2020-0001', '2020-05-01')):
        db.add(
            KEVRecord(
                cve=cve, vendor='Acme', product='Box', date_added=added, due_date='', required_action=''
            )
        )
    db.flush()
    data = landscape_data(db, start='2026-10-01T00:00:00+00:00')
    assert [k.cve for k in data.kev] == ['CVE-2026-0001']


def test_the_read_stops_at_its_limit_and_says_so(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('insight.services.landscape.MAX_LANDSCAPE_DOCUMENTS', 2)
    for i in range(3):
        report(db, f'R{i}', f'Report {i}.', created=f'2026-11-1{i}T00:00:00+00:00')
    data = landscape_data(db, start=START)
    assert data.truncated
    assert [d.title for d in data.documents] == ['R2', 'R1']
