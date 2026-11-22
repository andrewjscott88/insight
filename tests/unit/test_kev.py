"""CISA KEV import: validation is total (all-or-nothing) and imports are idempotent upserts."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from insight.connectors import (
    KEV_INBOX_LIMIT,
    KEV_NEW_ENTRY_LIMIT,
    MAX_BYTES,
    MAX_KEV_FIELD,
    MAX_KEV_ROWS,
    SOURCES,
    import_kev,
)
from insight.models import Document, KEVRecord


def kev_row(n: int = 12345, **changes: Any) -> dict[str, Any]:
    row = {
        'cveID': f'CVE-2024-{n}',
        'vendorProject': 'Fixture vendor',
        'product': 'Fixture product',
        'dateAdded': '2025-01-01',
        'dueDate': '2025-01-22',
        'requiredAction': 'Apply patch',
        'shortDescription': 'A fixture vulnerability.',
    }
    row.update(changes)
    return row


def payload(*rows: Any) -> bytes:
    return json.dumps({'vulnerabilities': list(rows)}).encode()


def documents(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(Document)) or 0


def test_import_creates_records_and_inbox_documents(db: Session) -> None:
    assert import_kev(db, payload(kev_row())) == (1, 1)
    record = db.get(KEVRecord, 'CVE-2024-12345')
    assert record is not None
    assert (record.vendor, record.due_date, record.required_action) == (
        'Fixture vendor',
        '2025-01-22',
        'Apply patch',
    )
    doc = db.scalar(select(Document))
    assert doc is not None
    assert doc.source_name == SOURCES['cisa-kev'].name
    assert doc.source_url == 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
    assert doc.title == 'CVE-2024-12345 · Fixture vendor Fixture product'
    assert 'Federal remediation due date: 2025-01-22' in doc.body


def test_reimport_is_an_upsert_without_duplicate_documents(db: Session) -> None:
    import_kev(db, payload(kev_row()))
    assert import_kev(db, payload(kev_row())) == (1, 0)
    assert import_kev(db, payload(kev_row(vendorProject='Renamed vendor')))[0] == 1
    record = db.get(KEVRecord, 'CVE-2024-12345')
    assert record is not None
    assert record.vendor == 'Renamed vendor'


def test_only_newest_entries_become_documents(db: Session) -> None:
    rows = [kev_row(10000 + i, dateAdded=f'2024-{1 + i % 12:02d}-{1 + i % 28:02d}') for i in range(150)]
    count, added = import_kev(db, payload(*rows))
    assert (count, added) == (150, KEV_INBOX_LIMIT)
    assert db.scalar(select(func.count()).select_from(KEVRecord)) == 150


def test_optional_fields_default_to_empty(db: Session) -> None:
    assert import_kev(db, payload({'cveID': 'CVE-2024-12345'})) == (1, 1)


@pytest.mark.parametrize(
    ('raw', 'message'),
    [
        (b'not json', 'valid JSON'),
        (b'[]', 'vulnerabilities array'),  # Regression: previously AttributeError.
        (b'{"vulnerabilities": {}}', 'vulnerabilities array'),
        (b'{}', 'vulnerabilities array'),
        (payload('not-a-dict'), 'Invalid KEV record'),  # Regression: previously AttributeError.
        (payload({'cveID': 12345}), 'Invalid CVE'),  # Regression: previously TypeError.
        (payload(kev_row(cveID='CVE-24-1')), 'Invalid CVE'),
        (payload(kev_row(cveID='cve-2024-12345')), 'Invalid CVE'),
        (payload(kev_row(product=None)), 'Invalid KEV record field'),
        (payload(kev_row(product=['list'])), 'Invalid KEV record field'),
        (payload(kev_row(shortDescription={'x': 1})), 'Invalid KEV record field'),
        (payload(kev_row(requiredAction='x' * (MAX_KEV_FIELD + 1))), 'Invalid KEV record field'),
    ],
)
def test_malformed_input_raises_value_error(db: Session, raw: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        import_kev(db, raw)


def test_validation_is_all_or_nothing(db: Session) -> None:
    with pytest.raises(ValueError, match='Invalid CVE'):
        import_kev(db, payload(kev_row(), {'cveID': 'INVALID'}))
    assert db.get(KEVRecord, 'CVE-2024-12345') is None
    assert documents(db) == 0


def test_row_count_is_bounded(db: Session) -> None:
    rows = [{'cveID': 'CVE-2024-1000'}] * (MAX_KEV_ROWS + 1)
    with pytest.raises(ValueError, match='bounded'):
        import_kev(db, payload(*rows))


def test_oversized_payload_rejected(db: Session) -> None:
    with pytest.raises(ValueError, match='size limit'):
        import_kev(db, b' ' * (MAX_BYTES + 1))


def test_limits_are_inclusive(db: Session) -> None:
    """Found by mutation testing: ``>`` vs ``>=`` at every limit survived. Exactly-at-limit input is valid."""
    exact_field = kev_row(requiredAction='x' * MAX_KEV_FIELD)
    assert import_kev(db, payload(exact_field))[0] == 1
    padded = payload(kev_row(n=54321))
    assert import_kev(db, padded + b' ' * (MAX_BYTES - len(padded)))[0] == 1


def test_inbox_documents_are_the_newest_entries(db: Session) -> None:
    rows = [kev_row(10000 + i, dateAdded=f'2020-01-{1 + i % 28:02d}') for i in range(KEV_INBOX_LIMIT)]
    rows.append(kev_row(99999, dateAdded='2030-01-01'))  # newest, listed last
    import_kev(db, payload(*rows))
    titles = set(db.scalars(select(Document.title)))
    assert any(t.startswith('CVE-2024-99999') for t in titles)
    assert len(titles) == KEV_INBOX_LIMIT


# --------------------------------------------------------------------------- TIP 1.1 inbox policy


def titles(db: Session) -> set[str]:
    return {t.split(' ')[0] for t in db.scalars(select(Document.title))}


def test_the_first_sync_reports_only_the_newest_entries(db: Session) -> None:
    """The whole catalog is background on the first sync: it must not flood the inbox."""
    rows = [kev_row(10000 + i, dateAdded=f'2021-{1 + i % 12:02d}-{1 + i % 28:02d}') for i in range(300)]
    assert import_kev(db, payload(*rows)) == (300, KEV_INBOX_LIMIT)


def test_a_later_addition_with_an_older_date_still_becomes_a_report(db: Session) -> None:
    newest = [kev_row(20000 + i, dateAdded='2030-01-01') for i in range(KEV_INBOX_LIMIT)]
    import_kev(db, payload(*newest))
    backdated = kev_row(30000, dateAdded='2019-06-01')  # added by CISA now, dated outside the newest 100
    assert import_kev(db, payload(*newest, backdated)) == (KEV_INBOX_LIMIT + 1, 1)
    assert 'CVE-2024-30000' in titles(db)


def test_more_than_the_limit_added_between_syncs_all_become_reports(db: Session) -> None:
    import_kev(db, payload(kev_row(1000, dateAdded='2020-01-01')))
    added = [kev_row(40000 + i, dateAdded=f'2025-{1 + i % 12:02d}-{1 + i % 28:02d}') for i in range(150)]
    count, made = import_kev(db, payload(kev_row(1000, dateAdded='2020-01-01'), *added))
    assert (count, made) == (151, 150)
    assert db.scalar(select(func.count()).select_from(Document)) == 151


def test_new_entries_per_sync_are_capped(db: Session) -> None:
    import_kev(db, payload(kev_row(1000, dateAdded='2020-01-01')))
    flood = [kev_row(50000 + i, dateAdded=f'20{30 + i // 336:02d}-{1 + i // 28 % 12:02d}-{1 + i % 28:02d}')
             for i in range(KEV_NEW_ENTRY_LIMIT + 50)]  # fmt: skip
    _, made = import_kev(db, payload(kev_row(1000, dateAdded='2020-01-01'), *flood))
    assert made == KEV_NEW_ENTRY_LIMIT  # the newest 100 are among the newest 500 new entries
    newest_first = sorted(flood, key=lambda r: r['dateAdded'], reverse=True)
    assert newest_first[0]['cveID'] in titles(db)
    assert newest_first[-1]['cveID'] not in titles(db)


def test_resyncing_never_remakes_reports(db: Session) -> None:
    rows = [kev_row(60000 + i, dateAdded='2026-01-01') for i in range(3)]
    import_kev(db, payload(*rows))
    assert import_kev(db, payload(*rows, kev_row(60010, dateAdded='2018-01-01'))) == (4, 1)
    assert import_kev(db, payload(*rows, kev_row(60010, dateAdded='2018-01-01'))) == (4, 0)


# --------------------------------------------------------------------------- TIP 1.1 fields (for TIP 1.3)


def test_the_weakness_name_ransomware_use_notes_and_cwes_are_kept(db: Session) -> None:
    row = kev_row(
        vulnerabilityName='Fixture Gateway Command Injection',
        knownRansomwareCampaignUse='Known',
        notes='https://vendor.example/advisory',
        cwes=['CWE-78', 'CWE-20', 'CWE-78'],
    )
    import_kev(db, payload(row))
    record = db.get(KEVRecord, 'CVE-2024-12345')
    assert record is not None
    assert (record.vulnerability_name, record.ransomware_use, record.notes) == (
        'Fixture Gateway Command Injection',
        'Known',
        'https://vendor.example/advisory',
    )
    assert record.cwes == 'CWE-78,CWE-20'
    assert record.ransomware
    import_kev(db, payload(kev_row(knownRansomwareCampaignUse='Unknown')))
    updated = db.get(KEVRecord, 'CVE-2024-12345')
    assert updated is not None
    assert not updated.ransomware
    assert (updated.vulnerability_name, updated.cwes) == ('', '')  # what CISA no longer says is not kept


@pytest.mark.parametrize('value', ['known', 'Yes', 'KNOWN', ''])
def test_any_other_ransomware_value_counts_as_not_known(db: Session, value: str) -> None:
    import_kev(db, payload(kev_row(knownRansomwareCampaignUse=value)))
    record = db.get(KEVRecord, 'CVE-2024-12345')
    assert record is not None
    assert (record.ransomware_use, record.ransomware) == ('', False)


@pytest.mark.parametrize(
    'cwes',
    ['CWE-78', ['CWE-78', 7], ['CWE-78; DROP'], ['NVD-CWE-noinfo'], [f'CWE-{n}' for n in range(21)]],
)
def test_invalid_cwes_refuse_the_whole_import(db: Session, cwes: object) -> None:
    with pytest.raises(ValueError, match='Invalid KEV record field'):
        import_kev(db, payload(kev_row(n=11111), kev_row(cwes=cwes)))
    assert db.scalar(select(func.count()).select_from(KEVRecord)) == 0


def test_the_reader_shows_ransomware_use_and_the_weakness_name(db: Session) -> None:
    from insight import services

    import_kev(
        db,
        payload(
            kev_row(knownRansomwareCampaignUse='Known', vulnerabilityName='Fixture Gateway Command Injection')
        ),
    )
    doc = db.scalars(select(Document)).one()
    (observation,) = [o for o in services.detail(db, doc)['observations'] if o['kind'] == 'cve']
    assert observation['kev']['ransomware_use'] == 'Known'
    assert observation['kev']['vulnerability_name'] == 'Fixture Gateway Command Injection'
