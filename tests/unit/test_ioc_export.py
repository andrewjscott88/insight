"""Cross-report IOC export: format, defanging, filters, TLP labels, auditing and ``insight export-iocs``."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import cli, services
from insight.extraction import canonical, extract
from insight.ioc_export import (
    FORMAT,
    IocMention,
    build_export,
    defang,
    defang_excerpt,
    defang_text,
    export_filename,
    most_restrictive_label,
)
from insight.migrations import upgrade
from insight.models import AuditEvent, Document, KEVRecord, Observation, database
from insight.schemas import INDICATOR_KINDS, DocumentInput, IocExportQuery, validation_message
from insight.services import SourceRef, export_iocs, ingest

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / 'docs' / 'schemas' / 'insight-ioc-v1.schema.json').read_text(
        'utf-8'
    )
)
A_BODY = 'Beacon to evil.example and 192.0.2.8. Exploits CVE-2024-12345.'
B_BODY = 'Second sighting of evil.example at 192.0.2.8, then evil.example again.'
Reports = tuple[Document, Document]


def item(**changes: Any) -> DocumentInput:
    base: dict[str, Any] = {'title': 'T', 'body': A_BODY, 'source_name': 'S', 'tlp': 'CLEAR'}
    return DocumentInput(**{**base, **changes})


def query(**changes: Any) -> IocExportQuery:
    return IocExportQuery.model_validate(changes)


def by_key(export: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(ioc['kind'], ioc['value']): ioc for ioc in export['iocs']}


@pytest.fixture
def two_reports(db: Session) -> Reports:
    """Report A (CLEAR, older) and B (AMBER, newer) share a domain and an IP; only A mentions the CVE."""
    a, _ = ingest(db, item(title='Report A'))
    b, _ = ingest(db, item(title='Report B', body=B_BODY, tlp='AMBER'))
    # Fixed timestamps: two ingests can share a clock tick on some platforms.
    a.created_at, b.created_at = '2026-01-01T00:00:00+00:00', '2026-01-02T00:00:00+00:00'
    db.flush()
    return a, b


def observation_ids(db: Session, doc: Document, value: str) -> list[str]:
    return [o['id'] for o in services.detail(db, doc)['observations'] if o['value'] == value]


# --------------------------------------------------------------------------- defanging (pure)


@pytest.mark.parametrize(
    ('kind', 'value', 'expected'),
    [
        ('url', 'https://evil.example/a.php', 'hxxps://evil[.]example/a[.]php'),
        ('url', 'http://192.0.2.8:8080/x', 'hxxp://192[.]0[.]2[.]8:8080/x'),
        ('domain', 'files.example.net', 'files[.]example[.]net'),
        ('ip', '203.0.113.9', '203[.]0[.]113[.]9'),
        ('ip', '2001:db8::1', '2001[:]db8[:][:]1'),
        ('cve', 'CVE-2024-12345', 'CVE-2024-12345'),
        ('sha256', 'a' * 64, 'a' * 64),
    ],
)
def test_defang(kind: str, value: str, expected: str) -> None:
    assert defang(kind, value) == expected


@pytest.mark.parametrize(
    ('kind', 'value'),
    [
        ('url', 'https://evil.example/a.php'),
        ('url', 'http://192.0.2.8:8080/x'),
        ('domain', 'files.example.net'),
        ('ip', '203.0.113.9'),
        ('ip', '2001:db8::1'),
    ],
)
def test_defanged_values_refang_to_the_original(kind: str, value: str) -> None:
    """A defanged export re-imported into Insight (or any refanging tool) yields the same indicators."""
    defanged = defang(kind, value)
    assert canonical(kind, defanged) == value
    assert (kind, value) in {(m.kind, m.value) for m in extract(f'Seen {defanged} today.')}


@given(st.ip_addresses())
def test_every_ip_address_survives_defanging(address: Any) -> None:
    value = str(address)
    assert canonical('ip', defang('ip', value)) == canonical('ip', value)


def test_defang_text_neutralises_every_network_indicator() -> None:
    text = 'C2 https://evil.example/x, fallback files.example.net and 203.0.113.9'
    assert defang_text(text) == (
        'C2 hxxps://evil[.]example/x, fallback files[.]example[.]net and 203[.]0[.]113[.]9'
    )


def test_defang_text_keeps_already_defanged_text_and_plain_prose() -> None:
    text = 'seen at hxxp://bad[.]example/p and evil[.]example; CVE-2024-12345 is unrelated.'
    assert defang_text(text) == text


def test_defang_text_catches_a_url_cut_off_at_the_excerpt_edge() -> None:
    assert defang_text('link: http://') == 'link: hxxp://'


# --------------------------------------------------------------------------- formatting (pure)


def test_most_restrictive_label_fails_safe() -> None:
    assert most_restrictive_label(['GREEN', 'AMBER+STRICT', 'AMBER']) == 'AMBER+STRICT'
    assert most_restrictive_label(['CLEAR', 'UNKNOWN']) == 'UNKNOWN'  # unknown labels win
    assert most_restrictive_label([]) == 'AMBER'  # an empty export is never labelled CLEAR


def test_export_filename_is_a_compact_utc_timestamp() -> None:
    assert export_filename('2026-11-13T10:15:00.123456+00:00') == 'insight-iocs-20261113T101500Z.json'


def mention(**changes: Any) -> IocMention:
    base: dict[str, Any] = {
        'entity_id': 'e1',
        'kind': 'domain',
        'value': 'evil.example',
        'review_status': 'unreviewed',
        'evidence': 'first evil.example',
        'document_id': 'd1',
        'title': 'Report',
        'source_name': 'S',
        'source_url': '',
        'tlp': 'GREEN',
        'status': 'new',
        'created_at': '2026-01-01T00:00:00+00:00',
        'is_current': True,
    }
    return IocMention(**{**base, **changes})


def test_build_export_groups_mentions_per_indicator_and_report() -> None:
    mentions = [
        mention(),
        mention(evidence='second evil.example', review_status='accepted'),
        mention(document_id='d2', tlp='RED', created_at='2026-02-01T00:00:00+00:00'),
        mention(entity_id='e2', kind='cve', value='CVE-2024-12345', evidence='CVE-2024-12345'),
    ]
    export = build_export(mentions, filters={'x': 1}, defanged=False, export_id='id', generated_at='now')
    assert export['format'] == FORMAT
    assert (export['export_id'], export['generated_at'], export['filters']) == ('id', 'now', {'x': 1})
    assert export['tlp'] == 'RED'
    assert export['counts'] == {'iocs': 2, 'documents': 2, 'mentions': 4, 'by_kind': {'cve': 1, 'domain': 1}}
    cve, domain = export['iocs']  # sorted by kind, then value
    assert cve['kind'] == 'cve'
    assert domain['tlp'] == 'RED'
    assert domain['review_statuses'] == {'unreviewed': 2, 'accepted': 1}
    assert (domain['first_ingested_at'], domain['last_ingested_at']) == (
        '2026-01-01T00:00:00+00:00',
        '2026-02-01T00:00:00+00:00',
    )
    first, second = domain['sources']
    assert (first['document_id'], first['mentions'], first['evidence']) == ('d1', 2, 'first evil.example')
    assert (second['document_id'], second['mentions']) == ('d2', 1)


def test_build_export_defangs_values_and_evidence_but_not_provenance() -> None:
    export = build_export(
        [mention(source_url='https://publisher.example/report')],
        filters={},
        defanged=True,
        export_id='id',
        generated_at='now',
    )
    (ioc,) = export['iocs']
    assert export['defanged'] is True
    assert ioc['value'] == 'evil[.]example'
    assert ioc['sources'][0]['evidence'] == 'first evil[.]example'
    assert ioc['sources'][0]['source_url'] == 'https://publisher.example/report'


# --------------------------------------------------------------------------- query validation


def test_query_defaults_leave_out_rejected_mentions() -> None:
    q = IocExportQuery()
    assert q.kinds == INDICATOR_KINDS
    assert q.review_statuses == ('unreviewed', 'accepted')
    assert (q.max_tlp, q.defang, q.include_superseded) == (None, False, False)


def test_query_normalises_repeated_and_reordered_filters() -> None:
    q = query(kinds=['ip', 'cve', 'ip'], review_statuses=['accepted', 'unreviewed', 'accepted'])
    assert q.kinds == ('cve', 'ip')
    assert q.review_statuses == IocExportQuery().review_statuses


@pytest.mark.parametrize(
    'changes',
    [
        {'kinds': ['bogus']},
        {'kinds': []},
        {'review_statuses': []},
        {'review_statuses': ['maybe']},
        {'max_tlp': 'WHITE'},
        {'tlp': 'amber'},
        {'status': 'done'},
        {'q': 'x' * 201},
        {'unexpected': True},
    ],
)
def test_query_rejects_invalid_filters(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as exc:
        query(**changes)
    assert validation_message(exc.value)


# --------------------------------------------------------------------------- service


def test_export_deduplicates_across_reports_and_raises_tlp(db: Session, two_reports: Reports) -> None:
    a, b = two_reports
    export = export_iocs(db, IocExportQuery())
    iocs = by_key(export)
    assert list(iocs) == [('cve', 'CVE-2024-12345'), ('domain', 'evil.example'), ('ip', '192.0.2.8')]
    assert export['tlp'] == 'AMBER'
    assert export['counts'] == {
        'iocs': 3,
        'documents': 2,
        'mentions': 6,
        'by_kind': {'cve': 1, 'domain': 1, 'ip': 1},
    }
    domain = iocs[('domain', 'evil.example')]
    assert domain['tlp'] == 'AMBER'
    assert [(s['document_id'], s['mentions'], s['tlp']) for s in domain['sources']] == [
        (a.id, 1, 'CLEAR'),
        (b.id, 2, 'AMBER'),
    ]
    assert all('evil.example' in s['evidence'] for s in domain['sources'])
    assert domain['review_statuses'] == {'unreviewed': 3}
    assert (domain['first_ingested_at'], domain['last_ingested_at']) == (a.created_at, b.created_at)
    assert iocs[('cve', 'CVE-2024-12345')]['tlp'] == 'CLEAR'


def test_export_echoes_filters_and_handling_notice(db: Session, two_reports: Reports) -> None:
    export = export_iocs(db, IocExportQuery())
    assert export['format'] == 'insight-ioc-v1'
    assert 'Not STIX' in export['handling_notice']
    assert export['defanged'] is False
    assert export['filters'] == {
        'q': '',
        'status': None,
        'tlp': None,
        'include_superseded': False,
        'kinds': list(INDICATOR_KINDS),
        'review_statuses': ['unreviewed', 'accepted'],
        'max_tlp': None,
        'document_ids': [],
        'include_evidence': True,
        'verdicts': ['unknown', 'benign', 'suspicious', 'malicious'],
        'exclude_flags': [],
    }


def test_rejected_mentions_are_left_out_by_default(db: Session, two_reports: Reports) -> None:
    a, _ = two_reports
    for obs_id in observation_ids(db, a, 'CVE-2024-12345'):
        services.set_observation_status(db, obs_id, 'rejected')
    assert ('cve', 'CVE-2024-12345') not in by_key(export_iocs(db, IocExportQuery()))
    rejected = export_iocs(db, query(review_statuses=['rejected']))
    assert list(by_key(rejected)) == [('cve', 'CVE-2024-12345')]


def test_accepted_only_export(db: Session, two_reports: Reports) -> None:
    a, _ = two_reports
    for obs_id in observation_ids(db, a, 'evil.example'):
        services.set_observation_status(db, obs_id, 'accepted')
    export = export_iocs(db, query(review_statuses=['accepted']))
    (ioc,) = export['iocs']
    assert (ioc['value'], ioc['review_statuses'], len(ioc['sources'])) == ('evil.example', {'accepted': 1}, 1)
    assert export['tlp'] == 'CLEAR'  # only report A contributed


def test_kind_filter(db: Session, two_reports: Reports) -> None:
    assert list(by_key(export_iocs(db, query(kinds=['ip'])))) == [('ip', '192.0.2.8')]


def test_max_tlp_leaves_out_more_restricted_reports(db: Session, two_reports: Reports) -> None:
    a, _ = two_reports
    export = export_iocs(db, query(max_tlp='GREEN'))
    assert export['tlp'] == 'CLEAR'
    assert export['counts']['documents'] == 1
    assert {s['document_id'] for ioc in export['iocs'] for s in ioc['sources']} == {a.id}


def test_report_filters_match_the_inbox_search(db: Session, two_reports: Reports) -> None:
    _, b = two_reports
    services.set_document_status(db, b.id, 'reviewed')
    for changes in ({'q': 'SECOND SIGHTING'}, {'status': 'reviewed'}, {'tlp': 'AMBER'}):
        export = export_iocs(db, query(**changes))
        assert {s['document_id'] for ioc in export['iocs'] for s in ioc['sources']} == {b.id}, changes


def test_superseded_revisions_only_on_request(db: Session) -> None:
    ref = SourceRef('cisa-kev', 'CVE-2024-11111')
    old, _ = ingest(db, item(body='CVE-2024-11111 affects the gateway.'), ref=ref)
    ingest(db, item(body='CVE-2024-11111 affects the gateway. See CVE-2024-22222.'), ref=ref)
    current = by_key(export_iocs(db, IocExportQuery()))
    assert len(current[('cve', 'CVE-2024-11111')]['sources']) == 1
    everything = by_key(export_iocs(db, query(include_superseded=True)))
    sources = everything[('cve', 'CVE-2024-11111')]['sources']
    assert len(sources) == 2
    assert {s['is_current'] for s in sources if s['document_id'] == old.id} == {False}


def test_cves_carry_kev_context(db: Session, two_reports: Reports) -> None:
    db.add(
        KEVRecord(
            cve='CVE-2024-12345',
            vendor='Acme',
            product='Gateway',
            date_added='2024-01-02',
            due_date='2024-01-23',
            required_action='Apply updates.',
        )
    )
    db.flush()
    iocs = by_key(export_iocs(db, IocExportQuery()))
    kev = iocs[('cve', 'CVE-2024-12345')]['kev']
    assert kev is not None
    assert (kev['vendor'], kev['product'], kev['due_date']) == ('Acme', 'Gateway', '2024-01-23')
    assert iocs[('ip', '192.0.2.8')]['kev'] is None


def test_defanged_export_contains_no_live_network_indicators(db: Session) -> None:
    ingest(db, item(body='Payload at https://evil.example/a.php from 192.0.2.8.'))
    export = export_iocs(db, query(defang=True))
    iocs = by_key(export)
    assert ('url', 'hxxps://evil[.]example/a[.]php') in iocs
    assert ('domain', 'evil[.]example') in iocs
    assert ('ip', '192[.]0[.]2[.]8') in iocs
    serialised = json.dumps(export['iocs'])
    for live in ('https://', 'evil.example', '192.0.2.8'):
        assert live not in serialised


def test_export_is_audited_with_its_export_id(db: Session, two_reports: Reports) -> None:
    export = export_iocs(db, query(kinds=['ip'], defang=True))
    event = db.scalar(select(AuditEvent).where(AuditEvent.action == 'ioc.export'))
    assert event is not None
    assert event.object_id == export['export_id']
    detail = json.loads(event.detail)
    assert detail == {
        'iocs': 1,
        'documents': 2,
        'tlp': 'AMBER',
        'defanged': True,
        'filters': export['filters'],
    }


def test_empty_workspace_exports_an_empty_amber_file(db: Session) -> None:
    export = export_iocs(db, IocExportQuery())
    assert export['iocs'] == []
    assert export['tlp'] == 'AMBER'
    assert export['counts'] == {'iocs': 0, 'documents': 0, 'mentions': 0, 'by_kind': {}}


def test_export_size_is_bounded(db: Session, two_reports: Reports, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(services.exports, 'MAX_EXPORT_MENTIONS', 5)  # the two reports hold 6 mentions
    with pytest.raises(ValueError, match='narrow the filters'):
        export_iocs(db, IocExportQuery())


def test_inbox_search_is_unchanged_by_the_shared_filters(db: Session, two_reports: Reports) -> None:
    """The inbox search now shares its report filters with the export; its results must not change."""
    a, b = two_reports
    services.set_document_status(db, a.id, 'reviewed')
    search = services.search_documents
    assert [d.id for d in search(db, services.DocumentQuery())] == [b.id, a.id]
    assert [d.id for d in search(db, services.DocumentQuery(q='second sighting'))] == [b.id]
    assert [d.id for d in search(db, services.DocumentQuery(status='reviewed'))] == [a.id]
    assert [d.id for d in search(db, services.DocumentQuery(tlp='AMBER'))] == [b.id]


# --------------------------------------------------------------------------- insight export-iocs


@pytest.fixture
def workspace_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A migrated SQLite workspace with one GREEN report, selected through the environment like the CLI."""
    monkeypatch.chdir(tmp_path)
    url = f'sqlite:///{tmp_path / "insight.db"}'
    engine, factory = database(url)
    with factory.begin() as db:
        ingest(db, item(tlp='GREEN'))
    engine.dispose()
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATABASE_URL': url})
    return url


def audit_actions(url: str) -> list[tuple[str, str]]:
    engine, factory = database(url)
    try:
        with factory() as db:
            return [(e.action, e.object_id) for e in db.scalars(select(AuditEvent))]
    finally:
        engine.dispose()


def test_cli_writes_a_private_filtered_export(
    workspace_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / 'iocs.json'
    argv = ['export-iocs', str(target), '--kind', 'DOMAIN', '--kind', 'ip', '--max-tlp', 'green', '--defang']
    assert cli.main(argv) == 0
    exported = json.loads(target.read_text(encoding='utf-8'))
    assert exported['format'] == 'insight-ioc-v1'
    assert exported['tlp'] == 'GREEN'
    assert exported['defanged'] is True
    assert exported['filters']['kinds'] == ['ip', 'domain']
    assert exported['filters']['max_tlp'] == 'GREEN'
    assert {(i['kind'], i['value']) for i in exported['iocs']} == {
        ('domain', 'evil[.]example'),
        ('ip', '192[.]0[.]2[.]8'),
    }
    out = capsys.readouterr().out
    assert 'Exported 2 IOCs' in out
    assert 'TLP:GREEN, defanged' in out
    if sys.platform != 'win32':
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert ('ioc.export', exported['export_id']) in audit_actions(workspace_url)


def test_cli_never_overwrites(workspace_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / 'iocs.json'
    target.write_text('keep me')
    assert cli.main(['export-iocs', str(target)]) == 1
    assert target.read_text() == 'keep me'
    assert 'Export failed' in capsys.readouterr().err


def test_cli_requires_a_destination() -> None:
    assert cli.main(['export-iocs']) == 2


def test_cli_rejects_invalid_filters_before_creating_a_file(
    workspace_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / 'iocs.json'
    assert cli.main(['export-iocs', str(target), '--kind', 'bogus']) == 1
    assert not target.exists()
    err = capsys.readouterr().err
    assert "--kind 'bogus': Input should be 'cve'" in err  # named as typed, with the bad value
    assert 'at least 1 item' not in err  # pydantic's follow-on error is dropped


def test_cli_refuses_a_missing_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / 'missing.db'
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATABASE_URL': f'sqlite:///{missing}'})
    assert cli.main(['export-iocs', str(tmp_path / 'iocs.json')]) == 1
    assert not missing.exists()  # no empty database is created as a side effect
    assert 'No database' in capsys.readouterr().err


def test_cli_requires_a_current_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    url = f'sqlite:///{tmp_path / "old.db"}'
    engine, _ = database(url, migrate=False)
    upgrade(engine, '0002')
    engine.dispose()
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATABASE_URL': url})
    target = tmp_path / 'iocs.json'
    assert cli.main(['export-iocs', str(target)]) == 1
    assert not target.exists()
    assert 'insight migrate' in capsys.readouterr().err


def test_cli_removes_the_file_and_audits_nothing_when_the_export_fails(
    workspace_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(services.exports, 'MAX_EXPORT_MENTIONS', 0)
    target = tmp_path / 'iocs.json'
    assert cli.main(['export-iocs', str(target)]) == 1
    assert not target.exists()
    assert all(action != 'ioc.export' for action, _ in audit_actions(workspace_url))


def test_observation_model_is_untouched_by_exports(db: Session, two_reports: Reports) -> None:
    """Exports read review state; they never change it."""
    before = [(o.id, o.review_status) for o in db.scalars(select(Observation).order_by(Observation.id))]
    export_iocs(db, IocExportQuery())
    after = [(o.id, o.review_status) for o in db.scalars(select(Observation).order_by(Observation.id))]
    assert before == after


# --------------------------------------------------------------------------- defanging skipped text


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('mail from billing@invoices.example.net today', 'mail from billing@invoices[.]example[.]net today'),
        ('subnet 203.0.113.0/24 scanned', 'subnet 203[.]0[.]113[.]0/24 scanned'),
        ('range 2001:db8::/32 advertised', 'range 2001[:]db8[:][:]/32 advertised'),
        ('fetched update.zip and setup.py', 'fetched update[.]zip and setup[.]py'),
        # Not network indicators: left as written.
        (
            'firmware 10.2.9.1 runs svchost.exe via Net.WebClient',
            'firmware 10.2.9.1 runs svchost.exe via Net.WebClient',
        ),
    ],
)
def test_defang_text_covers_network_text_the_extractor_skips(text: str, expected: str) -> None:
    """Regression: e-mail domains, CIDR ranges and file-like names stayed live in defanged evidence
    (found by exporting the GLASS HARBOR and SALT MERIDIAN reports)."""
    assert defang_text(text) == expected
    assert defang_text(expected) == expected  # idempotent


def test_defang_excerpt_handles_indicators_cut_at_the_edges() -> None:
    """Regression: an excerpt that starts or ends inside a URL or name kept its dots live."""
    excerpt = 'ttps://mail-relay.example.org/owa/auth/logon.aspx?url=/ews | credential | Domain | exfil.examp'
    assert defang_excerpt(excerpt) == (
        'ttps://mail-relay[.]example[.]org/owa/auth/logon[.]aspx?url=/ews'
        ' | credential | Domain | exfil[.]examp'
    )


def test_defanged_export_defangs_titles_but_keeps_source_urls(db: Session) -> None:
    ingest(
        db,
        item(
            title='Phishing from evil.example',
            body='Payload at https://evil.example/a.php.',
            source_url='https://publisher.example.com/post',
        ),
    )
    (source,) = {
        s['document_id']: s for ioc in export_iocs(db, query(defang=True))['iocs'] for s in ioc['sources']
    }.values()
    assert source['title'] == 'Phishing from evil[.]example'
    assert source['source_url'] == 'https://publisher.example.com/post'  # the publisher link stays usable


# --------------------------------------------------------------------------- document filter and counts


def test_document_filter_exports_only_the_chosen_reports(db: Session, two_reports: Reports) -> None:
    a, b = two_reports
    export = export_iocs(db, query(document_ids=[b.id]))
    assert {s['document_id'] for ioc in export['iocs'] for s in ioc['sources']} == {b.id}
    assert export['filters']['document_ids'] == [b.id]
    both = export_iocs(db, query(document_ids=[b.id, a.id, b.id]))  # repeated and reordered
    assert both['filters']['document_ids'] == sorted([a.id, b.id])
    assert export_iocs(db, query(document_ids=['no-such-report']))['iocs'] == []


def test_an_explicitly_chosen_superseded_revision_is_included(db: Session) -> None:
    ref = SourceRef('cisa-kev', 'CVE-2024-11111')
    old, _ = ingest(db, item(body='CVE-2024-11111 affects the gateway.'), ref=ref)
    ingest(db, item(body='CVE-2024-11111 affects the gateway. See CVE-2024-22222.'), ref=ref)
    (source,) = export_iocs(db, query(document_ids=[old.id]))['iocs'][0]['sources']
    assert (source['document_id'], source['is_current']) == (old.id, False)


def test_sources_record_their_extractor_version(db: Session, two_reports: Reports) -> None:
    versions = {
        s['extractor_version'] for ioc in export_iocs(db, IocExportQuery())['iocs'] for s in ioc['sources']
    }
    assert versions == {'regex-v2'}


@pytest.mark.parametrize(
    'changes',
    [
        {},
        {'kinds': ['ip']},
        {'review_statuses': ['rejected']},
        {'max_tlp': 'CLEAR'},
        {'q': 'second sighting'},
    ],
)
def test_preview_counts_match_the_export(db: Session, two_reports: Reports, changes: dict[str, Any]) -> None:
    counts = services.ioc_export_counts(db, query(**changes))
    exported = export_iocs(db, query(**changes))['counts']
    assert counts == {k: exported[k] for k in ('iocs', 'documents', 'mentions')}


def test_preview_counts_are_not_audited(db: Session, two_reports: Reports) -> None:
    services.ioc_export_counts(db, IocExportQuery())
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == 'ioc.export')) is None


def test_exports_without_evidence_for_sharing(db: Session, two_reports: Reports) -> None:
    """Regression: a rejected victim address still reached recipients inside a neighbouring excerpt
    (found with the GLASS HARBOR report); sharing needs a way to leave excerpts out."""
    export = export_iocs(db, query(include_evidence=False))
    assert export['filters']['include_evidence'] is False
    assert {s['evidence'] for ioc in export['iocs'] for s in ioc['sources']} == {None}
    assert {s['title'] for ioc in export['iocs'] for s in ioc['sources']} == {'Report A', 'Report B'}
    jsonschema.validate(json.loads(json.dumps(export)), SCHEMA)


# --------------------------------------------------------------------------- error messages


def test_validation_messages_use_the_callers_names() -> None:
    with pytest.raises(ValidationError) as exc:
        query(kinds=['ipv4'], max_tlp='WHITE')
    message = validation_message(exc.value, {'kinds': '--kind', 'max_tlp': '--max-tlp'})
    assert message.startswith("--kind 'ipv4': Input should be 'cve'")
    assert "--max-tlp: Input should be 'CLEAR'" in message
    assert 'at least 1 item' not in message
    with pytest.raises(ValidationError) as empty:
        query(kinds=[])
    assert 'at least 1 item' in validation_message(empty.value)  # a genuinely empty list is still reported


# --------------------------------------------------------------------------- JSON Schema


@pytest.mark.parametrize(
    'changes',
    [{}, {'defang': True}, {'q': 'nothing matches this'}, {'include_superseded': True}, {'max_tlp': 'CLEAR'}],
)
def test_exports_match_the_published_schema(
    db: Session, two_reports: Reports, changes: dict[str, Any]
) -> None:
    jsonschema.validate(json.loads(json.dumps(export_iocs(db, query(**changes)))), SCHEMA)


def test_the_schema_documents_every_exported_field(db: Session, two_reports: Reports) -> None:
    """With additionalProperties forbidden everywhere, a real export must still validate."""

    def closed(node: Any) -> Any:
        if isinstance(node, dict):
            node = {key: closed(value) for key, value in node.items()}
            if node.get('type') == 'object' and 'properties' in node:
                node['additionalProperties'] = False
            return node
        return [closed(value) for value in node] if isinstance(node, list) else node

    jsonschema.validate(json.loads(json.dumps(export_iocs(db, IocExportQuery()))), closed(SCHEMA))


def test_the_schema_rejects_malformed_exports(db: Session, two_reports: Reports) -> None:
    export = json.loads(json.dumps(export_iocs(db, IocExportQuery())))
    export['iocs'][0]['sources'][0]['status'] = 'accepted'  # a review state where the triage status belongs
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(export, SCHEMA)


# --------------------------------------------------------------------------- CLI options and messages


def test_cli_exports_one_report(workspace_url: str, tmp_path: Path) -> None:
    engine, factory = database(workspace_url)
    with factory() as db:
        doc_id = services.search_documents(db, services.DocumentQuery())[0].id
    engine.dispose()
    target = tmp_path / 'one.json'
    assert cli.main(['export-iocs', str(target), '--document', doc_id]) == 0
    exported = json.loads(target.read_text(encoding='utf-8'))
    assert exported['filters']['document_ids'] == [doc_id]
    assert {s['document_id'] for ioc in exported['iocs'] for s in ioc['sources']} == {doc_id}


def test_cli_explains_an_existing_file(
    workspace_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / 'iocs.json'
    target.write_text('keep me')
    assert cli.main(['export-iocs', str(target)]) == 1
    assert 'already exists; exports never overwrite, choose a new name' in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == 'win32' or os.geteuid() == 0, reason='needs POSIX permissions, non-root')
def test_cli_reports_an_unwritable_directory_without_a_traceback(
    workspace_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regression: a read-only or unwritable destination crashed with a PermissionError traceback."""
    locked = tmp_path / 'locked'
    locked.mkdir(mode=0o555)
    try:
        assert cli.main(['export-iocs', str(locked / 'iocs.json')]) == 1
    finally:
        locked.chmod(0o755)
    err = capsys.readouterr().err
    assert 'Export failed: cannot create' in err
    assert 'in Docker: /data' in err
    assert 'Traceback' not in err


def test_cli_help_lists_values_and_examples(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(['--help'])
    out = ' '.join(capsys.readouterr().out.split())  # argparse wraps to the terminal width
    assert '--status TRIAGE' in out  # the report's triage status ...
    assert '--review-status REVIEW' in out  # ... is not the review state of a mention
    assert 'CLEAR GREEN AMBER AMBER+STRICT RED' in out
    assert 'export-iocs examples:' in out
    assert '--document ID' in out


def test_cli_no_evidence(workspace_url: str, tmp_path: Path) -> None:
    target = tmp_path / 'share.json'
    assert cli.main(['export-iocs', str(target), '--no-evidence', '--defang']) == 0
    exported = json.loads(target.read_text(encoding='utf-8'))
    assert exported['filters']['include_evidence'] is False
    assert {s['evidence'] for ioc in exported['iocs'] for s in ioc['sources']} == {None}


def test_cli_explains_an_empty_export(
    workspace_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(['export-iocs', str(tmp_path / 'none.json'), '--review-status', 'accepted']) == 0
    out = capsys.readouterr().out
    assert 'Exported 0 IOCs (0 mentions) from 0 reports' in out
    assert 'Nothing matched the filters' in out


def test_cli_summary_uses_singular_and_plural() -> None:
    result = {'counts': {'iocs': 1, 'mentions': 2, 'documents': 1}, 'defanged': True, 'tlp': 'GREEN'}
    assert cli.export_summary(result, Path('x.json')).startswith(
        'Exported 1 IOC (2 mentions) from 1 report to x.json (TLP:GREEN, defanged).'
    )


def test_cli_write_failure_leaves_no_file_and_no_audit(
    workspace_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def disk_full(*_args: Any, **_kwargs: Any) -> None:
        raise OSError(28, 'No space left on device')

    monkeypatch.setattr(json, 'dump', disk_full)
    target = tmp_path / 'iocs.json'
    assert cli.main(['export-iocs', str(target)]) == 1
    err = capsys.readouterr().err
    assert 'Export failed: could not write' in err
    assert 'No space left on device' in err
    assert not target.exists()
    assert all(action != 'ioc.export' for action, _ in audit_actions(workspace_url))
