"""Threat-research sources: the registry, switching sources on and off, and each publisher's reuse rule."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import connectors, services
from insight.connectors import ALLOWED_HOSTS, SourceSwitchedOff, parse_feed, sync_all, sync_source
from insight.ioc_export import IocMention, build_export
from insight.models import AuditEvent, Schedule, SourceRun
from insight.schemas import DocumentInput, IocExportQuery
from insight.services import SourceRef, ingest
from insight.source_registry import CATEGORIES, METADATA_ONLY, SOURCES, in_use, metadata_only

NOW = datetime(2026, 11, 21, 6, 0, tzinfo=UTC)
RSS = b'<rss><channel><item><title>Ransomware crew returns</title><link>https://example.org/a</link></item></channel></rss>'

#: How the Ghost-run Cisco Talos feed and WordPress feeds (Microsoft, DFIR Report, ESET, Securelist) look:
#: an excerpt in <description>, the whole article in <content:encoded>, which Insight never reads.
WORDPRESS = (
    b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>Research</title>
<item>
  <title><![CDATA[Inside a ransomware intrusion: from phishing to encryption]]></title>
  <link>https://research.example/2026/11/intrusion/</link>
  <guid isPermaLink="false">https://research.example/?p=123</guid>
  <dc:creator><![CDATA[Research team]]></dc:creator>
  <description><![CDATA[<p>An affiliate got in by phishing and ran PowerShell (T1059.001). """
    + b'x' * 600
    + b"""</p>]]></description>
  <content:encoded><![CDATA[<p>FULL ARTICLE TEXT that Insight must not keep.</p>]]></content:encoded>
</item>
</channel></rss>"""
)


def runs(session_factory: sessionmaker[Session]) -> list[str]:
    with session_factory() as db:
        return [r.source_key for r in db.scalars(select(SourceRun))]


def switch(session_factory: sessionmaker[Session], key: str, on: bool) -> None:
    with session_factory.begin() as db:
        services.set_source_switch(db, key, on, at=NOW)


# --------------------------------------------------------------------------- the registry


def test_every_source_is_https_on_an_allowed_host_in_a_known_category() -> None:
    for source in SOURCES.values():
        for url in source.fetch_urls:
            parts = urlsplit(url)
            assert parts.scheme == 'https', url
            assert parts.hostname in ALLOWED_HOSTS, url
        assert source.category in CATEGORIES, source.key


def test_threat_research_and_news_sources_start_off_and_stay_in_insight() -> None:
    optional = {key for key, s in SOURCES.items() if s.optional and s.kind == 'rss'}
    assert optional == {'talos', 'microsoft-ti', 'dfir-report', 'eset', 'securelist', 'the-record'}
    assert all(SOURCES[key].kind == 'rss' and SOURCES[key].reuse == 'metadata' for key in optional)
    assert {key for key, s in SOURCES.items() if s.reuse == 'public'} == {'cisa-kev', 'cisa-csaf'}
    assert set(SOURCES) - {'cisa-kev', 'cisa-csaf'} == METADATA_ONLY
    assert metadata_only('talos')
    assert not metadata_only('cisa-kev')
    assert not metadata_only(None)  # a pasted report is the analyst's own


def test_in_use_follows_the_switch_or_the_default() -> None:
    assert in_use(SOURCES['cisa-kev'], {})
    assert not in_use(SOURCES['talos'], {})
    assert in_use(SOURCES['talos'], {'talos': True})
    assert not in_use(SOURCES['cisa-kev'], {'cisa-kev': False})


def test_a_research_feed_keeps_the_excerpt_and_never_the_article() -> None:
    (item,) = parse_feed(WORDPRESS, SOURCES['dfir-report'])
    assert item.document.title == 'Inside a ransomware intrusion: from phishing to encryption'
    assert item.document.source_name == 'The DFIR Report'
    assert item.document.tlp == 'CLEAR'
    assert 'T1059.001' in item.document.body
    assert 'FULL ARTICLE TEXT' not in item.document.body
    assert item.truncated
    assert item.external_id == 'https://research.example/2026/11/intrusion/'


# --------------------------------------------------------------------------- switches


def test_switching_a_source_off_turns_its_schedule_off_and_is_audited(db: Session) -> None:
    services.set_schedule(db, 'cisa-kev', 1440, at=NOW)
    services.set_source_switch(db, 'cisa-kev', False, at=NOW)
    services.set_source_switch(db, 'talos', True, at=NOW)
    assert services.source_switches(db) == {'cisa-kev': False, 'talos': True}
    schedule = db.get(Schedule, 'cisa-kev')
    assert schedule is not None
    assert not schedule.enabled
    events = db.scalars(select(AuditEvent).where(AuditEvent.action.like('source.%'))).all()
    assert [(e.action, e.object_id) for e in events] == [('source.off', 'cisa-kev'), ('source.on', 'talos')]


async def test_a_source_that_is_off_is_never_contacted(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def fake(url: str, params: Any = None, **_: Any) -> bytes:
        calls.append(url)
        return RSS

    monkeypatch.setattr(connectors, 'download', fake)
    with pytest.raises(SourceSwitchedOff, match='Cisco Talos is switched off'):
        await sync_source(session_factory, 'talos')
    assert calls == []
    assert runs(session_factory) == []  # refusing is not a failed sync
    switch(session_factory, 'talos', True)
    assert await sync_source(session_factory, 'talos') == 'Read 1 feed items; 1 new reports.'
    assert calls == [SOURCES['talos'].url]


async def test_sync_all_covers_the_sources_in_use(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake(url: str, params: Any = None, **_: Any) -> bytes:
        return RSS

    monkeypatch.setattr(connectors, 'download', fake)
    for key, on in (('cisa-kev', False), ('cisa-csaf', False), ('talos', True), ('the-record', True)):
        switch(session_factory, key, on)
    results = await sync_all(session_factory)
    assert [r.key for r in results] == ['sans-isc', 'ncsc', 'talos', 'the-record']


# --------------------------------------------------------------------------- reuse in exports


def test_ioc_export_leaves_out_evidence_from_metadata_only_publishers(db: Session) -> None:
    for key in ('sans-isc', 'cisa-kev'):
        ingest(
            db,
            DocumentInput(
                title=f'{key} item', body='Beacon to 198.51.100.9 seen.', source_name=key, tlp='CLEAR'
            ),
            ref=SourceRef(key, f'{key}-1'),
        )
    ingest(db, DocumentInput(title='Pasted', body='Also 198.51.100.9.', source_name='Partner', tlp='CLEAR'))
    export = services.export_iocs(db, IocExportQuery())
    (ioc,) = export['iocs']
    evidence = {s['source_name']: s['evidence'] for s in ioc['sources']}
    assert evidence['sans-isc'] is None
    assert '198.51.100.9' in evidence['cisa-kev']
    assert '198.51.100.9' in evidence['Partner']


def test_a_metadata_only_mention_has_no_evidence_even_when_evidence_is_on() -> None:
    mention = IocMention(
        'e',
        'ipv4',
        '198.51.100.9',
        'accepted',
        'words',
        'd',
        'T',
        'S',
        '',
        'CLEAR',
        'new',
        '2026',
        True,
        metadata_only=True,
    )
    export = build_export(
        [mention], filters={}, defanged=False, export_id='x', generated_at='2026-11-21T00:00:00+00:00'
    )
    assert export['iocs'][0]['sources'][0]['evidence'] is None
