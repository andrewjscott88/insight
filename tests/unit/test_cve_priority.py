"""TIP 1.3: the prioritised CVE view. Stated rules rank the CVEs (no hidden score), every row says why, and
the rows come only from reports the reader may see."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import services
from insight.brief import DEMO
from insight.cve_priority import TIERS, details, prioritise, rank
from insight.cve_scores import CveScores, EpssScore, NvdScore
from insight.demo import seed
from insight.models import Document, Enrichment, KEVRecord, Observation
from insight.schemas import DocumentInput
from insight.services import BriefKev, CveSignal, SourceRef

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def signal(
    cve: str,
    *,
    kev: BriefKev | None = None,
    cvss: float | None = None,
    csaf: float | None = None,
    epss: float | None = None,
    reports: int = 1,
    last_seen: str = '2026-11-20T00:00:00+00:00',
    status: str = 'Analyzed',
) -> CveSignal:
    nvd = NvdScore(cvss, '', '3.1', '', status, '', '', ()) if cvss is not None else None
    scores = CveScores(
        cve, nvd, EpssScore(epss, 0.9, '') if epss is not None else None, 'x' if nvd else '', ''
    )
    return CveSignal(cve, reports, 1, last_seen, last_seen, 'd1', 'Report', csaf, kev, scores)


def kev(cve: str, ransomware: bool = False) -> BriefKev:
    return BriefKev(cve, 'Acme', 'Gateway', '2026-11-03', '2026-11-24', '', ransomware=ransomware)


# --------------------------------------------------------------------------- the rules


@pytest.mark.parametrize(
    ('found', 'tier'),
    [
        (signal('CVE-1', kev=kev('CVE-1', ransomware=True), cvss=5.0), 1),
        (signal('CVE-2', kev=kev('CVE-2')), 2),
        (signal('CVE-3', epss=0.1, cvss=4.0), 3),
        (signal('CVE-4', cvss=9.0), 4),
        (signal('CVE-5', csaf=9.6, cvss=6.0), 4),  # a CISA advisory's higher score counts
        (signal('CVE-6', cvss=7.0, epss=0.0999), 5),
        (signal('CVE-7', cvss=6.9), 6),
        (signal('CVE-8'), 6),  # not looked up yet
        (signal('CVE-9', cvss=9.8, status='Rejected'), 6),  # NVD rejected it: its score does not count
    ],
)
def test_each_rule_places_a_cve_in_its_group(found: CveSignal, tier: int) -> None:
    assert prioritise(found).tier == tier


def test_within_a_group_epss_then_cvss_then_reports_then_recency_decide() -> None:
    ranked = rank(
        [
            signal('CVE-2026-0005', cvss=9.5),
            signal('CVE-2026-0004', cvss=9.5, reports=3),
            signal('CVE-2026-0003', cvss=9.5, reports=3, last_seen='2026-11-21T00:00:00+00:00'),
            signal('CVE-2026-0002', cvss=9.9),
            signal('CVE-2026-0001', kev=kev('CVE-2026-0001')),
            signal('CVE-2026-0006', epss=0.5),
            signal('CVE-2026-0007', epss=0.9),
        ]
    )
    assert [p.signal.cve for p in ranked] == [
        'CVE-2026-0001',  # known exploited
        'CVE-2026-0007',  # likely: higher EPSS first
        'CVE-2026-0006',
        'CVE-2026-0002',  # critical: higher CVSS first
        'CVE-2026-0003',  # same CVSS: more reports, then seen more recently
        'CVE-2026-0004',
        'CVE-2026-0005',
    ]


def test_each_row_says_why_in_plain_words() -> None:
    item = prioritise(
        signal('CVE-2026-1', kev=kev('CVE-2026-1', ransomware=True), cvss=9.8, csaf=9.1, epss=0.42, reports=3)
    )
    assert (item.label, item.reason) == TIERS[1]
    assert (item.cvss, item.cvss_source) == (9.8, 'NIST NVD')
    assert details(item) == [
        "On CISA's known exploited list since 2026-11-03, used in ransomware campaigns. "
        'US federal agencies must fix it by 2026-11-24.',
        'CVSS 9.8, NIST NVD',
        'CVSS 9.1 in a CISA advisory',
        'EPSS 42% chance of exploitation attempts within 30 days, higher than 90% of CVEs (FIRST)',
        '3 reports from 1 source · last seen 2026-11-20',
    ]
    assert details(prioritise(signal('CVE-2026-2')))[0] == 'Not looked up at NIST NVD or FIRST EPSS yet.'


# --------------------------------------------------------------------------- what the database gives


def add(
    factory: sessionmaker[Session], title: str, body: str, *, tlp: str = 'CLEAR', source: str = 'Partner',
    ref: SourceRef | None = None, days_ago: float = 1,
) -> str:  # fmt: skip
    with factory.begin() as db:
        doc, _ = services.ingest(
            db, DocumentInput(title=title, body=body, source_name=source, tlp=tlp), ref=ref
        )
        doc.created_at = (NOW - timedelta(days=days_ago)).isoformat()
        return doc.id


def signals(factory: sessionmaker[Session], **options: object) -> dict[str, CveSignal]:
    with factory() as db:
        found = services.cve_signals(db, since=(NOW - timedelta(days=30)).isoformat(), **options)  # type: ignore[arg-type]
    return {s.cve: s for s in found.signals}


def test_signals_count_reports_and_sources_and_keep_the_newest_report(
    session_factory: sessionmaker[Session],
) -> None:
    add(session_factory, 'Old note', 'CVE-2026-1111 seen', days_ago=5)
    newest = add(session_factory, 'New note', 'CVE-2026-1111 again', source='Other', days_ago=1)
    add(session_factory, 'Too old', 'CVE-2026-2222', days_ago=45)
    found = signals(session_factory)
    assert set(found) == {'CVE-2026-1111'}
    one = found['CVE-2026-1111']
    assert (one.reports, one.sources, one.report_id, one.report_title) == (2, 2, newest, 'New note')
    assert one.first_seen < one.last_seen
    assert (one.kev, one.csaf_score, one.scores.checked) == (None, None, False)


def test_signals_follow_the_readers_tlp_limit_and_leave_out_rejected_mentions_and_the_demo(
    session_factory: sessionmaker[Session],
) -> None:
    add(session_factory, 'Public', 'CVE-2026-1111', tlp='GREEN')
    add(session_factory, 'Partner only', 'CVE-2026-2222 and CVE-2026-1111', tlp='AMBER')
    rejected = add(session_factory, 'Mistake', 'CVE-2026-3333')
    with session_factory.begin() as db:
        for obs in db.scalars(select(Observation).where(Observation.document_id == rejected)):
            obs.review_status = 'rejected'
        seed(db)
        for demo in db.scalars(select(Document).where(Document.source_name.in_([s for _, s in DEMO]))):
            demo.created_at = NOW.isoformat()
    limited = signals(session_factory, max_tlp='GREEN', ignore=DEMO)
    assert set(limited) == {'CVE-2026-1111'}
    assert limited['CVE-2026-1111'].reports == 1  # the AMBER report is not counted for a GREEN reader
    assert set(signals(session_factory, ignore=DEMO)) == {'CVE-2026-1111', 'CVE-2026-2222'}
    assert 'CVE-2024-3400' in signals(session_factory)  # the demo's CVE, when not left out


def test_signals_read_csaf_scores_kev_entries_and_cached_scores(
    session_factory: sessionmaker[Session],
) -> None:
    body = 'Advisory.\n- CVE-2026-1111, CVSS 3.1 base score 9.4: Command injection.\n'
    add(session_factory, 'ICSA-26-1 · Acme', body, source='CISA', ref=SourceRef('cisa-csaf', 'icsa-26-1'))
    add(
        session_factory, 'KEV', 'CVE-2026-1111', source='CISA KEV', ref=SourceRef('cisa-kev', 'CVE-2026-1111')
    )
    with session_factory.begin() as db:
        db.add(
            KEVRecord(
                cve='CVE-2026-1111', vendor='Acme', product='Gateway', date_added='2026-11-10',
                due_date='2026-12-01', required_action='Patch', ransomware_use='Known',
                vulnerability_name='Acme Gateway Command Injection',
            )
        )  # fmt: skip
        epss = {'data': [{'cve': 'CVE-2026-1111', 'epss': '0.6', 'percentile': '0.99'}]}
        db.add(Enrichment(cve='CVE-2026-1111', provider='epss', payload=json.dumps(epss)))
    one = signals(session_factory)['CVE-2026-1111']
    assert one.csaf_score == 9.4
    assert one.kev is not None
    assert (one.kev.ransomware, one.kev.name, bool(one.kev.document_id)) == (
        True,
        'Acme Gateway Command Injection',
        True,
    )
    assert one.scores.epss is not None
    assert prioritise(one).tier == 1


def test_the_mention_limit_is_reported(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr('insight.services.cves.MAX_CVE_MENTIONS', 2)
    add(session_factory, 'Many', 'CVE-2026-0001 CVE-2026-0002 CVE-2026-0003')
    with session_factory() as db:
        found = services.cve_signals(db, since=(NOW - timedelta(days=30)).isoformat())
    assert found.truncated
    assert len(found.signals) == 2
