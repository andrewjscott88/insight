"""Executive claims stay tied to stored evidence, scoped dates, and visible reports."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session, sessionmaker

from insight import services
from insight.brief import compose, window_start
from insight.models import SourceRun
from insight.schemas import DocumentInput
from insight.services import BriefData, BriefDocument, BriefKev

NOW = datetime(2026, 11, 19, 12, tzinfo=UTC)


def document(n: int, *, hours: float = 2, source: str = 'Partner', body: str = '') -> BriefDocument:
    return BriefDocument(
        str(n), f'Report {n}', source, None, (NOW - timedelta(hours=hours)).isoformat(), '', body
    )


def data(*docs: BriefDocument, **kwargs: object) -> BriefData:
    values = {'since': window_start(NOW), 'documents': list(docs), 'mentions': [], 'kev': {}, 'watch': {}}
    return BriefData(**(values | kwargs))  # type: ignore[arg-type]


def test_receipt_count_uses_an_exact_clock_and_normalized_source_identity() -> None:
    """Regression: retain API receipt metadata without recreating a last-24-hours highlight."""
    items = [document(1), document(2, hours=24, source=' PARTNER '), document(3, hours=24.001)]
    items += [replace(document(4), created_at='2026-11-20T00:00:00+12:00')]
    result = compose(data(*items))
    assert (result.as_of, result.report_count, result.recent_reports, result.source_count) == (
        NOW.isoformat(),
        4,
        3,
        1,
    )
    assert result.highlights == ()
    assert not any('24-hour count' in note for note in result.coverage)


def test_bad_future_and_old_dates_cannot_become_current_news() -> None:
    docs = [
        document(1),
        document(2, hours=-1),
        replace(document(3), created_at='not a timestamp'),
        replace(document(4), published='2026-13-01'),
        replace(document(5), published='2026-11-20'),
        document(6, body='Released not-a-date.'),
        replace(document(7), published='2020-01-01'),
    ]
    entries = {
        value: BriefKev(value, 'Vendor', 'Product', date, '', '')
        for value, date in [('CVE-2026-1001', '2026-11-20'), ('CVE-2026-1002', '2026-14-01')]
    }
    result = compose(data(*docs, kev=entries))
    assert result.report_count == result.recent_reports == 1
    assert not result.sections[0].items
    assert any('invalid or future dates' in note for note in result.coverage)
    assert any('invalid or future listing dates' in note for note in result.coverage)


def test_repeated_topics_count_distinct_reports_and_open_the_evidence() -> None:
    docs = [document(1), document(2, source='Other source')]
    mentions = [('1', 'cve', 'CVE-2026-1001'), ('1', 'cve', 'CVE-2026-1001'), ('2', 'cve', 'CVE-2026-1001')]
    highlight = compose(data(*docs, mentions=mentions)).highlights[0]
    assert '2 reports from 2 sources' in highlight.text
    assert 'More mentions do not mean more attacks.' in highlight.text
    assert {item.document_id for item in highlight.evidence} == {'1', '2'}
    assert all(item.entity is None for item in highlight.evidence)


@pytest.mark.parametrize(
    ('weakness', 'meaning'),
    [
        ('Remote code execution', 'run code on an affected system'),
        ('Denial of service', 'interrupt a service on an affected system'),
        ('Authentication bypass', 'skip sign-in checks on an affected system'),
    ],
)
def test_severity_names_the_product_and_explains_only_the_stated_weakness(
    weakness: str, meaning: str
) -> None:
    doc = replace(
        document(1, body=f'- CVE-2026-1001, CVSS 3 base score 9.8: {weakness}'),
        title='Advisory 1 · Example Gateway',
    )
    result = compose(data(doc))
    severe = next(item for item in result.highlights if item.title == 'Highest reported severity')
    assert 'Example Gateway' in severe.text
    assert meaning in severe.text
    assert 'not the chance of an attack' in severe.text
    assert 'no confirmed CISA match' in severe.text
    assert severe.evidence[0].document_id == '1'
    assert not result.sections[0].items


def test_a_negated_weakness_is_quoted_without_reversing_its_meaning() -> None:
    doc = document(
        1, body='- CVE-2026-1001, CVSS 3 base score 9.8: This does not allow remote code execution.'
    )
    severe = next(h for h in compose(data(doc)).highlights if h.title == 'Highest reported severity')
    assert 'does not allow remote code execution' in severe.text
    assert 'could let an attacker run code' not in severe.text


def test_summary_explains_stated_harm_and_keeps_exact_scores_in_the_details() -> None:
    """Regression: the lead repeated CVSS numbers instead of explaining the source's stated harm."""
    doc = replace(
        document(1, body='- CVE-2026-1001, CVSS 3 base score 9.8: Remote code execution.'),
        title='Advisory · Example Gateway',
    )
    result = compose(data(doc))
    summary = ' '.join(result.summary)
    assert 'Example Gateway' in summary
    assert 'could let an attacker run code on an affected system' in summary
    assert 'not the chance of an attack' in summary
    assert 'Next step: check the named products and versions' in summary
    assert 'CVE-2026-1001' not in summary
    assert '9.8' not in summary
    assert result.sections[1].items[0].text == ('CVE-2026-1001 · CVSS 9.8 · Advisory · Example Gateway')
    assert result.sections[1].items[0].document_id == doc.id


def test_known_exploitation_is_separate_from_high_severity_and_is_conditional() -> None:
    entry = BriefKev('CVE-2020-1001', 'Example', 'Gateway', '2020-01-01', '', '1')
    result = compose(data(document(1), kev={entry.cve: entry}, mentions=[('1', 'cve', entry.cve)]))
    finding = result.highlights[0]
    assert 'Example Gateway' in finding.text
    assert 'past or present' in finding.text
    assert finding.action.startswith('If you use these products')
    assert not result.sections[1].items
    assert any('whether attacks are happening today' in note for note in result.coverage)


@pytest.mark.parametrize('score', ['-1', '10.1', '99', 'NaN', 'inf'])
def test_invalid_scores_do_not_create_severity_claims(score: str) -> None:
    result = compose(data(document(1, body=f'- CVE-2026-1001, CVSS 3 base score {score}: a flaw')))
    assert not result.sections[1].items
    assert all(item.title != 'Highest reported severity' for item in result.highlights)


def test_watch_matches_are_potential_relevance_not_confirmed_exposure() -> None:
    result = compose(data(document(1), watch={'Example Gateway': {'1'}}))
    finding = next(
        item for item in result.highlights if item.title == 'Possible relevance to your organization'
    )
    assert 'not proof that your systems are exposed' in finding.text
    assert finding.evidence[0].document_id == '1'


def test_vendor_evidence_matches_a_vendor_token_not_an_unrelated_word() -> None:
    result = compose(
        data(
            document(1, body='Vendors: GE'),
            document(2, body='Vendors: Acme\nThis general message concerns another product.'),
            document(3, body='Vendors: ge'),
        )
    )
    finding = next(item for item in result.highlights if item.title == 'Products to check against your own')
    assert 'GE is among' in finding.text
    assert {item.document_id for item in finding.evidence} == {'1', '3'}


def test_empty_stale_failed_and_capped_coverage_are_distinct() -> None:
    yesterday = (NOW - timedelta(hours=25)).isoformat()
    earlier = (NOW - timedelta(hours=2)).isoformat()
    checks = (
        ('old', 'Old feed', yesterday, 'success', yesterday),
        ('failed', 'Failed feed', NOW.isoformat(), 'error', earlier),
        ('fresh', 'Fresh feed', earlier, 'success', earlier),
        ('missing', 'Missing feed', '', '', ''),
    )
    result = compose(data(truncated=True, source_checks=checks))
    notes = '\n'.join(result.coverage)
    assert 'rankings are partial' in notes
    assert 'Old feed: no successful check in the last 24 hours' in notes
    assert 'Failed feed: the latest check failed' in notes
    assert 'Fresh feed: last successful check' in notes
    assert 'Missing feed: no successful check' in notes
    assert 'does not establish that your systems are safe' in notes


def test_gathering_marks_a_visible_cap_and_counts_unchanged_success_as_fresh(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr('insight.services.brief.MAX_BRIEF_DOCUMENTS', 1)
    with session_factory.begin() as db:
        for i in range(2):
            doc, _ = services.ingest(db, DocumentInput(title=f'Report {i}', body='Text', source_name='Feed'))
            doc.created_at = (NOW - timedelta(hours=2)).isoformat()
        db.add(
            SourceRun(
                source_key='ncsc',
                status='success',
                message='Unchanged since the last sync.',
                created_at=(NOW - timedelta(hours=1)).isoformat(),
            )
        )
    with session_factory() as db:
        gathered = services.brief_data(db, since=window_start(NOW))
    assert gathered.truncated
    assert len(gathered.documents) == 1
    assert any('UK NCSC Reports: last successful check' in note for note in compose(gathered).coverage)


def test_source_health_covers_only_the_sources_in_use(session_factory: sessionmaker[Session]) -> None:
    """Optional sources stay out of the coverage notes until switched on (ADR 0021)."""
    with session_factory() as db:
        keys = [check[0] for check in services.brief_data(db, since=window_start(NOW)).source_checks]
    assert keys == ['cisa-kev', 'cisa-csaf', 'sans-isc', 'ncsc']
    with session_factory.begin() as db:
        services.set_source_switch(db, 'talos', True, at=NOW)
        services.set_source_switch(db, 'ncsc', False, at=NOW)
    with session_factory() as db:
        keys = [check[0] for check in services.brief_data(db, since=window_start(NOW)).source_checks]
    assert keys == ['cisa-kev', 'cisa-csaf', 'sans-isc', 'talos']
