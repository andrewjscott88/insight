"""Confidence, source reliability and report credibility (TIP 4.2, ADR 0033)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, Document, Entity, Observation
from insight.schemas import CredibilityInput, DocumentInput, SourceRatingInput


def report(db: Session, title: str, body: str, source: str, tlp: str = 'GREEN') -> Document:
    doc, _ = services.ingest(db, DocumentInput(title=title, body=body, source_name=source, tlp=tlp))
    return doc


def entity(db: Session, value: str) -> str:
    found: str = db.scalars(select(Entity.id).where(Entity.value == value)).one()
    return found


def rate(db: Session, source: str, grade: str, half_life: int | None = None) -> None:
    payload = SourceRatingInput(source_name=source, reliability=grade, half_life_days=half_life)
    services.rate_source(db, payload)


def test_one_unrated_report_is_low_and_independent_reliable_sources_add_up(db: Session) -> None:
    report(db, 'First', 'C2 at 203.0.113.80.', 'Blog')
    ip = entity(db, '203.0.113.80')
    single = services.indicator_confidence(db, ip)
    assert (single.score, single.band) == (12, 'low')  # 0.6 x F 0.5 x credibility 6 0.5 x unreviewed 0.8
    assert [(c.source_name, c.reliability, c.reports) for c in single.sources] == [('Blog', 'F', 1)]

    report(db, 'Second', 'Again 203.0.113.80.', 'Vendor')
    report(db, 'Third', 'And 203.0.113.80.', 'CERT')
    rate(db, 'Vendor', 'A')
    rate(db, 'CERT', 'B')
    for doc in db.scalars(select(Document)):
        services.set_credibility(db, doc.id, CredibilityInput(credibility=2))
    for obs in db.scalars(select(Observation)):
        services.set_observation_status(db, obs.id, 'accepted')
    many = services.indicator_confidence(db, ip)
    assert many.band == 'high', many
    assert [c.source_name for c in many.sources] == ['Vendor', 'CERT', 'Blog']


def test_more_reports_from_one_source_do_not_count_as_agreement(db: Session) -> None:
    for n in range(5):
        report(db, f'Repost {n}', f'C2 at 203.0.113.81 ({n}).', 'Aggregator')
    found = services.indicator_confidence(db, entity(db, '203.0.113.81'))
    assert (found.score, found.sources[0].reports) == (12, 5)


def test_ip_addresses_age_hashes_do_not_and_a_source_can_age_faster(db: Session) -> None:
    sha = 'a' * 64
    report(db, 'Old note', f'C2 at 203.0.113.82, payload {sha}.', 'Vendor')
    rate(db, 'Vendor', 'A')
    ip, file_hash = entity(db, '203.0.113.82'), entity(db, sha)
    now = datetime.now(UTC)
    fresh = services.indicator_confidence(db, ip, at=now)
    month = services.indicator_confidence(db, ip, at=now + timedelta(days=30))
    assert month.score == round(fresh.score / 2)
    assert month.half_life_days == 30
    assert services.indicator_confidence(db, file_hash, at=now + timedelta(days=3650)).score == fresh.score
    rate(db, 'Vendor', 'A', half_life=7)
    assert services.indicator_confidence(db, ip, at=now + timedelta(days=7)).score == round(fresh.score / 2)
    assert services.indicator_confidence(db, file_hash, at=now + timedelta(days=700)).score == fresh.score


def test_rejected_mentions_hidden_reports_and_old_revisions_never_count(db: Session) -> None:
    open_doc = report(db, 'Open', 'C2 at 203.0.113.83.', 'Vendor')
    report(db, 'Partner', 'C2 at 203.0.113.83.', 'Partner feed', tlp='AMBER')
    ip = entity(db, '203.0.113.83')
    green = services.indicator_confidence(db, ip, max_tlp='GREEN')
    assert [c.source_name for c in green.sources] == ['Vendor']
    mention = db.scalars(select(Observation).where(Observation.document_id == open_doc.id)).one()
    services.set_observation_status(db, mention.id, 'rejected')
    assert [c.source_name for c in services.indicator_confidence(db, ip, max_tlp='GREEN').sources] == []
    db.execute(update(Document).values(is_current=False))
    assert services.indicator_confidence(db, ip).score == 0
    assert services.indicator_confidence(db, ip).band == 'none'


def test_credibility_is_audited_and_hidden_reports_cannot_be_graded(db: Session) -> None:
    hidden = report(db, 'Partner', 'Text.', 'Partner feed', tlp='AMBER')
    services.set_credibility(db, hidden.id, CredibilityInput(credibility=1))
    actions = [e.action for e in db.scalars(select(AuditEvent).where(AuditEvent.object_id == hidden.id))]
    assert 'document.credibility' in actions
    try:
        services.set_credibility(db, hidden.id, CredibilityInput(credibility=2), max_tlp='GREEN')
    except LookupError:
        pass
    else:
        raise AssertionError('a GREEN caller graded an AMBER report')


def test_source_statistics_count_what_each_source_adds(db: Session) -> None:
    first = report(db, 'One', 'C2 at 203.0.113.84 and 203.0.113.85.', 'Vendor')
    report(db, 'Two', 'Seen 203.0.113.85 too.', 'Blog')
    report(db, 'Three', 'Nothing here.', 'Blog')
    report(db, 'Hidden', 'C2 at 203.0.113.86.', 'Partner feed', tlp='AMBER')
    mention = db.scalars(
        select(Observation)
        .join(Entity)
        .where(Observation.document_id == first.id, Entity.value == '203.0.113.84')
    ).one()
    services.set_observation_status(db, mention.id, 'rejected')
    rate(db, 'Vendor', 'B')
    rate(db, 'Unused feed', 'C')
    stats = {s.source_name: s for s in services.source_statistics(db, max_tlp='GREEN')}
    assert set(stats) == {'Vendor', 'Blog'}  # Neither the AMBER-only source nor an unused rating shows.
    vendor, blog = stats['Vendor'], stats['Blog']
    assert (vendor.reliability, vendor.reports, vendor.indicators, vendor.unique_indicators) == ('B', 1, 1, 0)
    assert (vendor.reviewed, vendor.rejected) == (1, 1)
    assert (blog.reliability, blog.reports, blog.indicators, blog.unique_indicators) == ('F', 2, 1, 0)
    everything = {s.source_name for s in services.source_statistics(db)}
    assert everything == {'Vendor', 'Blog', 'Partner feed', 'Unused feed'}
