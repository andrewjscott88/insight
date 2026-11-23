"""Operator feed decisions, revisions and state retained when its config changes."""

import re
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import Document, FetchState, Job, OperatorSource, Schedule, SourceRun, SourceSwitch
from insight.schemas import DocumentInput, OperatorSourceInput, OperatorSourceSwitchInput
from insight.services.operator_sources import _visible_operator_history

FEED = OperatorSourceInput(name='Partner', url='https://feed.example.org/rss')
AT = datetime(2026, 1, 1, tzinfo=UTC)


def test_create_update_switch_and_delete_are_audited(db: Session) -> None:
    services.set_actor(db, 'operator')
    view = services.create_operator_source(db, FEED)
    assert re.fullmatch(r'op-[a-f0-9]{32}', view.key)
    assert UUID(view.key.removeprefix('op-')).version == 4
    assert view.kind == 'rss'
    assert view.tlp == 'AMBER'
    assert view.reuse == 'metadata'
    assert not view.enabled
    assert view.revision == 1
    assert view.created_at == view.updated_at
    assert view.actor == 'operator'
    assert db.get(SourceSwitch, view.key) is not None
    assert services.list_operator_sources(db) == [view]
    assert services.get_operator_source(db, view.key, lock=True) == view
    same = services.update_operator_source(db, view.key, FEED)
    assert same == services.set_operator_source_enabled(db, view.key, False) == view
    enabled = services.set_operator_source_enabled(db, view.key, True)
    assert enabled.enabled
    assert enabled.revision == 2
    assert services.set_operator_source_enabled(db, view.key, True) == enabled
    renamed = services.update_operator_source(db, view.key, FEED.model_copy(update={'name': 'Partner news'}))
    assert renamed.enabled
    assert renamed.revision == 3
    services.set_operator_source_enabled(db, view.key, False)
    services.delete_operator_source(db, view.key)
    assert not services.list_operator_sources(db)
    assert {event.action for event in services.audit_events(db) if event.actor == 'operator'} == {
        'source.create',
        'source.on',
        'source.update',
        'source.off',
        'source.delete',
    }


def test_hidden_and_above_limit_sources(db: Session) -> None:
    with pytest.raises(services.TlpNotPermitted):
        services.create_operator_source(db, FEED, max_tlp='GREEN')
    key = services.create_operator_source(db, FEED, max_tlp='AMBER').key
    limited = FEED.model_copy(update={'tlp': 'GREEN'})
    assert services.list_operator_sources(db, max_tlp='GREEN') == []
    assert len(services.list_operator_sources(db, max_tlp='AMBER')) == 1
    for candidate in (key, 'op-never-existed'):
        with pytest.raises(LookupError, match='Source not found'):
            services.get_operator_source(db, candidate, max_tlp='GREEN')
        with pytest.raises(LookupError, match='Source not found'):
            services.update_operator_source(db, candidate, limited, max_tlp='GREEN')
        with pytest.raises(LookupError, match='Source not found'):
            services.set_operator_source_enabled(db, candidate, True, max_tlp='GREEN')
        with pytest.raises(LookupError, match='Source not found'):
            services.delete_operator_source(db, candidate, max_tlp='GREEN')
    with pytest.raises(services.TlpNotPermitted):
        services.update_operator_source(db, key, FEED.model_copy(update={'tlp': 'RED'}), max_tlp='AMBER')
    assert services.get_operator_source(db, key).revision == 1


def test_endpoint_edit_requires_new_consent_and_only_resets_its_own_state(db: Session) -> None:
    key = services.create_operator_source(db, FEED).key
    other = services.create_operator_source(db, FEED).key
    jobs = {}
    for subject in [key, other]:
        services.set_operator_source_enabled(db, subject, True)
        services.set_schedule(db, subject, 60, at=AT)
        services.save_fetch_cursor(db, subject, 'prior-page')
        jobs[subject] = services.enqueue_job(db, services.SOURCE_SYNC, subject, at=AT).id

    policy = FEED.model_copy(update={'name': 'New name', 'tlp': 'GREEN', 'reuse': 'public'})
    changed = services.update_operator_source(db, key, policy)
    assert changed.enabled
    assert changed.revision == 3
    assert services.list_schedules(db)[key].enabled
    assert db.get(Job, jobs[key]) is not None
    assert db.get(FetchState, key) is None
    services.save_fetch_cursor(db, key, 'fresh')
    endpoint = policy.model_copy(update={'url': 'https://new.example.org/feed'})
    moved = services.update_operator_source(db, key, endpoint)
    assert not moved.enabled
    assert moved.revision == 4
    assert db.get(Schedule, key) is None
    assert db.get(Job, jobs[key]) is None
    assert db.get(FetchState, key) is None
    assert services.get_operator_source(db, other).enabled
    assert services.list_schedules(db)[other].enabled
    assert db.get(Job, jobs[other]) is not None
    assert services.fetch_cursor(db, other) == 'prior-page'


def test_delete_preserves_report_provenance_and_removes_future_work(db: Session) -> None:
    key = services.create_operator_source(db, FEED).key
    services.set_operator_source_enabled(db, key, True)
    services.save_fetch_cursor(db, key, 'page')
    services.set_schedule(db, key, 60, at=AT)
    job = services.enqueue_job(db, services.SOURCE_SYNC, key, at=AT)
    report, _ = services.ingest(
        db,
        DocumentInput(
            title='Partner report', body='Reference 192.0.2.1.', source_name='Partner', tlp='AMBER'
        ),
        ref=services.SourceRef(key, 'article-1'),
    )
    services.delete_operator_source(db, key)
    db.flush()
    db.expire_all()
    for model in (OperatorSource, SourceSwitch, Schedule, FetchState):
        assert db.get(model, key) is None
    assert db.get(Job, job.id) is None
    saved = db.get(Document, report.id)
    assert saved is not None
    assert (saved.source_key, saved.tlp) == (key, 'AMBER')


def test_endpoint_change_prevents_retry_of_an_in_flight_job(db: Session) -> None:
    key = services.create_operator_source(db, FEED).key
    services.set_operator_source_enabled(db, key, True)
    job = services.enqueue_job(db, services.SOURCE_SYNC, key, at=AT)
    assert services.claim_job(db, at=AT) == job
    services.update_operator_source(db, key, FEED.model_copy(update={'url': 'https://new.example.org/rss'}))
    result = services.finish_job(db, job.id, ok=False, message='Source changed.', at=AT)
    assert result.status == 'failed'


def test_limited_history_is_trimmed_when_source_label_is_lowered(db: Session) -> None:
    key = services.create_operator_source(db, FEED).key
    db.add(SourceRun(source_key=key, status='ok', message='sensitive', created_at=AT.isoformat()))
    services.update_operator_source(db, key, FEED.model_copy(update={'tlp': 'GREEN'}))
    db.add(SourceRun(source_key=key, status='ok', message='visible'))
    stmt = select(SourceRun.message)
    assert set(
        db.scalars(stmt.where(_visible_operator_history(SourceRun.source_key, SourceRun.created_at, 'GREEN')))
    ) == {'visible'}
    assert set(
        db.scalars(stmt.where(_visible_operator_history(SourceRun.source_key, SourceRun.created_at, None)))
    ) == {'sensitive', 'visible'}


@pytest.mark.parametrize(
    'url',
    [
        'http://example.org/feed',
        'https://example.org:8443/feed',
        'https://name:secret@example.org/',
        'https://@example.org/rss',
        'https://example.org/feed?value=anything',
        'https://example.org/?',
        'https://example.org/#',
        'https://bad.example\\@good.example/',
        'https://example.org:/rss',
        'https://127.0.0.1/',
        'https://[::ffff:127.0.0.1]/',
        'https://169.254.169.254/',
        'https://localhost/',
        'https://tra\ncker.example.org/rss',
        'https://feed%2Eexample.org/',
        'https://-bad.example.org/',
        'https://example.org/' + 'x' * 2048,
    ],
)
def test_endpoint_rejects_invalid_or_unsafe_addresses(url: str) -> None:
    with pytest.raises(ValidationError):
        OperatorSourceInput(name='Partner', url=url)


def test_rss_schema_defaults_limits_and_explicit_opt_in() -> None:
    for url in ('https://example.org/feed', 'https://example.org:443/a%20b', 'https://[2606:4700::1111]/'):
        assert OperatorSourceInput(name=' Partner ', url=url).name == 'Partner'
    for field, value in (
        ('kind', 'taxii'),
        ('name', ' '),
        ('name', 'x' * 161),
        ('reuse', 'private'),
        ('token', 'anything'),
    ):
        with pytest.raises(ValidationError):
            OperatorSourceInput.model_validate(FEED.model_dump() | {field: value})
    with pytest.raises(ValidationError):
        OperatorSourceSwitchInput.model_validate({'enabled': 'no'})


def test_address_normalization_preserves_the_feed_path() -> None:
    assert OperatorSourceInput(name='RSS', url='https://CAFÉ.example:443/Mixed%20Feed').url == (
        'https://xn--caf-dma.example/Mixed%20Feed'
    )
    assert OperatorSourceInput(name='RSS', url='https://[2606:4700:0000::1111]:443/Atom').url == (
        'https://[2606:4700::1111]/Atom'
    )
