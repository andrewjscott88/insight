"""Configuration and migration boundaries for operator-defined TAXII collections."""

from dataclasses import asdict
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

from insight import migrations, services
from insight.models import Document
from insight.schemas import DocumentInput, OperatorSourceInput
from insight.source_registry import metadata_only

URL = 'https://taxii.example.org/root/'
VARIABLE = 'INSIGHT_SOURCE_PARTNER'
TAXII = OperatorSourceInput(
    name='Partner collection',
    kind='taxii',
    url=URL,
    collection_id='collection_1',
    credential_env=VARIABLE,
)
AT = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    'collection_id', ['', '.', '..', 'a/../b', 'a%2Fb', 'a?x', 'name with space', 'x' * 251]
)
def test_collection_id_is_one_url_safe_segment(collection_id: str) -> None:
    with pytest.raises(ValidationError):
        OperatorSourceInput(name='Partner', kind='taxii', url=URL, collection_id=collection_id)


@pytest.mark.parametrize(
    'variable',
    [
        '',
        'SECRET',
        'INSIGHT_SOURCE_',
        'INSIGHT_SOURCE_lc',
        'INSIGHT_SOURCE_X-Y',
        'INSIGHT_SOURCE_' + 'A' * 41,
    ],
)
def test_credential_reference_is_only_an_allowed_variable_name(variable: str) -> None:
    with pytest.raises(ValidationError):
        OperatorSourceInput(name='Partner', kind='taxii', url=URL, collection_id='a', credential_env=variable)


def test_only_collections_can_reference_credentials() -> None:
    for field in ({'collection_id': 'all'}, {'credential_env': VARIABLE}):
        with pytest.raises(ValidationError):
            OperatorSourceInput.model_validate({'name': 'Feed', 'kind': 'rss', 'url': URL} | field)
    assert (
        OperatorSourceInput(
            name='Partner', kind='taxii', url=URL, collection_id='events_2.0~archive'
        ).credential_env
        is None
    )


def test_stores_only_a_reference_and_checks_credentials_each_read(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(VARIABLE, raising=False)
    source = services.create_operator_source(db, TAXII)
    assert not source.configured
    assert not source.enabled
    assert source.credential_env == VARIABLE
    assert source.collection_id == 'collection_1'
    monkeypatch.setenv(VARIABLE, 'synthetic-token')
    assert services.get_operator_source(db, source.key).configured
    assert services.list_operator_sources(db)[0].configured
    assert 'synthetic-token' not in repr(asdict(services.get_operator_source(db, source.key)))
    assert 'synthetic-token' not in repr(db.execute(text('SELECT * FROM operator_sources')).fetchall())
    assert all('synthetic-token' not in event.detail for event in services.audit_events(db))
    monkeypatch.setenv(VARIABLE, '')
    assert not services.get_operator_source(db, source.key).configured
    anon = services.create_operator_source(db, TAXII.model_copy(update={'credential_env': None}))
    assert anon.configured


@pytest.mark.parametrize(
    'changed',
    [
        {'collection_id': 'different'},
        {'credential_env': 'INSIGHT_SOURCE_OTHER'},
        {'url': 'https://example.org/'},
    ],
)
def test_endpoint_or_credential_reference_resets_consumption_state(
    db: Session, monkeypatch: pytest.MonkeyPatch, changed: dict[str, str]
) -> None:
    monkeypatch.setenv(VARIABLE, 'synthetic-token')
    source = services.create_operator_source(db, TAXII)
    services.set_operator_source_enabled(db, source.key, True)
    services.set_schedule(db, source.key, 60, at=AT)
    services.save_fetch_cursor(db, source.key, 'saved')
    adjusted = services.update_operator_source(db, source.key, TAXII.model_copy(update=changed))
    assert not adjusted.enabled
    assert adjusted.revision == 3
    assert source.key not in services.list_schedules(db)
    assert not services.fetch_cursor(db, source.key)


def test_editing_only_reuse_or_name_keeps_consent(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(VARIABLE, 'synthetic-token')
    key = services.create_operator_source(db, TAXII).key
    services.set_operator_source_enabled(db, key, True)
    services.set_schedule(db, key, 60, at=AT)
    revised = services.update_operator_source(
        db, key, TAXII.model_copy(update={'name': 'New name', 'reuse': 'public'})
    )
    assert revised.enabled
    assert services.list_schedules(db)[key].enabled
    rss = OperatorSourceInput(name='Partner RSS', url=URL)
    assert not services.update_operator_source(db, key, rss).enabled


def test_0032_rollback_preserves_sticky_restrictions_and_current_rss_config(empty_database_url: str) -> None:
    engine = create_engine(empty_database_url)
    try:
        migrations.upgrade(engine, '0031')
        migrations.upgrade(engine, '0032')
        with Session(engine) as db, db.begin():
            taxii = services.create_operator_source(
                db, TAXII.model_copy(update={'credential_env': None, 'reuse': 'public'})
            )
            rss = services.create_operator_source(
                db, OperatorSourceInput(name='RSS', url=URL, reuse='public')
            )
            for key in (taxii.key, rss.key):
                services.set_operator_source_enabled(db, key, True)
                services.set_schedule(db, key, 60, at=AT)
                services.save_fetch_cursor(db, key, 'cursor')
                services.enqueue_job(db, services.SOURCE_SYNC, key, at=AT)
            for source, ref, title, restricted in (
                (taxii, 'one', 'Removed collection', False),
                (taxii, 'two', 'Restricted collection report', True),
                (rss, 'same', 'Previous revision', False),
                (rss, 'same', 'Marked revision', True),
                (rss, 'other', 'Open report', False),
            ):
                doc, _ = services.ingest(
                    db,
                    DocumentInput(title=title, body='Retained text', source_name=source.name, tlp='GREEN'),
                    ref=services.SourceRef(source.key, ref),
                )
                doc.operator_publisher_metadata_only = restricted
            db.flush()
            original = set(db.scalars(select(Document.id)))
            gone, kept = taxii.key, rss.key
        migrations.downgrade(engine, '0031')
        assert 'collection_id' not in {c['name'] for c in inspect(engine).get_columns('operator_sources')}
        with engine.connect() as conn:
            sources = conn.execute(text('SELECT key, reuse FROM operator_sources')).mappings()
            policies = {source['key']: source['reuse'] for source in sources}
            assert policies == {kept: 'public'}
            rows = (
                conn.execute(
                    text('SELECT id,title,source_key,external_id,body,tlp,reuse_changed_at FROM documents')
                )
                .mappings()
                .all()
            )
            assert {r['id'] for r in rows} == original
            for row in rows:
                key = str(row['source_key'])
                assert metadata_only(key, policies.get(key)) == (row['title'] != 'Open report')
                assert row['body'] == 'Retained text'
                assert row['tlp'] == 'GREEN'
                if row['title'] == 'Removed collection':
                    assert row['reuse_changed_at'] is not None
                if row['title'] == 'Restricted collection report':
                    assert row['reuse_changed_at'] is None
            assert len({r['source_key'] for r in rows if r['external_id'] == 'same'}) == 1
            for stmt in (
                'SELECT source_key FROM schedules',
                'SELECT source_key FROM source_switches',
                'SELECT url FROM fetch_state',
                'SELECT key FROM jobs',
            ):
                assert set(conn.execute(text(stmt)).scalars()) == {kept}
        migrations.upgrade(engine)
        with Session(engine) as db:
            assert not db.scalars(select(Document).where(Document.operator_publisher_metadata_only)).all()
            assert services.get_operator_source(db, kept).kind == 'rss'
            with pytest.raises(LookupError):
                services.get_operator_source(db, gone)
    finally:
        engine.dispose()
