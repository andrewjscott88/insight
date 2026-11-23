"""Upgrading and rolling back retains labelled report identities, including deleted sources."""

from datetime import UTC, datetime

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from insight import migrations, services
from insight.models import Document
from insight.schemas import DocumentInput, OperatorSourceInput


def test_0031_rollback_retains_reports_without_exposing_their_text(empty_database_url: str) -> None:
    engine = create_engine(empty_database_url)
    try:
        migrations.upgrade(engine, '0030')
        migrations.upgrade(engine, '0031')
        keys: list[str] = []
        ids: list[str] = []
        with Session(engine) as db, db.begin():
            for name in ('First partner', 'Second partner'):
                source = services.create_operator_source(
                    db, OperatorSourceInput(name=name, url='https://feeds.example.org/rss', reuse='public')
                )
                keys.append(source.key)
                for title in ('First edition', 'Revised edition', 'Long publisher identity'):
                    item_id = 'item/17' if title != 'Long publisher identity' else 'z' * 500
                    doc, _ = services.ingest(
                        db,
                        DocumentInput(title=title, body='Partner text', source_name=name, tlp='AMBER'),
                        ref=services.SourceRef(source.key, item_id),
                    )
                    ids.append(doc.id)
                services.set_operator_source_enabled(db, source.key, True)
                services.set_schedule(db, source.key, 60, at=datetime.now(UTC))
                services.save_fetch_cursor(db, source.key, 'old cursor')
                services.enqueue_job(db, services.SOURCE_SYNC, source.key, at=datetime.now(UTC))
            services.delete_operator_source(db, keys[1])
            services.set_schedule(db, 'talos', 60, at=datetime.now(UTC))
        migrations.downgrade(engine, '0030')
        assert 'operator_sources' not in inspect(engine).get_table_names()
        with engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        'SELECT id, source_key, external_id, supersedes_id, tlp, title, body, source_name '
                        'FROM documents ORDER BY source_name, title'
                    )
                )
                .mappings()
                .all()
            )
            assert {r['id'] for r in rows} == set(ids)
            assert {r['source_key'] for r in rows} == {'stix-import-metadata'}
            assert {r['tlp'] for r in rows} == {'AMBER'}
            assert {r['body'] for r in rows} == {'Partner text'}
            assert {r['source_name'] for r in rows} == {'First partner', 'Second partner'}
            assert {r['external_id'] for r in rows if r['title'] == 'Revised edition'} == {
                f'{key}:id:item/17' for key in keys
            }
            for row in rows:
                if row['title'] == 'Revised edition':
                    previous = next(r for r in rows if r['id'] == row['supersedes_id'])
                    assert previous['external_id'] == row['external_id']
                if row['title'] == 'Long publisher identity':
                    assert len(row['external_id']) < 500
                    assert ':sha256:' in row['external_id']
            assert conn.execute(text('SELECT source_key FROM schedules')).scalars().all() == ['talos']
            assert conn.execute(text("SELECT count(*) FROM jobs WHERE kind='source.sync'")).scalar() == 0
        migrations.upgrade(engine)
        with Session(engine) as db:
            assert services.list_operator_sources(db) == []
            kept = db.get(Document, ids[0])
            assert kept is not None
            assert kept.source_key == 'stix-import-metadata'
    finally:
        engine.dispose()
