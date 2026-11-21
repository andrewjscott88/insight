"""Schema constraints and database initialisation."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from insight import migrations
from insight.models import Base, Document, Entity, Observation, WatchTerm, database, now, uid


def test_now_is_timezone_aware_utc_iso8601() -> None:
    parsed = datetime.fromisoformat(now())
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == UTC.utcoffset(None)


def test_uid_is_unique_uuid_string() -> None:
    ids = {uid() for _ in range(100)}
    assert len(ids) == 100
    assert all(len(i) == 36 for i in ids)


def test_in_memory_database_is_shared_across_threads(session_factory: sessionmaker[Session]) -> None:
    """Regression: "sqlite://" gave each thread its own empty database ("no such table").

    FastAPI runs sync endpoints in a worker thread and sync_source() uses asyncio.to_thread(), so the
    in-memory database must be visible from threads other than the one that created it.
    """
    with session_factory.begin() as db:
        db.add(WatchTerm(term='vpn'))
    seen: list[str | None] = []

    def read() -> None:
        with session_factory() as other:
            seen.append(other.scalar(select(WatchTerm.term)))

    worker = threading.Thread(target=read)
    worker.start()
    worker.join()
    assert seen == ['vpn']


def test_file_database_is_migrated_to_head(tmp_path: Path) -> None:
    engine, _ = database(f'sqlite:///{tmp_path / "x.db"}')
    try:
        assert set(inspect(engine).get_table_names()) == {*Base.metadata.tables, 'alembic_version'}
        assert migrations.current_revision(engine) == migrations.head_revision()
    finally:
        engine.dispose()


def test_database_can_skip_migrations(tmp_path: Path) -> None:
    engine, _ = database(f'sqlite:///{tmp_path / "raw.db"}', migrate=False)
    try:
        assert inspect(engine).get_table_names() == []
    finally:
        engine.dispose()


def test_foreign_keys_are_enforced(db: Session) -> None:
    db.add(Observation(document_id='missing', entity_id='missing', evidence='', start_offset=0, end_offset=0))
    with pytest.raises(IntegrityError):
        db.flush()


def test_entity_kind_value_is_unique(db: Session) -> None:
    db.add_all([Entity(kind='ip', value='192.0.2.1'), Entity(kind='ip', value='192.0.2.1')])
    with pytest.raises(IntegrityError):
        db.flush()


def test_same_value_different_kind_is_allowed(db: Session) -> None:
    db.add_all([Entity(kind='domain', value='x.test'), Entity(kind='url', value='x.test')])
    db.flush()


def test_document_fingerprint_is_unique(db: Session) -> None:
    common = {'content_hash': 'h', 'title': 't', 'body': 'b', 'source_name': 's'}
    db.add_all([Document(fingerprint='f', **common), Document(fingerprint='f', **common)])
    with pytest.raises(IntegrityError):
        db.flush()


def test_document_defaults(db: Session) -> None:
    doc = Document(fingerprint='f', content_hash='h', title='t', body='b', source_name='s')
    db.add(doc)
    db.flush()
    assert (doc.status, doc.tlp, doc.source_url, doc.extractor_version) == ('new', 'CLEAR', '', 'regex-v3')
    assert (doc.search_text, doc.truncated) == ('', False)
    assert doc.created_at


def _doc(fp: str, **extra: object) -> Document:
    return Document(fingerprint=fp, content_hash='h', title='t', body='b', source_name='s', **extra)


def test_only_one_current_revision_per_source_item(db: Session) -> None:
    db.add_all(
        [
            _doc('a', source_key='cisa-kev', external_id='CVE-1'),
            _doc('b', source_key='cisa-kev', external_id='CVE-1'),
        ]
    )
    with pytest.raises(IntegrityError):
        db.flush()


def test_superseded_revisions_and_manual_documents_are_unconstrained(db: Session) -> None:
    db.add_all(
        [
            _doc('a', source_key='cisa-kev', external_id='CVE-1', is_current=False),
            _doc('b', source_key='cisa-kev', external_id='CVE-1', is_current=False),
            _doc('c', source_key='cisa-kev', external_id='CVE-1'),
            _doc('d', source_key='cisa-kev', external_id='CVE-2'),
            _doc('e'),
            _doc('f'),
        ]
    )
    db.flush()
