"""Schema migrations (decision 1): fresh installs, reversibility, model parity and upgrades of real releases.

Runs on SQLite by default and on PostgreSQL when ``INSIGHT_TEST_DATABASE_URL`` is set.
"""

from __future__ import annotations

import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, func, inspect, select, text
from sqlalchemy.orm import Session

from insight import migrations, services
from insight.connectors import import_kev
from insight.demo import seed
from insight.models import ActorDocument, Base, Document, Note, Observation, ThreatActor, WatchTerm, database
from insight.services import DocumentQuery, search_documents

RELEASES = Path(__file__).parent.parent / 'fixtures' / 'releases'


@pytest.fixture
def engine(empty_database_url: str) -> Iterator[Engine]:
    engine = create_engine(empty_database_url)
    yield engine
    engine.dispose()


def schema_diff(engine: Engine) -> list[object]:
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={'compare_type': True})
        return list(compare_metadata(context, Base.metadata))


def revision_chain() -> list[str]:
    script = ScriptDirectory.from_config(migrations.alembic_config())
    return [rev.revision for rev in reversed(list(script.walk_revisions()))]


def test_revision_history_is_linear_and_sequential() -> None:
    script = ScriptDirectory.from_config(migrations.alembic_config())
    assert len(script.get_heads()) == 1, 'branched migration history; merge the heads'
    chain = revision_chain()
    assert chain[0] == migrations.BASELINE_REVISION
    assert chain == [f'{n:04d}' for n in range(1, len(chain) + 1)]
    assert chain[-1] == migrations.head_revision()


def test_fresh_database_migrates_to_head(engine: Engine) -> None:
    migrations.upgrade(engine)
    assert migrations.current_revision(engine) == migrations.head_revision()
    assert set(inspect(engine).get_table_names()) == {*Base.metadata.tables, 'alembic_version'}


def test_models_match_migrations(engine: Engine) -> None:
    """The equivalent of ``alembic check``: a model change without a migration fails here."""
    migrations.upgrade(engine)
    assert schema_diff(engine) == []


def test_every_revision_is_reversible(engine: Engine) -> None:
    chain = revision_chain()
    for revision in chain:
        migrations.upgrade(engine, revision)
        assert migrations.current_revision(engine) == revision
    for previous in [*reversed(chain[:-1]), 'base']:
        migrations.downgrade(engine, previous)
        assert migrations.current_revision(engine) == (None if previous == 'base' else previous)
    migrations.upgrade(engine)
    assert schema_diff(engine) == []


def test_upgrade_is_idempotent(engine: Engine) -> None:
    migrations.upgrade(engine)
    migrations.upgrade(engine)
    assert migrations.current_revision(engine) == migrations.head_revision()


# --------------------------------------------------------------------------- upgrading real releases


@pytest.fixture
def release_0_1_0(tmp_path: Path) -> Path:
    """A database written by the actual 0.1.0 code (demo, KEV with a publisher edit, RSS, notes, reviews)."""
    path = tmp_path / 'insight-0.1.0.sqlite3'
    shutil.copy(RELEASES / 'insight-0.1.0.sqlite3', path)
    return path


def test_release_0_1_0_upgrades_without_data_loss(release_0_1_0: Path) -> None:
    with closing(sqlite3.connect(release_0_1_0)) as before:
        existing = {row[0] for row in before.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        # Tables added after 0.1.0 (e.g. api_keys in 0004) cannot lose data; count every table 0.1.0 had.
        counts = {
            t: before.execute(f'SELECT count(*) FROM {t}').fetchone()[0]  # noqa: S608
            for t in Base.metadata.tables
            if t in existing
        }
        assert set(counts) >= {'documents', 'observations', 'entities', 'notes', 'audit_events'}

    engine, sessions = database(f'sqlite:///{release_0_1_0}')
    try:
        assert migrations.current_revision(engine) == migrations.head_revision()
        assert schema_diff(engine) == []
        with engine.connect() as conn:
            assert conn.exec_driver_sql('PRAGMA foreign_key_check').fetchall() == []
            for table, expected in counts.items():
                assert conn.execute(text(f'SELECT count(*) FROM {table}')).scalar() == expected, table  # noqa: S608
        with sessions() as db:
            assert db.scalar(select(Note.body)) == 'Escalated to SOC lead.'
            assert db.scalar(select(WatchTerm.term)) == 'GlobalProtect'
            reviewed = db.scalar(select(Document).where(Document.title == 'Analyst paste'))
            assert reviewed is not None
            assert reviewed.status == 'reviewed'
            assert reviewed.source_key is None  # manual documents are not keyed
            assert 'accepted' in db.scalars(select(Observation.review_status)).all()
    finally:
        engine.dispose()


def test_release_0_1_0_duplicates_become_linked_revisions(release_0_1_0: Path) -> None:
    engine, sessions = database(f'sqlite:///{release_0_1_0}')
    try:
        with sessions() as db:
            kev = list(
                db.scalars(
                    select(Document)
                    .where(Document.external_id == 'CVE-2024-3400')
                    .order_by(Document.created_at)
                )
            )
            assert [d.is_current for d in kev] == [False, True]
            assert kev[1].supersedes_id == kev[0].id
            assert all(d.source_key == 'cisa-kev' for d in kev)
            rss = db.scalar(select(Document).where(Document.external_id == 'https://isc.sans.edu/diary/1'))
            assert rss is not None
            assert rss.source_key == 'sans-isc'
            visible = [d.title for d in search_documents(db, DocumentQuery(q='PAN-OS'))]
            assert visible == ['CVE-2024-3400 · Palo Alto Networks PAN-OS']  # only the current revision
    finally:
        engine.dispose()


def test_release_0_1_0_fingerprints_still_deduplicate(release_0_1_0: Path) -> None:
    """Data written by 0.1.0 must still be recognised: re-seeding or re-syncing creates nothing new."""
    engine, sessions = database(f'sqlite:///{release_0_1_0}')
    try:
        with sessions.begin() as db:
            total = db.scalar(select(func.count()).select_from(Document))
            assert seed(db) == 0
            payload = (
                b'{"vulnerabilities": [{"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks",'
                b' "product": "PAN-OS", "dateAdded": "2024-04-12", "dueDate": "2024-04-19",'
                b' "requiredAction": "Apply mitigations per vendor instructions.",'
                b' "shortDescription": "OS command injection in the GlobalProtect feature of PAN-OS."}]}'
            )
            assert import_kev(db, payload) == (1, 0)
            assert db.scalar(select(func.count()).select_from(Document)) == total
    finally:
        engine.dispose()


@pytest.mark.parametrize('fixture', sorted(RELEASES.glob('insight-*.sqlite3')), ids=lambda p: p.stem)
def test_every_released_database_upgrades_cleanly(fixture: Path, tmp_path: Path) -> None:
    """Every final release commits a fixture (scripts/make_release_fixture.py); all must keep upgrading."""
    path = tmp_path / fixture.name
    shutil.copy(fixture, path)
    with closing(sqlite3.connect(path)) as conn:
        documents_before = conn.execute('SELECT count(*) FROM documents').fetchone()[0]
    engine, sessions = database(f'sqlite:///{path}')
    try:
        assert migrations.current_revision(engine) == migrations.head_revision()
        assert schema_diff(engine) == []
        with engine.connect() as conn:
            assert conn.exec_driver_sql('PRAGMA foreign_key_check').fetchall() == []
        with sessions.begin() as db:
            assert db.scalar(select(func.count()).select_from(Document)) == documents_before
            assert seed(db) == 0  # fingerprints written by that release still de-duplicate
    finally:
        engine.dispose()


def test_unversioned_legacy_database_is_stamped_and_backfilled(engine: Engine) -> None:
    """Backend-neutral version of the release test: an unversioned baseline schema with duplicates."""
    migrations.upgrade(engine, migrations.BASELINE_REVISION)
    insert = text(
        'INSERT INTO documents (id, fingerprint, content_hash, title, body, source_name, source_url, tlp, '
        "status, created_at, extractor_version) VALUES (:id, :fp, 'h', :title, 'b', :source, :url, 'CLEAR', "
        "'new', :created, 'regex-v1')"
    )
    kev = 'CISA Known Exploited Vulnerabilities'
    rows = [
        ('d1', 'CVE-2024-1000 · Vendor Product', kev, '', '2025-01-01T00:00:00+00:00'),
        ('d2', 'CVE-2024-1000 · Vendor Product', kev, '', '2025-02-01T00:00:00+00:00'),
        ('d3', 'CVE-2024-1000 · Vendor Product', kev, '', '2025-03-01T00:00:00+00:00'),
        ('d4', 'Feed item', 'UK NCSC Reports', 'https://ncsc.example/r/1', '2025-01-01T00:00:00+00:00'),
        ('d5', 'Manual', 'Analyst', '', '2025-01-01T00:00:00+00:00'),
    ]
    with engine.begin() as conn:
        for doc_id, title, source, url, created in rows:
            conn.execute(
                insert,
                {
                    'id': doc_id,
                    'fp': doc_id,
                    'title': title,
                    'source': source,
                    'url': url,
                    'created': created,
                },
            )
        conn.execute(text('DROP TABLE alembic_version'))  # what a 0.1.0 database looks like

    migrations.upgrade(engine)

    assert migrations.current_revision(engine) == migrations.head_revision()
    with engine.connect() as conn:
        result = conn.execute(
            text('SELECT id, source_key, external_id, is_current, supersedes_id FROM documents ORDER BY id')
        ).all()
    assert [tuple(r) for r in result] == [
        ('d1', 'cisa-kev', 'CVE-2024-1000', False, None),
        ('d2', 'cisa-kev', 'CVE-2024-1000', False, 'd1'),
        ('d3', 'cisa-kev', 'CVE-2024-1000', True, 'd2'),
        ('d4', 'ncsc', 'https://ncsc.example/r/1', True, None),
        ('d5', None, None, True, None),
    ]


def test_search_text_is_backfilled_so_old_documents_are_searchable(release_0_1_0: Path) -> None:
    """0003 folds existing documents; an upgraded 0.1.0 database supports the new search immediately."""
    engine, sessions = database(f'sqlite:///{release_0_1_0}')
    try:
        with sessions() as db:
            assert all(d.search_text for d in db.scalars(select(Document)))
            hits = search_documents(db, DocumentQuery(q='globalprotect feature of pan-os'))
            assert [d.title for d in hits] == ['CVE-2024-3400 · Palo Alto Networks PAN-OS']
            assert not any(d.truncated for d in db.scalars(select(Document)))
    finally:
        engine.dispose()


def test_upgrades_are_logged(release_0_1_0: Path, caplog: pytest.LogCaptureFixture) -> None:
    engine = create_engine(f'sqlite:///{release_0_1_0}')
    try:
        with caplog.at_level('INFO', logger='insight.migrations'):
            migrations.upgrade(engine)
            migrations.upgrade(engine)
    finally:
        engine.dispose()
    messages = [r.getMessage() for r in caplog.records if r.name == 'insight.migrations']
    assert messages[0].startswith('Unversioned (0.1.0) database detected')
    assert messages[1] == f'Database schema upgraded 0001 -> {migrations.head_revision()}'
    assert messages[2] == f'Database schema at revision {migrations.head_revision()} (up to date)'


def test_0015_preserves_markings_in_existing_actor_notes(engine: Engine) -> None:
    migrations.upgrade(engine, '0014')
    stamp = '2026-01-01T00:00:00+00:00'
    with Session(engine) as db, db.begin():
        # Raw SQL: the ORM model has columns later migrations add (0025's credibility).
        db.execute(
            text(
                'INSERT INTO documents (id, fingerprint, content_hash, title, body, source_name, source_url, '
                'tlp, status, created_at, extractor_version, is_current, search_text, truncated) '
                "VALUES (:id, :id, :id, 'Synthetic', 'Example only.', 'Lab', '', 'GREEN', 'new', :stamp, "
                "'1', :yes, '', :no)"
            ),
            {'id': 'historical-doc', 'stamp': stamp, 'yes': True, 'no': False},
        )
        actor = ThreatActor(name='Tracked example', description='Restricted TLP:AMBER', tlp='CLEAR')
        db.add(actor)
        db.flush()
        db.execute(
            text(
                'INSERT INTO actor_documents (id, group_ref, document_id, note, created_at, actor) '
                "VALUES (:id, :group_ref, :document_id, :note, :stamp, 'analyst')"
            ),
            {
                'id': 'historical-link',
                'group_ref': actor.id,
                'document_id': 'historical-doc',
                'note': 'Private TLP:RED, retained.',
                'stamp': stamp,
            },
        )
    migrations.upgrade(engine)
    with Session(engine) as db:
        assert db.scalars(select(ThreatActor)).one().tlp == 'AMBER'
        link = db.scalars(select(ActorDocument)).one()
        assert (link.tlp, link.note) == ('RED', 'Private TLP:RED, retained.')
        assert services.linked_reports(db, link.group_ref, max_tlp='AMBER') == []


def test_0022_turns_postgres_timestamps_into_timestamptz_and_back(engine: Engine) -> None:
    """Issue #11: text in any form Insight wrote becomes the same moment; code still reads ISO strings."""
    if engine.dialect.name != 'postgresql':
        pytest.skip('PostgreSQL only: SQLite keeps timestamps as text')
    migrations.upgrade(engine, '0021')
    written = {
        'with-offset': '2026-11-20T10:00:00.123456+00:00',
        'other-zone': '2026-11-20T12:30:00+02:30',  # 10:00 UTC
        'zulu': '2026-11-20T10:00:00Z',
        'naive': '2026-11-20T10:00:00',  # legacy rows had no offset: UTC
    }
    with engine.begin() as connection:
        connection.execute(text("SET TIME ZONE 'America/New_York'"))  # the session zone must not matter
        for term, stamp in written.items():
            connection.execute(
                text('INSERT INTO watch_terms (id, term, created_at) VALUES (:id, :term, :stamp)'),
                {'id': term, 'term': term, 'stamp': stamp},
            )
    migrations.upgrade(engine)
    columns = {c['name']: c['type'] for c in inspect(engine).get_columns('watch_terms')}
    assert str(columns['created_at']).startswith('TIMESTAMP')
    with Session(engine) as db:
        stored = {w.term: w.created_at for w in db.scalars(select(WatchTerm))}
        assert stored == {
            'with-offset': '2026-11-20T10:00:00.123456+00:00',
            'other-zone': '2026-11-20T10:00:00+00:00',
            'zulu': '2026-11-20T10:00:00+00:00',
            'naive': '2026-11-20T10:00:00+00:00',
        }
        # Comparing with an ISO string still works, in time order: 11:00+02:00 is 09:00 UTC (as text it would
        # sort after every 10:00 value and match none).
        later = db.scalars(select(WatchTerm.term).where(WatchTerm.created_at > '2026-11-20T11:00:00+02:00'))
        assert set(later) == set(written)
        newest = db.scalars(
            select(WatchTerm.term).where(WatchTerm.created_at > '2026-11-20T10:00:00.1+00:00')
        )
        assert list(newest) == ['with-offset']
    migrations.downgrade(engine, '0021')
    with engine.connect() as connection:
        back: dict[str, str] = dict(
            connection.execute(text('SELECT term, created_at FROM watch_terms')).all()
        )
    assert back['with-offset'] == '2026-11-20T10:00:00.123456+00:00'
    assert back['naive'] == '2026-11-20T10:00:00.000000+00:00'
