"""Relational schema and database initialisation.

The schema is owned by Alembic migrations (``insight/migrations``); these models must stay in sync with them,
which ``tests/unit/test_migrations.py`` enforces. Timestamps are stored as ISO-8601 UTC strings (see
``docs/ARCHITECTURE.md`` for why the datetime-column conversion is deferred to the PostgreSQL milestone).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, TypeAlias
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Engine,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    false,
    text,
    true,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from .extraction import EXTRACTOR_VERSION


def uid() -> str:
    """Return a new random UUID4 string primary key."""
    return str(uuid4())


def now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()


class Base(DeclarativeBase):
    pass


class Document(Base):
    """Immutable source text plus provenance.

    Documents synced from a curated source carry ``(source_key, external_id)``. When the publisher changes an
    item, a new revision is created (``supersedes_id`` points to the previous one) and only one revision per
    item is ``is_current``. Bodies are never edited in place because observations store exact offsets.
    """

    __tablename__ = 'documents'
    __table_args__ = (
        Index(
            'uq_documents_current_source_item',
            'source_key',
            'external_id',
            unique=True,
            sqlite_where=text('is_current = 1 AND external_id IS NOT NULL'),
            postgresql_where=text('is_current AND external_id IS NOT NULL'),
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text)
    source_name: Mapped[str] = mapped_column(String(160))
    source_url: Mapped[str] = mapped_column(Text, default='')
    tlp: Mapped[str] = mapped_column(String(20), default='CLEAR')
    status: Mapped[str] = mapped_column(String(20), default='new')
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    extractor_version: Mapped[str] = mapped_column(String(40), default=EXTRACTOR_VERSION)
    source_key: Mapped[str | None] = mapped_column(String(80), default=None)
    external_id: Mapped[str | None] = mapped_column(String(500), default=None)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    supersedes_id: Mapped[str | None] = mapped_column(ForeignKey('documents.id'), default=None)
    #: Case-, accent- and width-folded copy of title, source and body (``services.fold``). Search runs on it,
    #: so results are identical on SQLite and PostgreSQL and independent of Unicode normal form.
    search_text: Mapped[str] = mapped_column(Text, default='', server_default='')
    #: True when a connector had to shorten the publisher's text (e.g. RSS summaries are capped at 500 chars).
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())


class Entity(Base):
    __tablename__ = 'entities'
    __table_args__ = (UniqueConstraint('kind', 'value'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(Text)


class EntityAssessment(Base):
    """An analyst's verdict on an indicator: whether it is harmful, separate from whether it was copied right.

    Review (``Observation.review_status``) says a mention was extracted correctly; the verdict says what the
    indicator means. The verdict is global, but its reason may quote a restricted report, so it carries its
    own TLP label: a reader limited below that label does not see it. No row means the verdict is unknown.
    """

    __tablename__ = 'entity_assessments'
    entity_id: Mapped[str] = mapped_column(ForeignKey('entities.id'), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text, default='')
    tlp: Mapped[str] = mapped_column(String(20), default='AMBER')
    valid_until: Mapped[str | None] = mapped_column(String(40), default=None)
    decided_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80))


class Observation(Base):
    __tablename__ = 'observations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    document_id: Mapped[str] = mapped_column(ForeignKey('documents.id'), index=True)
    entity_id: Mapped[str] = mapped_column(ForeignKey('entities.id'), index=True)
    evidence: Mapped[str] = mapped_column(Text)
    start_offset: Mapped[int]
    end_offset: Mapped[int]
    review_status: Mapped[str] = mapped_column(String(20), default='unreviewed')


class DocumentTechnique(Base):
    """A MITRE ATT&CK technique on one report revision (ADR 0019).

    ``source`` is ``report`` (the ID is written in the text) or ``analyst`` (added by hand). ``status`` is
    ``tagged`` or ``removed``: a removed row is kept, so a new revision of the item does not bring it back.
    """

    __tablename__ = 'document_techniques'
    __table_args__ = (UniqueConstraint('document_id', 'technique_id'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    document_id: Mapped[str] = mapped_column(ForeignKey('documents.id'), index=True)
    technique_id: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(10), default='tagged')
    evidence: Mapped[str] = mapped_column(Text, default='')
    actor: Mapped[str] = mapped_column(String(80), default='system')
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class Note(Base):
    __tablename__ = 'notes'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    document_id: Mapped[str] = mapped_column(ForeignKey('documents.id'), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class AuditEvent(Base):
    __tablename__ = 'audit_events'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    action: Mapped[str] = mapped_column(String(50))
    object_id: Mapped[str] = mapped_column(String(36))
    detail: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    #: Who acted: ``operator`` (browser session), ``api-key:<key id>``, ``cli``, ``connector:<source>`` or
    #: ``system``. Empty for events recorded before 0005. Taken from ``Session.info['actor']`` (see services).
    actor: Mapped[str] = mapped_column(String(80), default='', server_default='')


class KEVRecord(Base):
    __tablename__ = 'kev_records'
    cve: Mapped[str] = mapped_column(String(40), primary_key=True)
    vendor: Mapped[str] = mapped_column(Text)
    product: Mapped[str] = mapped_column(Text)
    date_added: Mapped[str] = mapped_column(String(30))
    due_date: Mapped[str] = mapped_column(String(30))
    required_action: Mapped[str] = mapped_column(Text)
    imported_at: Mapped[str] = mapped_column(String(40), default=now)


class WatchTerm(Base):
    __tablename__ = 'watch_terms'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    term: Mapped[str] = mapped_column(String(120), unique=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class SourceRun(Base):
    __tablename__ = 'source_runs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source_key: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class Enrichment(Base):
    __tablename__ = 'enrichments'
    __table_args__ = (UniqueConstraint('cve', 'provider'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    cve: Mapped[str] = mapped_column(String(40), index=True)
    provider: Mapped[str] = mapped_column(String(20))
    payload: Mapped[str] = mapped_column(Text)
    fetched_at: Mapped[str] = mapped_column(String(40), default=now)


class ApiKey(Base):
    """API key for scripts and SIEM integrations. Only the SHA-256 of the key is stored (``insight.apikeys``).

    Rows are never deleted: revoked and expired keys stay as a record of what existed. At most one key is
    active (not revoked, not expired) at a time; ``services.create_api_key`` enforces this.
    """

    __tablename__ = 'api_keys'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    key_id: Mapped[str] = mapped_column(String(12), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(100))
    access: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    expires_at: Mapped[str] = mapped_column(String(40))
    last_used_at: Mapped[str | None] = mapped_column(String(40), default=None)
    revoked_at: Mapped[str | None] = mapped_column(String(40), default=None)
    #: Most restrictive TLP label this key may read or write; ``None`` means the instance limit only.
    max_tlp: Mapped[str | None] = mapped_column(String(20), default=None)


class OperatorSession(Base):
    """A signed-in browser (review B4), stored so that a restart keeps it and sign-out reaches everywhere.

    The cookie carries a random session ID. Only a hash of that ID, keyed to the current password and MFA
    setting (``services.session_binding``), is stored: the database alone cannot sign anyone in, and changing
    the password or the MFA setting ends every session. Rows are deleted when a session ends; expired ones
    are deleted at the next sign-in.
    """

    __tablename__ = 'operator_sessions'
    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    expires_at: Mapped[str] = mapped_column(String(40), index=True)


class OperatorMfa(Base):
    """The operator's TOTP second factor (at most one row; no row means MFA is off). See ``insight.totp``.

    The shared secret must be stored in a recoverable form to verify codes; protect the database accordingly.
    ``last_step`` is the 30-second time step of the last accepted code, so a code can never be used twice.
    """

    __tablename__ = 'operator_mfa'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    secret: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    last_step: Mapped[int] = mapped_column(default=0)


class Job(Base):
    """A unit of background work, such as one scheduled source sync (``insight.jobs`` runs them).

    At most one job per ``(kind, key)`` is queued or running at a time (a partial unique index), so a schedule
    and a person pressing *Sync now* never start the same source twice. Finished jobs are kept for a while as
    a record, then pruned.
    """

    __tablename__ = 'jobs'
    __table_args__ = (
        Index(
            'uq_jobs_active',
            'kind',
            'key',
            unique=True,
            sqlite_where=text("status IN ('queued', 'running')"),
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index('ix_jobs_due', 'status', 'run_after'),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(40))
    key: Mapped[str] = mapped_column(String(120))
    #: ``queued``, ``running``, ``succeeded`` or ``failed``.
    status: Mapped[str] = mapped_column(String(20))
    attempts: Mapped[int] = mapped_column(default=0)
    max_attempts: Mapped[int] = mapped_column(default=3)
    run_after: Mapped[str] = mapped_column(String(40))
    started_at: Mapped[str | None] = mapped_column(String(40), default=None)
    finished_at: Mapped[str | None] = mapped_column(String(40), default=None)
    message: Mapped[str] = mapped_column(Text, default='')
    actor: Mapped[str] = mapped_column(String(80), default='')
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class Schedule(Base):
    """How often a source syncs by itself. No row, or ``enabled`` false, means never (the default)."""

    __tablename__ = 'schedules'
    source_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    interval_minutes: Mapped[int] = mapped_column(default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    next_run_at: Mapped[str | None] = mapped_column(String(40), default=None)
    updated_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')


class FetchState(Base):
    """What a source URL returned last time, so the next fetch can be skipped when nothing changed.

    ``etag`` and ``last_modified`` go back as ``If-None-Match`` / ``If-Modified-Since``, and
    ``payload_sha256`` catches servers that ignore them. ``insight_version`` makes a new release re-read every
    source once, in case its parsing changed.
    """

    __tablename__ = 'fetch_state'
    url: Mapped[str] = mapped_column(String(500), primary_key=True)
    etag: Mapped[str] = mapped_column(String(200), default='')
    last_modified: Mapped[str] = mapped_column(String(100), default='')
    payload_sha256: Mapped[str] = mapped_column(String(64), default='')
    insight_version: Mapped[str] = mapped_column(String(40), default='')
    updated_at: Mapped[str] = mapped_column(String(40), default=now)


SessionFactory: TypeAlias = sessionmaker[Session]


def _is_memory_sqlite(url: str) -> bool:
    return url in {'sqlite://', 'sqlite:///:memory:'} or 'mode=memory' in url


def database(url: str, *, migrate: bool = True) -> tuple[Engine, SessionFactory]:
    """Create the engine and apply pending migrations (unless ``migrate=False``)."""
    is_sqlite = url.startswith('sqlite')
    options: dict[str, Any] = {}
    if is_sqlite:
        options['connect_args'] = {'check_same_thread': False}
        if _is_memory_sqlite(url):
            # Each new connection to ``:memory:`` is a brand-new empty database; share one connection.
            options['poolclass'] = StaticPool
    engine = create_engine(url, **options)
    if is_sqlite:

        @event.listens_for(engine, 'connect')
        def sqlite_config(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute('PRAGMA foreign_keys=ON')
                cursor.execute('PRAGMA busy_timeout=5000')
            finally:
                cursor.close()

    if migrate:
        from .migrations import upgrade  # Deferred: the migration environment imports this module.

        upgrade(engine)
    return engine, sessionmaker(engine, expire_on_commit=False)
