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
    CheckConstraint,
    Engine,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    false,
    select,
    text,
    true,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    column_property,
    mapped_column,
    sessionmaker,
    synonym,
)
from sqlalchemy.pool import StaticPool

from .extraction import EXTRACTOR_VERSION
from .schemas import most_restrictive


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


class DocumentAttachment(Base):
    """Provenance of the original uploaded file. Insight retains only its digest and metadata."""

    __tablename__ = 'document_attachments'
    document_id: Mapped[str] = mapped_column(ForeignKey('documents.id', ondelete='CASCADE'), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64))
    media_type: Mapped[str] = mapped_column(String(80))
    size_bytes: Mapped[int]
    page_count: Mapped[int]


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
    #: CISA's name for the weakness, such as "Palo Alto Networks PAN-OS Command Injection Vulnerability".
    vulnerability_name: Mapped[str] = mapped_column(Text, default='', server_default='')
    #: ``knownRansomwareCampaignUse``: ``Known`` or ``Unknown`` (``''`` before migration 0013's first import).
    ransomware_use: Mapped[str] = mapped_column(String(20), default='', server_default='')
    notes: Mapped[str] = mapped_column(Text, default='', server_default='')
    #: Weakness types (``CWE-78``), comma-separated.
    cwes: Mapped[str] = mapped_column(Text, default='', server_default='')

    @property
    def ransomware(self) -> bool:
        return self.ransomware_use == 'Known'


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
    """One provider's cached context. The legacy cve column also holds IP entity UUIDs for GreyNoise."""

    __tablename__ = 'enrichments'
    __table_args__ = (UniqueConstraint('cve', 'provider'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    cve: Mapped[str] = mapped_column(String(40), index=True)
    subject = synonym('cve')
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


class AlertTarget(Base):
    """Where alerts go: a webhook (JSON or chat style) or an e-mail address (ADR 0022).

    Set only from the workspace, never with an API key. ``secret`` signs JSON webhooks; ``max_tlp`` is the
    most restrictive label whose report titles may be sent there (stricter reports are announced untitled).
    """

    __tablename__ = 'alert_targets'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(10))  # webhook | email
    style: Mapped[str] = mapped_column(String(10))  # json | chat | email
    address: Mapped[str] = mapped_column(String(2048))
    secret: Mapped[str] = mapped_column(String(80), default='')
    max_tlp: Mapped[str] = mapped_column(String(20), default='AMBER')
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')
    last_status: Mapped[str] = mapped_column(String(10), default='')
    last_sent_at: Mapped[str] = mapped_column(String(40), default='')
    last_error: Mapped[str] = mapped_column(String(300), default='')


class Alert(Base):
    """One alert for one target: queued when it fires, then sent by the job runner (``insight.alerts``).

    ``dedupe_key`` makes an alert fire once per target: a new revision of the same item, or the same KEV entry
    seen again, adds nothing.
    """

    __tablename__ = 'alerts'
    __table_args__ = (
        UniqueConstraint('target_id', 'dedupe_key'),
        Index('ix_alerts_due', 'status', 'next_attempt_at'),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    target_id: Mapped[str] = mapped_column(ForeignKey('alert_targets.id'), index=True)
    trigger: Mapped[str] = mapped_column(String(10))  # watch | kev | test
    dedupe_key: Mapped[str] = mapped_column(String(300))
    subject: Mapped[str] = mapped_column(String(200))
    document_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(10), default='pending')  # pending | sent | failed
    attempts: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[str] = mapped_column(String(40), default=now)
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    sent_at: Mapped[str] = mapped_column(String(40), default='')
    error: Mapped[str] = mapped_column(String(300), default='')


class SourceSwitch(Base):
    """Whether the operator uses a curated source. No row means its default: on, except optional sources."""

    __tablename__ = 'source_switches'
    source_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    updated_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')


class LookupFailure(Base):
    """A CVE a provider could not answer for (review M2): it is not looked up by itself again until
    ``retry_at`` (1 hour after the first failure, doubling up to 7 days), so it cannot hold up the rest."""

    __tablename__ = 'lookup_failures'
    provider: Mapped[str] = mapped_column(String(10), primary_key=True)
    cve: Mapped[str] = mapped_column(String(40), primary_key=True)
    failures: Mapped[int] = mapped_column(default=1)
    message: Mapped[str] = mapped_column(String(200), default='')
    failed_at: Mapped[str] = mapped_column(String(40), default=now)
    retry_at: Mapped[str] = mapped_column(String(40), index=True)


class ThreatActor(Base):
    """A threat actor the analyst created (TIP 2.5, minimum for TIP 2.10; ADR 0025).

    Insight never creates one by itself, and never from shared indicators. ``attack_group_id`` optionally
    says which MITRE ATT&CK group (``G0016``) the analyst considers the same actor: the guide then shows that
    group's catalog data, labelled as coming from ATT&CK. ``aliases`` is one name per line.
    """

    __tablename__ = 'threat_actors'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    aliases: Mapped[str] = mapped_column(Text, default='')
    description: Mapped[str] = mapped_column(Text, default='')
    attack_group_id: Mapped[str | None] = mapped_column(String(10), default=None)
    tlp: Mapped[str] = mapped_column(String(20), default='AMBER')
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    updated_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')


class ActorDocument(Base):
    """A report the analyst linked to a group (``group_ref``: an ATT&CK ID such as ``G0016``, or a
    :class:`ThreatActor` ID). An explicit analyst decision, never inferred."""

    __tablename__ = 'actor_documents'
    __table_args__ = (UniqueConstraint('group_ref', 'document_id'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    group_ref: Mapped[str] = mapped_column(String(36), index=True)
    document_id: Mapped[str] = mapped_column(ForeignKey('documents.id'), index=True)
    tlp: Mapped[str] = mapped_column(String(20), default='CLEAR', server_default='CLEAR')
    note: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')


class Campaign(Base):
    """A campaign an analyst explicitly tracks."""

    __tablename__ = 'campaigns'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    aliases: Mapped[str] = mapped_column(Text, default='')
    description: Mapped[str] = mapped_column(Text, default='')
    tlp: Mapped[str] = mapped_column(String(20), default='AMBER')
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')


class ThreatLink(Base):
    """One explicit link. Actor/report links stay in actor_documents for existing guides."""

    __tablename__ = 'threat_links'
    __table_args__ = (
        CheckConstraint('(actor_id IS NULL) <> (campaign_id IS NULL)', name='one_threat_subject'),
        CheckConstraint(
            '(CASE WHEN document_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN entity_id IS NULL THEN 0 ELSE 1 END + '
            'CASE WHEN technique_id IS NULL THEN 0 ELSE 1 END) = 1',
            name='one_threat_target',
        ),
        CheckConstraint('actor_id IS NULL OR document_id IS NULL', name='existing_actor_reports'),
        UniqueConstraint('actor_id', 'entity_id'),
        UniqueConstraint('actor_id', 'technique_id'),
        UniqueConstraint('campaign_id', 'document_id'),
        UniqueConstraint('campaign_id', 'entity_id'),
        UniqueConstraint('campaign_id', 'technique_id'),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str | None] = mapped_column(
        ForeignKey('threat_actors.id', ondelete='CASCADE'), index=True
    )
    campaign_id: Mapped[str | None] = mapped_column(
        ForeignKey('campaigns.id', ondelete='CASCADE'), index=True
    )
    document_id: Mapped[str | None] = mapped_column(
        ForeignKey('documents.id', ondelete='CASCADE'), index=True
    )
    entity_id: Mapped[str | None] = mapped_column(ForeignKey('entities.id', ondelete='CASCADE'), index=True)
    technique_id: Mapped[str | None] = mapped_column(String(16), index=True)
    tlp: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')


class IndustryClaim(Base):
    """The analyst's own industry mapping for a group: ``added`` with a citation, or ``removed`` (a catalog
    claim the analyst disagrees with, with the reason). Labelled TLP because the reason may quote a report."""

    __tablename__ = 'industry_claims'
    __table_args__ = (UniqueConstraint('group_ref', 'industry'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    group_ref: Mapped[str] = mapped_column(String(36), index=True)
    industry: Mapped[str] = mapped_column(String(40))
    decision: Mapped[str] = mapped_column(String(10))  # added | removed
    citation_url: Mapped[str] = mapped_column(Text, default='')
    document_id: Mapped[str | None] = mapped_column(ForeignKey('documents.id'), default=None)
    reason: Mapped[str] = mapped_column(Text, default='')
    tlp: Mapped[str] = mapped_column(String(20), default='AMBER')
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')
    subject_tlp = column_property(
        select(ThreatActor.tlp)
        .where(ThreatActor.id == group_ref)
        .correlate_except(ThreatActor)
        .scalar_subquery()
    )
    source_tlp = column_property(
        select(Document.tlp).where(Document.id == document_id).correlate_except(Document).scalar_subquery()
    )

    @property
    def effective_tlp(self) -> str:
        return most_restrictive(self.tlp, self.source_tlp or 'CLEAR', self.subject_tlp or 'CLEAR')


class DetectionRule(Base):
    """A YARA or Sigma rule carried as text (TIP 2.7, minimum for TIP 2.10). Insight never runs it."""

    __tablename__ = 'detection_rules'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(10))  # yara | sigma
    name: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str] = mapped_column(Text, default='')
    licence: Mapped[str] = mapped_column(String(120), default='')
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    tlp: Mapped[str] = mapped_column(String(20), default='AMBER')
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')


class RuleLink(Base):
    """An explicit rule association with a group, technique, report, CVE or malware family."""

    __tablename__ = 'rule_links'
    __table_args__ = (UniqueConstraint('rule_id', 'target_kind', 'target_id'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    rule_id: Mapped[str] = mapped_column(ForeignKey('detection_rules.id'), index=True)
    target_kind: Mapped[str] = mapped_column(String(12))
    target_id: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')


class Hunt(Base):
    """A threat hunt started from a group's threat guide (TIP 2.10): the record that makes it repeatable."""

    __tablename__ = 'hunts'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    group_ref: Mapped[str] = mapped_column(String(36), index=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(10), default='open')  # open | closed
    summary: Mapped[str] = mapped_column(Text, default='')
    tlp: Mapped[str] = mapped_column(String(20), default='AMBER')
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    updated_at: Mapped[str] = mapped_column(String(40), default=now)
    actor: Mapped[str] = mapped_column(String(80), default='')
    subject_tlp = column_property(
        select(ThreatActor.tlp)
        .where(ThreatActor.id == group_ref)
        .correlate_except(ThreatActor)
        .scalar_subquery()
    )

    @property
    def effective_tlp(self) -> str:
        return most_restrictive(self.tlp, self.subject_tlp or 'CLEAR')


class HuntCheck(Base):
    """One hypothesis of a hunt (one ATT&CK technique): what was checked, when, and the result."""

    __tablename__ = 'hunt_checks'
    __table_args__ = (UniqueConstraint('hunt_id', 'technique_id'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    hunt_id: Mapped[str] = mapped_column(ForeignKey('hunts.id'), index=True)
    technique_id: Mapped[str] = mapped_column(String(16))
    #: ``not-checked``, ``nothing-found``, ``suspicious`` or ``confirmed``.
    result: Mapped[str] = mapped_column(String(20), default='not-checked')
    data_checked: Mapped[str] = mapped_column(Text, default='')
    period_start: Mapped[str] = mapped_column(String(40), default='')
    period_end: Mapped[str] = mapped_column(String(40), default='')
    notes: Mapped[str] = mapped_column(Text, default='')
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


def shares_one_connection(factory: SessionFactory) -> bool:
    """Whether every session of ``factory`` uses the same connection (in-memory SQLite), which two threads
    must never use at once: the job runner's lanes then take turns instead of running side by side (L5)."""
    engine = factory.kw.get('bind')
    return isinstance(getattr(engine, 'pool', None), StaticPool)


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
