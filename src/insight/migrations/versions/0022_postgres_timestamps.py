"""PostgreSQL stores timestamps as ``timestamptz`` (issue #11).

Every timestamp column was ISO-8601 text. On PostgreSQL it becomes ``timestamptz``, so the database
compares, sorts and indexes real moments; text without an offset is read as UTC, as Insight always meant it.
SQLite keeps the text it has (its ``DateTime`` would drop the offset). Code is unaffected:
``models.UtcTimestamp`` turns moments back into the same ISO strings.

Two columns stay text because ``''`` means "never" there: ``alerts.sent_at`` and
``alert_targets.last_sent_at``. Dates (``kev_records.date_added``, ``due_date``, hunt periods) stay text too.

The change runs in one transaction: a value PostgreSQL cannot read as a moment stops the upgrade and leaves
the database as it was, naming the column.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

import sqlalchemy as sa
from alembic import op

revision: str = '0022'
down_revision: str | None = '0021'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The timestamp columns, fixed here: a migration never imports application code.
COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    'actor_documents': ('created_at',),
    'alert_targets': ('created_at',),
    'alerts': ('next_attempt_at', 'created_at'),
    'api_keys': ('created_at', 'expires_at', 'last_used_at', 'revoked_at'),
    'audit_events': ('created_at',),
    'campaigns': ('created_at',),
    'case_items': ('added_at',),
    'cases': ('created_at', 'updated_at', 'closed_at'),
    'detection_rules': ('created_at',),
    'document_techniques': ('created_at',),
    'documents': ('created_at',),
    'enrichments': ('fetched_at',),
    'entity_assessments': ('valid_until', 'decided_at'),
    'exploit_signals': ('found_at',),
    'fetch_state': ('updated_at',),
    'hunt_checks': ('updated_at',),
    'hunts': ('created_at', 'updated_at'),
    'industry_claims': ('created_at',),
    'jobs': ('run_after', 'started_at', 'finished_at', 'created_at'),
    'kev_records': ('imported_at', 'changed_at'),
    'lookup_failures': ('failed_at', 'retry_at'),
    'notes': ('created_at',),
    'observations': ('reviewed_at',),
    'operator_mfa': ('created_at',),
    'operator_sessions': ('created_at', 'expires_at'),
    'rule_links': ('created_at',),
    'schedules': ('next_run_at', 'updated_at'),
    'source_runs': ('created_at',),
    'source_switches': ('updated_at',),
    'threat_actors': ('created_at', 'updated_at'),
    'threat_links': ('created_at',),
    'watch_terms': ('created_at',),
}
#: How a moment is written back as text on downgrade: the form ``models.now`` writes.
TEXT_FORM: Final = 'YYYY-MM-DD"T"HH24:MI:SS.US"+00:00"'


def _postgres() -> bool:
    return op.get_bind().dialect.name == 'postgresql'


def upgrade() -> None:
    if not _postgres():
        return
    op.execute(sa.text("SET LOCAL TIME ZONE 'UTC'"))  # text without an offset is UTC
    op.execute(sa.text('ALTER TABLE kev_records ALTER COLUMN changed_at DROP DEFAULT'))  # '' since 0020
    for table, columns in COLUMNS.items():
        for column in columns:
            # NULLIF: '' in a nullable column meant "not set"; in a NOT NULL column the cast then fails.
            op.execute(
                sa.text(
                    f'ALTER TABLE {table} ALTER COLUMN {column} TYPE timestamptz '
                    f"USING NULLIF({column}, '')::timestamptz"
                )
            )


def downgrade() -> None:
    if not _postgres():
        return
    for table, columns in COLUMNS.items():
        for column in columns:
            op.execute(
                sa.text(
                    f'ALTER TABLE {table} ALTER COLUMN {column} TYPE varchar(40) '
                    f"USING to_char({column} AT TIME ZONE 'UTC', '{TEXT_FORM}')"
                )
            )
    op.execute(sa.text("ALTER TABLE kev_records ALTER COLUMN changed_at SET DEFAULT ''"))
