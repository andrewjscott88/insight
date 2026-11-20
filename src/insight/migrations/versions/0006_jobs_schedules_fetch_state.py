"""Background jobs, per-source schedules and HTTP fetch state (opt-in scheduled syncs, ADR 0018).

* ``jobs``: queued, running and finished background work. At most one queued or running job per
  ``(kind, key)`` (partial unique index ``uq_jobs_active``).
* ``schedules``: how often each source syncs by itself. No rows: nothing is scheduled, as before.
* ``fetch_state``: ETag, Last-Modified and payload hash per fetched URL, so unchanged feeds are skipped.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-20
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0006'
down_revision: str | None = '0005'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTIVE = "status IN ('queued', 'running')"


def upgrade() -> None:
    op.create_table(
        'jobs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('kind', sa.String(length=40), nullable=False),
        sa.Column('key', sa.String(length=120), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('max_attempts', sa.Integer(), nullable=False),
        sa.Column('run_after', sa.String(length=40), nullable=False),
        sa.Column('started_at', sa.String(length=40), nullable=True),
        sa.Column('finished_at', sa.String(length=40), nullable=True),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('actor', sa.String(length=80), nullable=False),
        sa.Column('created_at', sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'uq_jobs_active',
        'jobs',
        ['kind', 'key'],
        unique=True,
        sqlite_where=sa.text(ACTIVE),
        postgresql_where=sa.text(ACTIVE),
    )
    op.create_index('ix_jobs_due', 'jobs', ['status', 'run_after'])
    op.create_table(
        'schedules',
        sa.Column('source_key', sa.String(length=80), nullable=False),
        sa.Column('interval_minutes', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('next_run_at', sa.String(length=40), nullable=True),
        sa.Column('updated_at', sa.String(length=40), nullable=False),
        sa.Column('actor', sa.String(length=80), nullable=False),
        sa.PrimaryKeyConstraint('source_key'),
    )
    op.create_table(
        'fetch_state',
        sa.Column('url', sa.String(length=500), nullable=False),
        sa.Column('etag', sa.String(length=200), nullable=False),
        sa.Column('last_modified', sa.String(length=100), nullable=False),
        sa.Column('payload_sha256', sa.String(length=64), nullable=False),
        sa.Column('insight_version', sa.String(length=40), nullable=False),
        sa.Column('updated_at', sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint('url'),
    )


def downgrade() -> None:
    op.drop_table('fetch_state')
    op.drop_table('schedules')
    op.drop_index('ix_jobs_due', table_name='jobs')
    op.drop_index('uq_jobs_active', table_name='jobs')
    op.drop_table('jobs')
