"""Alerts for watch-term matches and new KEV entries (ADR 0022).

* ``alert_targets``: where alerts go (webhook or e-mail), set from the workspace only.
* ``alerts``: one row per alert per target, unique by ``(target_id, dedupe_key)``, sent by the job runner.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0011'
down_revision: str | None = '0010'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'alert_targets',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(80), nullable=False),
        sa.Column('kind', sa.String(10), nullable=False),
        sa.Column('style', sa.String(10), nullable=False),
        sa.Column('address', sa.String(2048), nullable=False),
        sa.Column('secret', sa.String(80), nullable=False),
        sa.Column('max_tlp', sa.String(20), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.Column('last_status', sa.String(10), nullable=False),
        sa.Column('last_sent_at', sa.String(40), nullable=False),
        sa.Column('last_error', sa.String(300), nullable=False),
    )
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('target_id', sa.String(36), sa.ForeignKey('alert_targets.id'), nullable=False),
        sa.Column('trigger', sa.String(10), nullable=False),
        sa.Column('dedupe_key', sa.String(300), nullable=False),
        sa.Column('subject', sa.String(200), nullable=False),
        sa.Column('document_id', sa.String(36), nullable=True),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('next_attempt_at', sa.String(40), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('sent_at', sa.String(40), nullable=False),
        sa.Column('error', sa.String(300), nullable=False),
        sa.UniqueConstraint('target_id', 'dedupe_key'),
    )
    op.create_index('ix_alerts_target_id', 'alerts', ['target_id'])
    op.create_index('ix_alerts_due', 'alerts', ['status', 'next_attempt_at'])


def downgrade() -> None:
    op.drop_index('ix_alerts_due', table_name='alerts')
    op.drop_index('ix_alerts_target_id', table_name='alerts')
    op.drop_table('alerts')
    op.drop_table('alert_targets')
