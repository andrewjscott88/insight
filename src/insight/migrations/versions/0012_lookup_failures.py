"""CVEs a provider could not answer for, and when to try them again (code review M2).

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0012'
down_revision: str | None = '0011'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'lookup_failures',
        sa.Column('provider', sa.String(10), primary_key=True),
        sa.Column('cve', sa.String(40), primary_key=True),
        sa.Column('failures', sa.Integer(), nullable=False),
        sa.Column('message', sa.String(200), nullable=False),
        sa.Column('failed_at', sa.String(40), nullable=False),
        sa.Column('retry_at', sa.String(40), nullable=False),
    )
    op.create_index('ix_lookup_failures_retry_at', 'lookup_failures', ['retry_at'])


def downgrade() -> None:
    op.drop_index('ix_lookup_failures_retry_at', table_name='lookup_failures')
    op.drop_table('lookup_failures')
