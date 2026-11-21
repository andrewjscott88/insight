"""Switching curated sources on and off (ADR 0021).

* ``source_switches``: one row per source the operator switched on or off. No row means the source's default:
  on for the sources Insight has always had, off for the optional threat-research and news sources.

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0010'
down_revision: str | None = '0009'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'source_switches',
        sa.Column('source_key', sa.String(80), primary_key=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('updated_at', sa.String(40), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('source_switches')
