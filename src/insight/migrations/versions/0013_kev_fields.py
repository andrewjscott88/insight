"""More of CISA's KEV fields (TIP 1.1, for TIP 1.3): the weakness name, known ransomware use, notes and CWEs.

Existing rows get empty values; the next KEV sync fills them (the whole catalog is read on every sync).

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0013'
down_revision: str | None = '0012'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLUMNS = (
    ('vulnerability_name', sa.Text()),
    ('ransomware_use', sa.String(20)),
    ('notes', sa.Text()),
    ('cwes', sa.Text()),
)


def upgrade() -> None:
    with op.batch_alter_table('kev_records') as batch:
        for name, kind in COLUMNS:
            batch.add_column(sa.Column(name, kind, nullable=False, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('kev_records') as batch:
        for name, _ in reversed(COLUMNS):
            batch.drop_column(name)
