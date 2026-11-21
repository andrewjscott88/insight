"""Keep the original PDF's digest and size with its report. Raw bytes are never persisted."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0016'
down_revision: str | None = '0015'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'document_attachments',
        sa.Column(
            'document_id', sa.String(36), sa.ForeignKey('documents.id', ondelete='CASCADE'), primary_key=True
        ),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('media_type', sa.String(80), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('page_count', sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('document_attachments')
