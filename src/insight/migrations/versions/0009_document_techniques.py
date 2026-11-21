"""MITRE ATT&CK techniques on reports (ADR 0019).

* ``document_techniques``: one row per report revision and technique: written in the report (``report``) or
  added by an analyst (``analyst``), tagged or removed. Existing reports get their techniques with
  ``insight attack-backfill`` (``make attack-backfill``); a migration never imports application code.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0009'
down_revision: str | None = '0008'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'document_techniques',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('technique_id', sa.String(16), nullable=False),
        sa.Column('source', sa.String(10), nullable=False),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('actor', sa.String(80), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.UniqueConstraint('document_id', 'technique_id'),
    )
    op.create_index('ix_document_techniques_document_id', 'document_techniques', ['document_id'])
    op.create_index('ix_document_techniques_technique_id', 'document_techniques', ['technique_id'])


def downgrade() -> None:
    op.drop_index('ix_document_techniques_technique_id', table_name='document_techniques')
    op.drop_index('ix_document_techniques_document_id', table_name='document_techniques')
    op.drop_table('document_techniques')
