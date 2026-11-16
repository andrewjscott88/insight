"""Baseline: the exact schema shipped in 0.1.0 (previously created with ``create_all``).

Revision ID: 0001
Revises:
Create Date: 2026-11-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('object_id', sa.String(36), nullable=False),
        sa.Column('detail', sa.Text(), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
    )
    op.create_table(
        'documents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('fingerprint', sa.String(64), nullable=False, unique=True),
        sa.Column('content_hash', sa.String(64), nullable=False),
        sa.Column('title', sa.String(300), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('source_name', sa.String(160), nullable=False),
        sa.Column('source_url', sa.Text(), nullable=False),
        sa.Column('tlp', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
        sa.Column('extractor_version', sa.String(40), nullable=False),
    )
    op.create_index('ix_documents_content_hash', 'documents', ['content_hash'])
    op.create_table(
        'enrichments',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('cve', sa.String(40), nullable=False),
        sa.Column('provider', sa.String(20), nullable=False),
        sa.Column('payload', sa.Text(), nullable=False),
        sa.Column('fetched_at', sa.String(40), nullable=False),
        sa.UniqueConstraint('cve', 'provider'),
    )
    op.create_index('ix_enrichments_cve', 'enrichments', ['cve'])
    op.create_table(
        'entities',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('kind', sa.String(20), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.UniqueConstraint('kind', 'value'),
    )
    op.create_table(
        'kev_records',
        sa.Column('cve', sa.String(40), primary_key=True),
        sa.Column('vendor', sa.Text(), nullable=False),
        sa.Column('product', sa.Text(), nullable=False),
        sa.Column('date_added', sa.String(30), nullable=False),
        sa.Column('due_date', sa.String(30), nullable=False),
        sa.Column('required_action', sa.Text(), nullable=False),
        sa.Column('imported_at', sa.String(40), nullable=False),
    )
    op.create_table(
        'source_runs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('source_key', sa.String(80), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
    )
    op.create_index('ix_source_runs_source_key', 'source_runs', ['source_key'])
    op.create_table(
        'watch_terms',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('term', sa.String(120), nullable=False, unique=True),
        sa.Column('created_at', sa.String(40), nullable=False),
    )
    op.create_table(
        'notes',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_at', sa.String(40), nullable=False),
    )
    op.create_index('ix_notes_document_id', 'notes', ['document_id'])
    op.create_table(
        'observations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('entity_id', sa.String(36), sa.ForeignKey('entities.id'), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('start_offset', sa.Integer(), nullable=False),
        sa.Column('end_offset', sa.Integer(), nullable=False),
        sa.Column('review_status', sa.String(20), nullable=False),
    )
    op.create_index('ix_observations_document_id', 'observations', ['document_id'])
    op.create_index('ix_observations_entity_id', 'observations', ['entity_id'])


def downgrade() -> None:
    for table in (
        'observations',
        'notes',
        'watch_terms',
        'source_runs',
        'kev_records',
        'entities',
        'enrichments',
        'documents',
        'audit_events',
    ):
        op.drop_table(table)
