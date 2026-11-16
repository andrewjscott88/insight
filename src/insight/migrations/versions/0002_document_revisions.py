"""Document revisions: stable source identity for synced items.

Adds ``source_key``/``external_id`` (e.g. ``('cisa-kev', 'CVE-2024-3400')``), ``is_current`` and
``supersedes_id``, plus a partial unique index allowing only one *current* document per source item.

Backfill: existing KEV documents are keyed by the CVE in their title and RSS documents by their link. Where
0.1.0 already created duplicates (publisher edits), the newest becomes current and older ones become linked,
non-current revisions. Nothing is deleted.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-12
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from itertools import pairwise

import sqlalchemy as sa
from alembic import op

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Snapshot of the 0.1.0 source registry. Migrations must not import application code that may change later.
KEV_SOURCE_NAME = 'CISA Known Exploited Vulnerabilities'
RSS_SOURCE_NAMES = {
    'CISA Cybersecurity Advisories': 'cisa-advisories',
    'SANS Internet Storm Center': 'sans-isc',
    'UK NCSC Reports': 'ncsc',
}
KEV_TITLE = re.compile(r'^(CVE-\d{4}-\d{4,}) ·')
INDEX = 'uq_documents_current_source_item'


def upgrade() -> None:
    with op.batch_alter_table('documents') as batch:
        batch.add_column(sa.Column('source_key', sa.String(80), nullable=True))
        batch.add_column(sa.Column('external_id', sa.String(500), nullable=True))
        batch.add_column(sa.Column('is_current', sa.Boolean(), nullable=False, server_default=sa.true()))
        batch.add_column(sa.Column('supersedes_id', sa.String(36), nullable=True))
        batch.create_foreign_key('fk_documents_supersedes_id', 'documents', ['supersedes_id'], ['id'])

    _backfill(op.get_bind())

    op.create_index(
        INDEX,
        'documents',
        ['source_key', 'external_id'],
        unique=True,
        sqlite_where=sa.text('is_current = 1 AND external_id IS NOT NULL'),
        postgresql_where=sa.text('is_current AND external_id IS NOT NULL'),
    )


def _backfill(bind: sa.Connection) -> None:
    documents = sa.table(
        'documents',
        sa.column('id', sa.String),
        sa.column('title', sa.String),
        sa.column('source_name', sa.String),
        sa.column('source_url', sa.Text),
        sa.column('created_at', sa.String),
        sa.column('source_key', sa.String),
        sa.column('external_id', sa.String),
        sa.column('is_current', sa.Boolean),
        sa.column('supersedes_id', sa.String),
    )
    rows = bind.execute(
        sa.select(documents.c.id, documents.c.title, documents.c.source_name, documents.c.source_url)
        .where(documents.c.source_name.in_([KEV_SOURCE_NAME, *RSS_SOURCE_NAMES]))
        .order_by(documents.c.created_at, documents.c.id)
    ).all()
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for doc_id, title, source_name, source_url in rows:
        if source_name == KEV_SOURCE_NAME:
            match = KEV_TITLE.match(title)
            key = ('cisa-kev', match.group(1)) if match else None
        else:
            key = (RSS_SOURCE_NAMES[source_name], source_url) if source_url else None
        if key is None:
            continue
        groups[key].append(doc_id)
        bind.execute(
            documents.update()
            .where(documents.c.id == doc_id)
            .values(source_key=key[0], external_id=key[1][:500])
        )
    for ids in groups.values():  # oldest first; the newest revision stays current
        for previous, newer in pairwise(ids):
            bind.execute(documents.update().where(documents.c.id == previous).values(is_current=False))
            bind.execute(documents.update().where(documents.c.id == newer).values(supersedes_id=previous))


def downgrade() -> None:
    op.drop_index(INDEX, table_name='documents')
    with op.batch_alter_table('documents') as batch:
        batch.drop_constraint('fk_documents_supersedes_id', type_='foreignkey')
        batch.drop_column('supersedes_id')
        batch.drop_column('is_current')
        batch.drop_column('external_id')
        batch.drop_column('source_key')
