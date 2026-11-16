"""Folded search text and connector truncation flag.

* ``documents.search_text``: case-, accent- and width-folded copy of title, source name and body. Search
  matches against it, so behaviour is identical on SQLite (whose ``lower()`` only folds ASCII) and PostgreSQL,
  and independent of Unicode normal form (``café`` typed as NFC finds text stored as NFD).
* ``documents.truncated``: set when a connector had to shorten the publisher's text.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-12
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BATCH = 500
_ZERO_WIDTH = frozenset('\u200b\u200c\u200d\u2060\ufeff\u00ad')


def _fold(text: str) -> str:
    """Snapshot of ``insight.services.fold`` at this revision (migrations never import app code)."""
    decomposed = unicodedata.normalize('NFKD', text)
    kept = ''.join(c for c in decomposed if not unicodedata.combining(c) and c not in _ZERO_WIDTH)
    return unicodedata.normalize('NFC', kept.casefold())


def upgrade() -> None:
    with op.batch_alter_table('documents') as batch:
        batch.add_column(sa.Column('search_text', sa.Text(), nullable=False, server_default=''))
        batch.add_column(sa.Column('truncated', sa.Boolean(), nullable=False, server_default=sa.false()))
    documents = sa.table(
        'documents',
        sa.column('id', sa.String),
        sa.column('title', sa.String),
        sa.column('source_name', sa.String),
        sa.column('body', sa.Text),
        sa.column('search_text', sa.Text),
    )
    bind = op.get_bind()
    last_id = ''
    while True:
        rows = bind.execute(
            sa.select(documents.c.id, documents.c.title, documents.c.source_name, documents.c.body)
            .where(documents.c.id > last_id)
            .order_by(documents.c.id)
            .limit(BATCH)
        ).all()
        if not rows:
            break
        for doc_id, title, source_name, body in rows:
            folded = _fold(f'{title}\n{source_name}\n{body}')
            bind.execute(documents.update().where(documents.c.id == doc_id).values(search_text=folded))
        last_id = rows[-1][0]


def downgrade() -> None:
    with op.batch_alter_table('documents') as batch:
        batch.drop_column('truncated')
        batch.drop_column('search_text')
