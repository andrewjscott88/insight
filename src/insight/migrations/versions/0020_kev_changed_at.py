"""Record when a KEV entry last changed, so the TAXII KEV collection can be polled (ADR 0026).

``imported_at`` is rewritten at every sync, so it cannot say when an entry changed. Existing rows start with
their last import time.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0020'
down_revision: str | None = '0019'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('kev_records') as batch:
        batch.add_column(sa.Column('changed_at', sa.String(40), nullable=False, server_default=''))
    op.execute(sa.text('UPDATE kev_records SET changed_at = imported_at'))


def downgrade() -> None:
    with op.batch_alter_table('kev_records') as batch:
        batch.drop_column('changed_at')
