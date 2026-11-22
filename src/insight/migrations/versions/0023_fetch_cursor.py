"""Where a paged feed resumes (issue #11): OTX keeps its ``modified_since`` cursor and next page here, so a
sync that stops early (a failure or the page limit) continues where it stopped.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0023'
down_revision: str | None = '0022'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('fetch_state') as batch:
        batch.add_column(sa.Column('cursor', sa.Text(), nullable=False, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('fetch_state') as batch:
        batch.drop_column('cursor')
