"""Record when a mention was last reviewed, so TAXII clients can poll for newly accepted indicators.

Existing rows keep ``NULL``: their report's arrival time stands in for it (ADR 0026).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0018'
down_revision: str | None = '0017'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('observations') as batch:
        batch.add_column(sa.Column('reviewed_at', sa.String(40), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('observations') as batch:
        batch.drop_column('reviewed_at')
