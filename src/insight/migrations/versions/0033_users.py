"""People who sign in through an identity provider, and the person behind each session (ADR 0046).

* ``users``: one row per person (the provider's issuer and subject), with a role (``viewer``, ``analyst`` or
  ``admin``; empty while waiting for approval), whether provider groups set that role, and a disabled flag.
* ``operator_sessions.user_id``: who signed in; empty for the built-in operator's password sign-in, so every
  existing session stays the operator's and keeps the admin role.

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0033'
down_revision: str | None = '0032'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Named, so SQLite's batch mode can add and drop it (the model uses the same name).
FOREIGN_KEY = 'fk_operator_sessions_user_id_users'


def upgrade() -> None:
    timestamp = sa.String(40).with_variant(sa.TIMESTAMP(timezone=True), 'postgresql')
    op.create_table(
        'users',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('issuer', sa.String(500), nullable=False),
        sa.Column('subject', sa.String(255), nullable=False),
        sa.Column('email', sa.String(320), nullable=False, server_default=''),
        sa.Column('display_name', sa.String(200), nullable=False, server_default=''),
        sa.Column('role', sa.String(20), nullable=True),
        sa.Column('role_from_groups', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('disabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('first_sign_in_at', timestamp, nullable=False),
        sa.Column('last_sign_in_at', timestamp, nullable=False),
        sa.UniqueConstraint('issuer', 'subject'),
    )
    with op.batch_alter_table('operator_sessions') as batch:
        batch.add_column(sa.Column('user_id', sa.String(36), nullable=True))
        batch.create_foreign_key(FOREIGN_KEY, 'users', ['user_id'], ['id'], ondelete='CASCADE')
        batch.create_index('ix_operator_sessions_user_id', ['user_id'])


def downgrade() -> None:
    # Without the column, a person's session would read as the operator's (an admin): end them first.
    sessions = sa.table('operator_sessions', sa.column('user_id'))
    op.get_bind().execute(sessions.delete().where(sessions.c.user_id.is_not(None)))
    with op.batch_alter_table('operator_sessions') as batch:
        batch.drop_index('ix_operator_sessions_user_id')
        batch.drop_constraint(FOREIGN_KEY, type_='foreignkey')
        batch.drop_column('user_id')
    op.drop_table('users')
