"""Operator-defined TAXII collections and persistent STIX publisher restrictions (TIP 4.5)."""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = '0032'
down_revision: str | None = '0031'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('operator_sources', sa.Column('collection_id', sa.String(250), nullable=True))
    op.add_column('operator_sources', sa.Column('credential_env', sa.String(55), nullable=True))
    op.add_column(
        'documents',
        sa.Column(
            'operator_publisher_metadata_only', sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )


def downgrade() -> None:
    conn = op.get_bind()
    sources = sa.table('operator_sources', sa.column('key'), sa.column('kind'), sa.column('reuse'))
    docs = sa.table(
        'documents',
        sa.column('source_key'),
        sa.column('external_id'),
        sa.column('operator_publisher_metadata_only'),
        sa.column('reuse_changed_at'),
    )
    dropping = sa.select(sources.c.key).where(sources.c.kind == 'taxii')
    retained = sa.select(sources.c.key).where(sources.c.kind != 'taxii')
    stamp = datetime.now(UTC).isoformat()
    # In 0031 unrecognized operator keys are metadata-only. Mark newly restricted public reports as
    # changed for clients polling by modification time. Already restricted reports retain their date.
    conn.execute(
        docs.update()
        .where(
            docs.c.source_key.in_(dropping.where(sources.c.reuse == 'public')),
            docs.c.operator_publisher_metadata_only.is_(False),
        )
        .values(reuse_changed_at=stamp)
    )
    # A collection may already have become an RSS source, even a public one. Quarantine just publisher-
    # restricted item histories from that feed; preserve the source key in a namespace no source can claim.
    protected = (docs.c.source_key.in_(retained), docs.c.operator_publisher_metadata_only.is_(True))
    while items := conn.execute(
        sa.select(docs.c.source_key, docs.c.external_id)
        .where(*protected, docs.c.external_id.is_not(None))
        .distinct()
        .limit(200)
    ).all():
        for key, item in items:
            conn.execute(
                docs.update()
                .where(docs.c.source_key == key, docs.c.external_id == item)
                .values(source_key=f'op-publisher-restricted:{key}', reuse_changed_at=stamp)
            )
    conn.execute(
        docs.update()
        .where(*protected, docs.c.external_id.is_(None))
        .values(
            source_key=sa.literal('op-publisher-restricted:').concat(docs.c.source_key),
            reuse_changed_at=stamp,
        )
    )
    for table, column in (
        ('source_switches', 'source_key'),
        ('schedules', 'source_key'),
        ('fetch_state', 'url'),
        ('source_runs', 'source_key'),
    ):
        target = sa.table(table, sa.column(column))
        conn.execute(target.delete().where(target.c[column].in_(dropping)))
    jobs = sa.table('jobs', sa.column('kind'), sa.column('key'))
    conn.execute(jobs.delete().where(jobs.c.kind == 'source.sync', jobs.c.key.in_(dropping)))
    conn.execute(sources.delete().where(sources.c.kind == 'taxii'))
    with op.batch_alter_table('operator_sources') as batch:
        batch.drop_column('credential_env')
        batch.drop_column('collection_id')
    with op.batch_alter_table('documents') as batch:
        batch.drop_column('operator_publisher_metadata_only')
