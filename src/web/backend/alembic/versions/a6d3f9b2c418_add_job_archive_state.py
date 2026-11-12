"""add_job_archive_state

When a job was archived, and the status it had before (archived_at, archived_from on jobs).
Without the second, restoring a job read its old status back from what the job held, and a
cancelled job (a cancel sets completed_at) came back as completed. Jobs archived before this have
neither: restoring them still reads the status from the job (main._unarchived_status).

A database built by create_all already has both columns, so each is added only when missing.
Downgrading drops them; a job archived meanwhile is then restored by the old rule.

Revision ID: a6d3f9b2c418
Revises: e8c3a1f5b927
Create Date: 2026-11-12 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a6d3f9b2c418'
down_revision = 'e8c3a1f5b927'
branch_labels = None
depends_on = None

COLUMNS = (
    ('archived_at', sa.DateTime()),
    ('archived_from', sa.String()),
)


def _existing() -> set:
    return {column['name'] for column in sa.inspect(op.get_bind()).get_columns('jobs')}


def upgrade():
    missing = [(name, kind) for name, kind in COLUMNS if name not in _existing()]
    if not missing:
        return
    with op.batch_alter_table('jobs') as batch:
        for name, kind in missing:
            batch.add_column(sa.Column(name, kind, nullable=True))


def downgrade():
    present = [name for name, _ in COLUMNS if name in _existing()]
    if not present:
        return
    with op.batch_alter_table('jobs') as batch:
        for name in present:
            batch.drop_column(name)
