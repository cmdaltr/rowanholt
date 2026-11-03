"""jobs_baseline

The jobs table as JobStorage (storage.py) has always created it. Databases from before
Alembic ran already have it, so it's only created when missing, and those databases are
simply stamped from here on.

The history before this (users, accounts, sessions, a jobs table with user_id) described
the database-backed sign-in in models/database.py, which was never switched on; sign-in
uses auth/users.py, and no database ever ran those revisions.

Revision ID: 3e5a9c1b7d20
Revises:
Create Date: 2026-10-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '3e5a9c1b7d20'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create jobs if this database doesn't have it yet."""
    if 'jobs' in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        'jobs',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('case_number', sa.String(), nullable=False),
        sa.Column('source_paths', sa.JSON(), nullable=False),
        sa.Column('destination_path', sa.String(), nullable=True),
        sa.Column('options', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('progress', sa.Integer(), nullable=True),
        sa.Column('log', sa.JSON(), nullable=True),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('celery_task_id', sa.String(), nullable=True),
        sa.Column('pending_action', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )
    op.create_index(op.f('ix_jobs_case_number'), 'jobs', ['case_number'], unique=False)
    op.create_index(op.f('ix_jobs_status'), 'jobs', ['status'], unique=False)
    op.create_index(op.f('ix_jobs_created_at'), 'jobs', ['created_at'], unique=False)


def downgrade() -> None:
    """Drop jobs."""
    op.drop_index(op.f('ix_jobs_created_at'), table_name='jobs')
    op.drop_index(op.f('ix_jobs_status'), table_name='jobs')
    op.drop_index(op.f('ix_jobs_case_number'), table_name='jobs')
    op.drop_table('jobs')
