"""add_case_collaboration

Findings, notes, host assignments and an activity feed per case (job), for the case browser
(case_routes.py). A finding references a row of the case's output by file, row and hash;
nothing here copies or changes evidence. Databases that ran this branch before Alembic was in
the images got these tables through create_all, so each is skipped when it exists.

Revision ID: 4d8b1f6e2c57
Revises: 7c41d2e9a0b3
Create Date: 2026-10-28 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4d8b1f6e2c57'
down_revision = '7c41d2e9a0b3'
branch_labels = None
depends_on = None


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if 'case_findings' not in existing:
        _findings()
    if 'case_notes' not in existing:
        _notes()
    if 'case_hosts' not in existing:
        _hosts()
    if 'case_activity' not in existing:
        _activity()


def _findings():
    op.create_table(
        'case_findings',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('job_id', sa.String(), nullable=False),
        sa.Column('host', sa.String(), nullable=False),
        sa.Column('artefact', sa.Text(), nullable=False),
        sa.Column('row_ref', sa.String(), nullable=False),
        sa.Column('row_hash', sa.String(), nullable=False),
        sa.Column('excerpt', sa.Text(), nullable=True),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('technique', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('author', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index(op.f('ix_case_findings_job_id'), 'case_findings', ['job_id'])


def _notes():
    op.create_table(
        'case_notes',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('job_id', sa.String(), nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=True),
        sa.Column('author', sa.String(), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index(op.f('ix_case_notes_job_id'), 'case_notes', ['job_id'])
    op.create_index(op.f('ix_case_notes_finding_id'), 'case_notes', ['finding_id'])


def _hosts():
    op.create_table(
        'case_hosts',
        sa.Column('job_id', sa.String(), primary_key=True),
        sa.Column('host', sa.String(), primary_key=True),
        sa.Column('assignee', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('updated_by', sa.String(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )


def _activity():
    op.create_table(
        'case_activity',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('job_id', sa.String(), nullable=False),
        sa.Column('actor', sa.String(), nullable=False),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index(op.f('ix_case_activity_job_id'), 'case_activity', ['job_id'])
    op.create_index(op.f('ix_case_activity_created_at'), 'case_activity', ['created_at'])


def downgrade():
    op.drop_index(op.f('ix_case_activity_created_at'), table_name='case_activity')
    op.drop_index(op.f('ix_case_activity_job_id'), table_name='case_activity')
    op.drop_table('case_activity')
    op.drop_table('case_hosts')
    op.drop_index(op.f('ix_case_notes_finding_id'), table_name='case_notes')
    op.drop_index(op.f('ix_case_notes_job_id'), table_name='case_notes')
    op.drop_table('case_notes')
    op.drop_index(op.f('ix_case_findings_job_id'), table_name='case_findings')
    op.drop_table('case_findings')
