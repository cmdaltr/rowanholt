"""add_ostraka_pairing

Pairing with Ostraka (docs/suite/INTEGRATION.md): the pairing_codes table, where each code is kept
only as its SHA-256 with who made it, when it expires and what its one claim made (a token and a
webhook); and external_ref on jobs, the Ostraka reference a job was started for.

A database built by create_all already has both, so each is added only when missing. Downgrading
drops them.

Revision ID: b9d4e2f7a1c3
Revises: a6d3f9b2c418
Create Date: 2026-11-23 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b9d4e2f7a1c3'
down_revision = 'a6d3f9b2c418'
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def upgrade():
    inspector = _inspector()
    if 'pairing_codes' not in inspector.get_table_names():
        op.create_table(
            'pairing_codes',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('code_hash', sa.String(), nullable=False, unique=True),
            sa.Column('note', sa.String(), nullable=False, server_default=''),
            sa.Column('created_by_id', sa.String(), nullable=False),
            sa.Column('created_by', sa.String(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('claimed_at', sa.DateTime(), nullable=True),
            sa.Column('claimed_by_name', sa.String(), nullable=True),
            sa.Column('token_id', sa.String(), nullable=True),
            sa.Column('webhook_id', sa.String(), nullable=True),
        )
    if 'external_ref' not in {column['name'] for column in inspector.get_columns('jobs')}:
        with op.batch_alter_table('jobs') as batch:
            batch.add_column(sa.Column('external_ref', sa.String(), nullable=True))
            batch.create_index(op.f('ix_jobs_external_ref'), ['external_ref'])


def downgrade():
    inspector = _inspector()
    if 'external_ref' in {column['name'] for column in inspector.get_columns('jobs')}:
        with op.batch_alter_table('jobs') as batch:
            batch.drop_index(op.f('ix_jobs_external_ref'))
            batch.drop_column('external_ref')
    if 'pairing_codes' in inspector.get_table_names():
        op.drop_table('pairing_codes')
