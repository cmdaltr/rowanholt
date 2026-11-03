"""add_threat_intel_validity

How long each threat intelligence indicator holds (dernvale/threat_intel/validity.py): a STIX
indicator's valid_until and confidence, or a default lifetime by kind (90 days for IPs and
domains), with when it was first seen. A side table keyed by threat_intel_indicators.id, so the
fixed 10-column table stays as it is; no row means no expiry. Nothing is backfilled: indicators
imported before this have no expiry until they're imported again or an admin sets one.

Revision ID: 9e3c5a7b1f42
Revises: 4d8b1f6e2c57
Create Date: 2026-11-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '9e3c5a7b1f42'
down_revision = '4d8b1f6e2c57'
branch_labels = None
depends_on = None


def upgrade():
    if 'threat_intel_validity' in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        'threat_intel_validity',
        sa.Column('indicator_id', sa.Integer(), primary_key=True),
        sa.Column('valid_until', sa.DateTime(), nullable=True),
        sa.Column('confidence', sa.Integer(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
    )
    op.create_index(op.f('ix_threat_intel_validity_valid_until'), 'threat_intel_validity', ['valid_until'])


def downgrade():
    op.drop_index(op.f('ix_threat_intel_validity_valid_until'), table_name='threat_intel_validity')
    op.drop_table('threat_intel_validity')
