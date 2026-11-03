"""add_threat_intel_indicators

Threat intelligence indicators in the fixed 10-column schema (rivendell/threat_intel/schema.py):
the Iran APT workbook, STIX, TAXII and MITRESaw, as imported through /api/threat-intel.
Duplicates are dropped on import, by the indicator's key, rather than by a unique index: an
index over the long text columns could exceed Postgres's btree row size on a long command line.
Databases that ran this branch before Alembic was in the images got it through create_all,
so it's skipped when it exists.

Revision ID: 7c41d2e9a0b3
Revises: b7e4c2d9a810
Create Date: 2026-10-28 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '7c41d2e9a0b3'
down_revision = 'b7e4c2d9a810'
branch_labels = None
depends_on = None


def upgrade():
    if 'threat_intel_indicators' in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        'threat_intel_indicators',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('evidential_element', sa.Text(), nullable=False),
        sa.Column('threat_group', sa.String(), nullable=True),
        sa.Column('procedure_example', sa.Text(), nullable=True),
        sa.Column('technique_id', sa.String(), nullable=True),
        sa.Column('technique_name', sa.String(), nullable=True),
        sa.Column('tactic', sa.String(), nullable=True),
        sa.Column('contextual_evidence', sa.Text(), nullable=True),
        sa.Column('reference_url', sa.Text(), nullable=True),
        sa.Column('navigation_layer_url', sa.Text(), nullable=True),
        sa.Column('source_type', sa.String(), nullable=True),
    )
    op.create_index(op.f('ix_threat_intel_indicators_threat_group'), 'threat_intel_indicators', ['threat_group'])
    op.create_index(op.f('ix_threat_intel_indicators_source_type'), 'threat_intel_indicators', ['source_type'])


def downgrade():
    op.drop_index(op.f('ix_threat_intel_indicators_source_type'), table_name='threat_intel_indicators')
    op.drop_index(op.f('ix_threat_intel_indicators_threat_group'), table_name='threat_intel_indicators')
    op.drop_table('threat_intel_indicators')
