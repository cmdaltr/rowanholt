"""add_audit_logs

The security log for events outside a case: a licence installed or removed (licence.py), with the
terms version accepted. models/database.py's AuditLog had this shape but was never created, and its
foreign key points at a users table Rowanholt doesn't use (accounts are in users.json).

Revision ID: d5a2e8f1c693
Revises: f2b7c9d4e816
Create Date: 2026-11-11 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd5a2e8f1c693'
down_revision = 'f2b7c9d4e816'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if 'audit_logs' in inspector.get_table_names():
        columns = {c['name'] for c in inspector.get_columns('audit_logs')}
        if 'username' in columns:
            return  # already this shape: storage.py's create_all got there first
        # The old models/database.py shape, if its create_all ever ran: its foreign key to users.id
        # would refuse every entry (accounts are in users.json). Nothing ever wrote to it, so an empty
        # one is replaced; one with rows only gains the column, so no record is lost.
        if bind.execute(sa.text('SELECT COUNT(*) FROM audit_logs')).scalar():
            op.add_column('audit_logs', sa.Column('username', sa.String(), nullable=True))
            return
        op.drop_table('audit_logs')
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('username', sa.String(), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(36), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
    )
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'])
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'])
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'])


def downgrade():
    op.drop_index(op.f('ix_audit_logs_timestamp'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_action'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_user_id'), table_name='audit_logs')
    op.drop_table('audit_logs')
