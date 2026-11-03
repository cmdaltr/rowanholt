"""add_api_tokens

Long-lived, revocable tokens for scripts and Eru's MCP server (auth/tokens.py). Only each
token's SHA-256 is stored. A scope of "eru-mcp" limits a token to what Eru's MCP server may do.

Revision ID: a3f8c6e1d295
Revises: 9e3c5a7b1f42
Create Date: 2026-11-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a3f8c6e1d295'
down_revision = '9e3c5a7b1f42'
branch_labels = None
depends_on = None


def upgrade():
    if 'api_tokens' in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        'api_tokens',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False, unique=True),
        sa.Column('prefix', sa.String(), nullable=False),
        sa.Column('scope', sa.String(), nullable=False, server_default='full'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
    )
    op.create_index(op.f('ix_api_tokens_user_id'), 'api_tokens', ['user_id'])


def downgrade():
    op.drop_index(op.f('ix_api_tokens_user_id'), table_name='api_tokens')
    op.drop_table('api_tokens')
