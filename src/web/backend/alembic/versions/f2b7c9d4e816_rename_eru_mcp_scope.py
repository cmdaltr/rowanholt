"""rename_eru_mcp_scope

Rowanholt's AI analyst was renamed from Eru to Aulë, and its API token scope with it: stored
"eru-mcp" tokens become "aule-mcp". The backend still takes "eru-mcp" wherever a scope is given
or checked (auth/tokens.py, OLD_SCOPES), so a token is never refused for the rename. Downgrading
names every aule-mcp token eru-mcp again, the only name the code before the rename knows.

Authors and actors already recorded as "Eru (for <user>)" in case_findings, case_notes and
case_activity are left as written: they are the case's audit record.

Revision ID: f2b7c9d4e816
Revises: c71d4e9a2b58
Create Date: 2026-11-09 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f2b7c9d4e816'
down_revision = 'c71d4e9a2b58'
branch_labels = None
depends_on = None

OLD = 'eru-mcp'
NEW = 'aule-mcp'


def _rename(old: str, new: str) -> None:
    if 'api_tokens' not in sa.inspect(op.get_bind()).get_table_names():
        return
    op.execute(sa.text('UPDATE api_tokens SET scope = :new WHERE scope = :old').bindparams(new=new, old=old))


def upgrade() -> None:
    _rename(OLD, NEW)


def downgrade() -> None:
    _rename(NEW, OLD)
