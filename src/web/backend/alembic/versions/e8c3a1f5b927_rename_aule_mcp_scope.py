"""rename_aule_mcp_scope

Rowanholt's AI analyst was renamed from Aulë to Smith, and its API token scope with it: stored
"aule-mcp" tokens become "smith-mcp". The backend still takes "aule-mcp" (and "eru-mcp", its first
name) wherever a scope is given or checked (auth/tokens.py, OLD_SCOPES), so a token is never refused
for the rename. Downgrading names every smith-mcp token aule-mcp again, the only name the code before
this rename knows.

Authors and actors already recorded as "Aulë (for <user>)" in case_findings, case_notes and
case_activity are left as written: they are the case's audit record.

Revision ID: e8c3a1f5b927
Revises: d5a2e8f1c693
Create Date: 2026-11-12 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e8c3a1f5b927'
down_revision = 'd5a2e8f1c693'
branch_labels = None
depends_on = None

OLD = 'aule-mcp'
NEW = 'smith-mcp'


def _rename(old: str, new: str) -> None:
    if 'api_tokens' not in sa.inspect(op.get_bind()).get_table_names():
        return
    op.execute(sa.text('UPDATE api_tokens SET scope = :new WHERE scope = :old').bindparams(new=new, old=old))


def upgrade() -> None:
    _rename(OLD, NEW)


def downgrade() -> None:
    _rename(NEW, OLD)
