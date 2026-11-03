"""unique_finding_per_row

One finding per row of a case's output: two analysts (or Eru and an analyst) flagging the same
row at the same moment both passed the "already flagged" check before either was saved. A
database that already holds such pairs is left without the constraint, with a warning, rather
than have a migration choose which finding to drop.

Revision ID: c71d4e9a2b58
Revises: a3f8c6e1d295
Create Date: 2026-11-03 00:00:00.000000

"""
import logging

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c71d4e9a2b58'
down_revision = 'a3f8c6e1d295'
branch_labels = None
depends_on = None

NAME = 'uq_case_findings_row'
COLUMNS = ['job_id', 'host', 'artefact', 'row_ref']
logger = logging.getLogger('alembic.runtime.migration')


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if 'case_findings' not in inspector.get_table_names():
        return
    if any(c['name'] == NAME for c in inspector.get_unique_constraints('case_findings')):
        return  # a new database: create_all made it from the model
    duplicates = bind.execute(sa.text(
        'SELECT job_id, host, artefact, row_ref FROM case_findings '
        'GROUP BY job_id, host, artefact, row_ref HAVING COUNT(*) > 1')).fetchall()
    if duplicates:
        logger.warning(f"{len(duplicates)} rows are flagged more than once in case_findings; "
                       f"{NAME} not added until they're merged by hand")
        return
    with op.batch_alter_table('case_findings') as batch:
        batch.create_unique_constraint(NAME, COLUMNS)


def downgrade():
    bind = op.get_bind()
    if any(c['name'] == NAME for c in sa.inspect(bind).get_unique_constraints('case_findings')):
        with op.batch_alter_table('case_findings') as batch:
            batch.drop_constraint(NAME, type_='unique')
