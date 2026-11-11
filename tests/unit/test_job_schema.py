"""Unit tests for JobStorage's migrations (src/web/backend/storage.py, alembic/), on SQLite.

Run: python3 -m unittest tests/unit/test_job_schema.py (needs sqlalchemy and alembic)
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine, inspect, text

TMP = tempfile.mkdtemp(prefix="rowanholt-schema-")
# pydantic settings read .env from the working directory: keep the repository's out of it
os.chdir(TMP)
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "web" / "backend"))

import storage  # noqa: E402

HEAD = "d5a2e8f1c693"  # the newest file in src/web/backend/alembic/versions


def heads(url: str) -> list:
    with create_engine(url).connect() as connection:
        return [row[0] for row in connection.execute(text("SELECT version_num FROM alembic_version"))]


class MigrationTest(unittest.TestCase):
    def url(self, name: str) -> str:
        return f"sqlite:///{TMP}/{name}.db"

    def test_fresh_database_gets_every_table_at_head(self):
        url = self.url("fresh")
        storage.JobStorage(url)
        tables = set(inspect(create_engine(url)).get_table_names())
        self.assertTrue({"jobs", "job_access", "threat_intel_indicators", "case_findings", "case_notes", "case_hosts",
                         "case_activity", "threat_intel_validity", "api_tokens", "audit_logs", "alembic_version"} <= tables)
        self.assertEqual(heads(url), [HEAD])

    def test_database_from_before_migrations_keeps_its_jobs(self):
        url = self.url("legacy")
        engine = create_engine(url)
        storage.JobModel.__table__.create(engine)
        with engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO jobs (id, case_number, source_paths, options, status, progress, created_at) "
                "VALUES ('j1', 'CASE01', '[]', '{}', 'completed', 100, '2026-10-01 10:00:00')"))
        jobs = storage.JobStorage(url)
        self.assertEqual(heads(url), [HEAD])
        self.assertEqual(jobs.get_job("j1").case_number, "CASE01")
        self.assertIn("job_access", inspect(create_engine(url)).get_table_names())

    def test_database_built_by_create_all_migrates(self):
        """Images without Alembic created every table with create_all and no alembic_version; the
        first start with Alembic must adopt them, not fail on the first table that exists."""
        url = self.url("create_all")
        storage.Base.metadata.create_all(create_engine(url))
        storage.JobStorage(url)
        self.assertEqual(heads(url), [HEAD])

    def test_starting_twice_changes_nothing(self):
        url = self.url("twice")
        storage.JobStorage(url)
        storage.JobStorage(url)
        self.assertEqual(heads(url), [HEAD])

    def test_eru_mcp_tokens_become_aule_mcp_and_back(self):
        """Aulë was Eru: stored eru-mcp scopes are renamed on the way up and named again on the way down."""
        from alembic import command
        from alembic.config import Config
        url = self.url("scopes")
        storage.JobStorage(url)
        engine = create_engine(url)
        with engine.begin() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num = 'c71d4e9a2b58'"))
            for n, scope in enumerate(("eru-mcp", "full")):
                connection.execute(text(
                    "INSERT INTO api_tokens (id, user_id, username, name, token_hash, prefix, scope, created_at, "
                    "expires_at) VALUES (:id, 'u1', 'alice', 'mcp', :hash, 'rvt_ab', :scope, "
                    "'2026-11-01 10:00:00', '2027-11-01 10:00:00')"), {"id": f"t{n}", "hash": f"h{n}", "scope": scope})

        def scopes() -> list:
            with engine.connect() as connection:
                return [row[0] for row in connection.execute(text("SELECT scope FROM api_tokens ORDER BY id"))]

        storage.JobStorage(url)
        self.assertEqual((heads(url), scopes()), ([HEAD], ["aule-mcp", "full"]))
        config = Config()
        config.set_main_option("script_location", str(Path(storage.__file__).resolve().parent / "alembic"))
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            config.attributes["target_metadata"] = storage.Base.metadata
            command.downgrade(config, "c71d4e9a2b58")
        self.assertEqual(scopes(), ["eru-mcp", "full"])

    def test_models_match_the_migrations(self):
        from alembic.autogenerate import compare_metadata
        from alembic.migration import MigrationContext
        url = self.url("compare")
        storage.JobStorage(url)
        with create_engine(url).connect() as connection:
            diff = compare_metadata(MigrationContext.configure(connection), storage.Base.metadata)
        self.assertEqual(diff, [])


if __name__ == "__main__":
    unittest.main()
