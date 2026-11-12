"""
Job Storage

PostgreSQL-based storage for jobs using SQLAlchemy.
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from sqlalchemy import create_engine, text, Column, String, Integer, Text, DateTime, Enum as SQLEnum, JSON, \
    UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, defer
from sqlalchemy.pool import NullPool

try:
    from .models.job import Job, JobStatus
    from .config import settings
except ImportError:
    # Fallback for standalone module execution (Celery worker)
    from models.job import Job, JobStatus
    from config import settings


# SQLAlchemy Base
Base = declarative_base()

logger = logging.getLogger(__name__)
# Held while migrating, so the backend and the worker starting together don't both run them
MIGRATION_LOCK = 5688


class JobModel(Base):
    """SQLAlchemy model for jobs table."""
    __tablename__ = "jobs"

    id = Column(String, primary_key=True)
    case_number = Column(String, nullable=False, index=True)
    source_paths = Column(JSON, nullable=False)
    destination_path = Column(String, nullable=True)
    options = Column(JSON, nullable=False)
    status = Column(String, nullable=False, index=True)
    progress = Column(Integer, default=0)
    log = Column(JSON, default=list)
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    celery_task_id = Column(String, nullable=True)
    pending_action = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.now, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class JobAccessModel(Base):
    """Who owns a job and who it's shared with (server mode). A table of its own, so the
    jobs table stays as it is; create_all adds it to existing databases."""
    __tablename__ = "job_access"

    job_id = Column(String, primary_key=True)
    owner_id = Column(String, nullable=True, index=True)
    owner_username = Column(String, nullable=True)
    shared_with = Column(JSON, default=list)


class ThreatIntelIndicatorModel(Base):
    """One threat intelligence indicator: the fixed 10-column schema of
    rowanholt/threat_intel/schema.py, with a key. Revision 7c41d2e9a0b3."""
    __tablename__ = "threat_intel_indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidential_element = Column(Text, nullable=False)
    threat_group = Column(String, nullable=True, index=True)
    procedure_example = Column(Text, nullable=True)
    technique_id = Column(String, nullable=True)
    technique_name = Column(String, nullable=True)
    tactic = Column(String, nullable=True)
    contextual_evidence = Column(Text, nullable=True)
    reference_url = Column(Text, nullable=True)
    navigation_layer_url = Column(Text, nullable=True)
    source_type = Column(String, nullable=True, index=True)


class ThreatIntelValidityModel(Base):
    """How long a threat intelligence indicator holds (rowanholt/threat_intel/validity.py): beside the
    fixed 10-column table rather than in it. No row, or valid_until empty: no expiry. Revision 9e3c5a7b1f42."""
    __tablename__ = "threat_intel_validity"

    indicator_id = Column(Integer, primary_key=True)  # threat_intel_indicators.id
    valid_until = Column(DateTime, nullable=True, index=True)
    confidence = Column(Integer, nullable=True)
    first_seen = Column(DateTime, nullable=True)


class ApiTokenModel(Base):
    """A long-lived token for scripts and Smith's MCP server (auth/tokens.py). Only the token's
    SHA-256 is kept; the token itself is shown once, when it's made. Revision a3f8c6e1d295."""
    __tablename__ = "api_tokens"

    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False)
    name = Column(String, nullable=False)
    token_hash = Column(String, nullable=False, unique=True)
    prefix = Column(String, nullable=False)  # the first characters, so a token can be recognised
    scope = Column(String, nullable=False, default="full")
    created_at = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)


class CaseFindingModel(Base):
    """A row of a case's output an analyst flagged: a reference to the evidence, never a copy of it.
    row_hash pins the row, so a re-run that moves or changes it shows up instead of re-pointing."""
    __tablename__ = "case_findings"
    # One finding per row (migration c71d4e9a2b58): a second flag at the same moment fails here
    __table_args__ = (UniqueConstraint("job_id", "host", "artefact", "row_ref", name="uq_case_findings_row"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, nullable=False, index=True)
    host = Column(String, nullable=False)
    artefact = Column(Text, nullable=False)
    row_ref = Column(String, nullable=False)
    row_hash = Column(String, nullable=False)
    excerpt = Column(Text, nullable=True)
    title = Column(Text, nullable=False)
    technique = Column(String, nullable=True)
    status = Column(String, nullable=False, default="lead")
    author = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now)


class CaseNoteModel(Base):
    """Markdown notes on a case, or on one of its findings."""
    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, nullable=False, index=True)
    finding_id = Column(Integer, nullable=True, index=True)
    author = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now)


class CaseHostModel(Base):
    """Who is working on a host in a case, and how far they've got."""
    __tablename__ = "case_hosts"

    job_id = Column(String, primary_key=True)
    host = Column(String, primary_key=True)
    assignee = Column(String, nullable=True)
    status = Column(String, nullable=False, default="to do")
    updated_by = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.now)


class CaseActivityModel(Base):
    """Who flagged, confirmed, assigned or noted what, in a case: append-only, as the audit log is."""
    __tablename__ = "case_activity"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, nullable=False, index=True)
    actor = Column(String, nullable=False)
    action = Column(String, nullable=False)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now, index=True)


class AuditLogModel(Base):
    """Security events outside a case, append-only: licence installs and removals (licence.py).
    The shape of models/database.py's AuditLog, but with no foreign key: Rowanholt's accounts live
    in users.json, not in the database, so user_id is the users.json id and username is kept too."""
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=True, index=True)
    username = Column(String, nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(36), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class JobStorage:
    """PostgreSQL-based job storage using SQLAlchemy."""

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize job storage.

        Args:
            database_url: PostgreSQL connection URL (defaults to DATABASE_URL env var)
        """
        self.database_url = database_url or os.getenv(
            "DATABASE_URL",
            "postgresql://rowanholt:rowanholt@localhost:5432/rowanholt"
        )

        # Create engine with connection pooling disabled for file-based compatibility
        # In production, you might want to enable pooling
        self.engine = create_engine(
            self.database_url,
            poolclass=NullPool,
            echo=False  # Set to True for SQL debugging
        )

        # Create session factory
        self.Session = sessionmaker(bind=self.engine)

        self.migrate()

    def migrate(self) -> None:
        """Bring the schema to Alembic's head (alembic/versions). Without Alembic installed
        (a worker image built before it was added, host-side tools), create missing tables
        instead, as JobStorage always did."""
        try:
            from alembic import command
            from alembic.config import Config
        except ImportError:
            Base.metadata.create_all(self.engine)
            return
        config = Config()
        config.set_main_option("script_location", str(Path(__file__).resolve().parent / "alembic"))
        with self.engine.begin() as connection:
            if connection.dialect.name == "postgresql":
                connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK})
            config.attributes["connection"] = connection
            config.attributes["target_metadata"] = Base.metadata
            command.upgrade(config, "head")
        logger.debug("Schema at Alembic head")

    def _job_model_to_pydantic(self, job_model: JobModel, include_log: bool = True) -> Job:
        """Convert SQLAlchemy model to Pydantic model."""
        return Job(
            id=job_model.id,
            case_number=job_model.case_number,
            source_paths=job_model.source_paths,
            destination_path=job_model.destination_path,
            options=job_model.options,
            status=JobStatus(job_model.status),
            progress=job_model.progress,
            log=job_model.log or [] if include_log else [],
            result=job_model.result,
            error=job_model.error,
            celery_task_id=job_model.celery_task_id,
            pending_action=job_model.pending_action,
            created_at=job_model.created_at,
            started_at=job_model.started_at,
            completed_at=job_model.completed_at,
        )

    def save_job(self, job: Job) -> None:
        """
        Save job to storage.

        Args:
            job: Job to save
        """
        session = self.Session()
        previous = None
        try:
            # Check if job exists
            existing = session.query(JobModel).filter_by(id=job.id).first()

            if existing:
                previous = existing.status
                self._copy_into(existing, job)
            else:
                # Create new job
                job_model = JobModel(
                    id=job.id,
                    case_number=job.case_number,
                    source_paths=job.source_paths,
                    destination_path=job.destination_path,
                    options=job.options.dict(),
                    status=job.status.value,
                    progress=job.progress,
                    log=job.log,
                    result=job.result,
                    error=job.error,
                    celery_task_id=job.celery_task_id,
                    pending_action=job.pending_action.dict() if job.pending_action else None,
                    created_at=job.created_at,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                )
                session.add(job_model)

            session.commit()
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()
        self._after_save(job, previous)

    @staticmethod
    def _copy_into(row: "JobModel", job: Job) -> None:
        """Every column of the row from the job: a full save."""
        row.case_number = job.case_number
        row.source_paths = job.source_paths
        row.destination_path = job.destination_path
        row.options = job.options.dict()
        row.status = job.status.value
        row.progress = job.progress
        row.log = job.log
        row.result = job.result
        row.error = job.error
        row.celery_task_id = job.celery_task_id
        row.pending_action = job.pending_action.dict() if job.pending_action else None
        row.created_at = job.created_at
        row.started_at = job.started_at
        row.completed_at = job.completed_at

    def save_worker_job(self, job: Job) -> None:
        """The worker's save of the job it's running: a full save, as save_job, unless the job was
        cancelled meanwhile (POST /cancel marks it cancelled before it kills the process group).
        Then the cancel stands: its status, completed_at, error and pending action are kept, and so
        is its log line, with the worker's own new lines merged in after the stored ones; the
        worker's progress and result are still written. Without this, the worker's save after the
        kill (exit code -9) would turn a cancelled job into a failed one and drop the cancel's
        line. The row is locked (FOR UPDATE on Postgres) from the read to the write, so a cancel
        can't land in between."""
        session = self.Session()
        previous = None
        saved = job
        try:
            row = session.query(JobModel).filter_by(id=job.id).with_for_update().first()
            if row is None:
                session.close()
                self.save_job(job)
                return
            previous = row.status
            if row.status == JobStatus.CANCELLED.value and job.status != JobStatus.CANCELLED:
                stored = list(row.log or [])
                known = set(stored)
                row.log = stored + [line for line in job.log if line not in known]
                row.progress = job.progress
                row.result = job.result
            else:
                self._copy_into(row, job)
            session.commit()
            saved = self._job_model_to_pydantic(row)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        self._after_save(saved, previous)

    @staticmethod
    def _after_save(job: Job, previous: Optional[str]) -> None:
        # Every way a job ends is a save (the worker's, a cancel, a failed start, a dead worker's
        # job failed by job_liveness): the webhook follows the change of status, once, whichever
        # path got there
        status = job.status.value
        if status in (JobStatus.COMPLETED.value, JobStatus.FAILED.value) and previous != status:
            try:
                try:
                    from . import webhooks
                except ImportError:
                    import webhooks
                webhooks.emit_job(job)
            except Exception:  # noqa: BLE001 - a webhook mustn't fail the job's save
                logger.exception("Webhook for job %s not sent", job.id)

    def set_status(self, job_id: str, status: JobStatus) -> None:
        """
        Update only a job's status.

        The worker saves the whole row from its in-memory copy, so a full
        save_job from the API would overwrite the worker's latest log and
        progress with a stale read.

        Args:
            job_id: Job ID
            status: New status
        """
        session = self.Session()
        try:
            session.query(JobModel).filter_by(id=job_id).update({"status": status.value})
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_job(self, job_id: str) -> Optional[Job]:
        """
        Get job from storage.

        Args:
            job_id: Job ID

        Returns:
            Job if found, None otherwise
        """
        session = self.Session()
        try:
            job_model = session.query(JobModel).filter_by(id=job_id).first()

            if not job_model:
                return None

            return self._job_model_to_pydantic(job_model)
        finally:
            session.close()

    def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        limit: int = 50,
        offset: int = 0,
        job_ids: Optional[Iterable[str]] = None,
    ) -> List[Job]:
        """
        List jobs from storage.

        Args:
            status: Filter by job status
            limit: Maximum number of jobs to return
            offset: Offset for pagination
            job_ids: Only these jobs (None for all)

        Returns:
            List of jobs
        """
        session = self.Session()
        try:
            query = (
                session.query(JobModel)
                .options(defer(JobModel.log))  # log can be 10MB+; excluded from list
                .order_by(JobModel.created_at.desc())
            )

            if status:
                query = query.filter_by(status=status.value)
            if job_ids is not None:
                query = query.filter(JobModel.id.in_(list(job_ids)))

            job_models = query.offset(offset).limit(limit).all()

            # include_log=False: don't touch the deferred log attribute
            return [self._job_model_to_pydantic(jm, include_log=False) for jm in job_models]
        finally:
            session.close()

    def count_jobs(self, status: Optional[JobStatus] = None, job_ids: Optional[Iterable[str]] = None) -> int:
        """
        Count jobs in storage.

        Args:
            status: Filter by job status
            job_ids: Only these jobs (None for all)

        Returns:
            Number of jobs
        """
        session = self.Session()
        try:
            query = session.query(JobModel)

            if status:
                query = query.filter_by(status=status.value)
            if job_ids is not None:
                query = query.filter(JobModel.id.in_(list(job_ids)))

            return query.count()
        finally:
            session.close()

    def active_jobs(self, statuses: Iterable[JobStatus]) -> List[Tuple[str, str, Optional[str]]]:
        """(ID, status, Celery task ID) of every job with one of these statuses: the three
        columns job_liveness needs, from the status index, never the log."""
        session = self.Session()
        try:
            values = [status.value for status in statuses]
            query = session.query(JobModel.id, JobModel.status, JobModel.celery_task_id)
            return [tuple(row) for row in query.filter(JobModel.status.in_(values)).all()]
        finally:
            session.close()

    def set_celery_task_id(self, job_id: str, task_id: str) -> None:
        """Record the task queued for a job, and nothing else: the worker may already have
        picked it up and saved, and a full save from the API would put its status back."""
        session = self.Session()
        try:
            session.query(JobModel).filter_by(id=job_id).update({"celery_task_id": task_id})
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def interrupt_job(self, job_id: str, statuses: Iterable[JobStatus], reason: str) -> Optional[Job]:
        """Fail a job no worker is working on (job_liveness), if it still has one of these
        statuses: the reason goes in its error and at the end of its log, so the web app shows
        why. Returns the job as saved, or None when it had moved on (finished, cancelled)."""
        values = [status.value for status in statuses]
        session = self.Session()
        try:
            row = (session.query(JobModel).filter(JobModel.id == job_id, JobModel.status.in_(values))
                   .with_for_update().first())
            if row is None:
                return None
            previous = row.status
            stamp = datetime.now().isoformat().replace("T", " ")
            row.status = JobStatus.FAILED.value
            row.error = reason
            row.log = list(row.log or []) + [f"[{stamp}] -> {reason}"]
            row.completed_at = datetime.now()
            session.commit()
            job = self._job_model_to_pydantic(row)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        self._after_save(job, previous)
        return job

    def transition(self, job_id: str, statuses: Iterable[JobStatus], status: JobStatus,
                   log_line: Optional[str] = None, **fields) -> Optional[Job]:
        """Move a job to `status` only if it still has one of `statuses`, in one conditional UPDATE,
        so of two callers racing (two confirmations, two workers given the same job) exactly one
        wins; `fields` are other columns to set with it, `log_line` is appended to its log.
        Returns the job as saved, or None when it had moved on."""
        values = [s.value for s in statuses]
        session = self.Session()
        try:
            changed = (session.query(JobModel)
                       .filter(JobModel.id == job_id, JobModel.status.in_(values))
                       .update({"status": status.value, **fields}, synchronize_session=False))
            if not changed:
                session.rollback()
                return None
            row = session.query(JobModel).filter_by(id=job_id).first()
            if log_line:
                stamp = datetime.now().isoformat().replace("T", " ")
                row.log = list(row.log or []) + [f"[{stamp}] -> {log_line}"]
            session.commit()
            job = self._job_model_to_pydantic(row)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        self._after_save(job, values[0] if values else None)
        return job

    def audit(self, action: str, actor: Optional[dict] = None, ip: Optional[str] = None,
              resource_type: str = "job", resource_id: Optional[str] = None, **details) -> None:
        """A row in audit_logs. The worker has no licence module to call (licence.audit), and a
        removal's record must outlive the job log, which lives in the folder being removed. A
        database that's down is logged loudly rather than raised: the action has happened."""
        import uuid

        actor = actor or {}
        session = self.Session()
        try:
            session.add(AuditLogModel(
                id=str(uuid.uuid4()),
                user_id=actor.get("id"),
                username=actor.get("username") or "worker",
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                ip_address=ip,
                timestamp=datetime.utcnow(),
            ))
            session.commit()
        except Exception:  # noqa: BLE001 - see the docstring
            session.rollback()
            logger.exception("%s not audited: %s", action, details)
        finally:
            session.close()

    def audit_records(self, resource_id: Optional[str] = None, action_prefix: str = "") -> List[dict]:
        """Audit rows, oldest first, for one resource and the actions starting with a prefix."""
        session = self.Session()
        try:
            query = session.query(AuditLogModel).order_by(AuditLogModel.timestamp)
            if resource_id:
                query = query.filter(AuditLogModel.resource_id == resource_id)
            if action_prefix:
                query = query.filter(AuditLogModel.action.startswith(action_prefix))
            return [{"action": row.action, "username": row.username, "user_id": row.user_id,
                     "ip_address": row.ip_address, "resource_id": row.resource_id, "details": row.details,
                     "timestamp": row.timestamp} for row in query.all()]
        finally:
            session.close()

    # The tables keyed by a job's ID that go with it. audit_logs isn't one: the security log
    # outlives what it records, a deletion included
    JOB_TABLES = (JobAccessModel, CaseFindingModel, CaseNoteModel, CaseHostModel, CaseActivityModel)

    def delete_job(self, job_id: str) -> Dict[str, int]:
        """Delete a job's row and every row keyed by its ID (JOB_TABLES), in one transaction: left
        behind, a case's findings, notes, host assignments and activity can't be reached by anyone.
        Nothing on disk is touched. Returns how many rows went from each table."""
        session = self.Session()
        try:
            removed = {"jobs": session.query(JobModel).filter_by(id=job_id).delete(synchronize_session=False)}
            for model in self.JOB_TABLES:
                removed[model.__tablename__] = (
                    session.query(model).filter_by(job_id=job_id).delete(synchronize_session=False))
            session.commit()
            return removed
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()

    # ── Access (server mode) ─────────────────────────────────────────────────

    @staticmethod
    def _access_dict(row: JobAccessModel) -> dict:
        return {
            "owner_id": row.owner_id,
            "owner_username": row.owner_username,
            "shared_with": list(row.shared_with or []),
        }

    def set_owner(self, job_id: str, owner_id: str, owner_username: str) -> None:
        """Record who created a job."""
        session = self.Session()
        try:
            row = session.query(JobAccessModel).filter_by(job_id=job_id).first()
            if row:
                row.owner_id, row.owner_username = owner_id, owner_username
            else:
                session.add(JobAccessModel(job_id=job_id, owner_id=owner_id,
                                           owner_username=owner_username, shared_with=[]))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def set_shared(self, job_id: str, usernames: List[str]) -> dict:
        """Replace who a job is shared with; returns the access record."""
        session = self.Session()
        try:
            row = session.query(JobAccessModel).filter_by(job_id=job_id).first()
            if not row:
                row = JobAccessModel(job_id=job_id, owner_id=None, owner_username=None)
                session.add(row)
            row.shared_with = sorted(set(usernames))
            session.commit()
            return self._access_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_access(self, job_id: str) -> Optional[dict]:
        """The owner and sharing of one job, or None if it has no record."""
        session = self.Session()
        try:
            row = session.query(JobAccessModel).filter_by(job_id=job_id).first()
            return self._access_dict(row) if row else None
        finally:
            session.close()

    def all_access(self) -> Dict[str, dict]:
        """Every job's access record, by job ID."""
        session = self.Session()
        try:
            return {row.job_id: self._access_dict(row) for row in session.query(JobAccessModel).all()}
        finally:
            session.close()

    # ── API tokens (auth/tokens.py) ───────────────────────────────────────────

    @staticmethod
    def _token_dict(row: ApiTokenModel) -> dict:
        return {"id": row.id, "user_id": row.user_id, "username": row.username, "name": row.name,
                "prefix": row.prefix, "scope": row.scope, "created_at": row.created_at,
                "expires_at": row.expires_at, "last_used_at": row.last_used_at, "revoked_at": row.revoked_at}

    def add_token(self, token: dict) -> dict:
        """Store a new token (its hash, never the token)."""
        session = self.Session()
        try:
            row = ApiTokenModel(**token)
            session.add(row)
            session.commit()
            return self._token_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def token_by_hash(self, token_hash: str) -> Optional[dict]:
        """The token with this hash, revoked and expired ones included (the caller decides)."""
        session = self.Session()
        try:
            row = session.query(ApiTokenModel).filter_by(token_hash=token_hash).first()
            return self._token_dict(row) if row else None
        finally:
            session.close()

    def list_tokens(self, user_id: Optional[str] = None) -> List[dict]:
        """One user's tokens, or everyone's, newest first."""
        session = self.Session()
        try:
            query = session.query(ApiTokenModel)
            if user_id is not None:
                query = query.filter_by(user_id=user_id)
            return [self._token_dict(row) for row in query.order_by(ApiTokenModel.created_at.desc()).all()]
        finally:
            session.close()

    def revoke_token(self, token_id: str, user_id: Optional[str] = None) -> Optional[dict]:
        """Revoke a token (one of `user_id`'s, unless None); None if there's no such token."""
        session = self.Session()
        try:
            query = session.query(ApiTokenModel).filter_by(id=token_id)
            if user_id is not None:
                query = query.filter_by(user_id=user_id)
            row = query.first()
            if not row:
                return None
            if row.revoked_at is None:
                row.revoked_at = datetime.now()
                session.commit()
            return self._token_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def touch_token(self, token_id: str, when: datetime) -> None:
        """Record when a token was last used."""
        session = self.Session()
        try:
            session.query(ApiTokenModel).filter_by(id=token_id).update({"last_used_at": when})
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
