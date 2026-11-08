"""The password of an encrypted phone backup, from the job form to the worker without being stored.

The job (Postgres) never has it, nor the Celery task's arguments. The API puts it in Redis under
the job's ID with an expiry, and the worker takes it (read and deleted at once) as it starts
Elrond, which reads it on its standard input (--backupPasswordStdin), never its command line.
A job restarted later has no password: Elrond says the backup needs one.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Long enough for a job to wait for its images' locks (two hours) and the queue
TTL_SECONDS = 12 * 60 * 60
_client = None


def _redis():
    global _client
    if _client is None:
        import redis

        _client = redis.Redis(host=os.environ.get("REDIS_HOST", "redis"),
                              port=int(os.environ.get("REDIS_PORT", 6379)), db=1)
    return _client


def _key(job_id: str) -> str:
    return f"rowanholt:backup_password:{job_id}"


def stash(job_id: str, password: str, client=None) -> None:
    """Hold a job's backup password until its worker takes it (or TTL_SECONDS pass)."""
    (client or _redis()).set(_key(job_id), password.encode("utf-8"), ex=TTL_SECONDS)


def take(job_id: str, client=None) -> Optional[str]:
    """A job's backup password, removed as it's read; None when there isn't one."""
    client = client or _redis()
    pipe = client.pipeline()
    pipe.get(_key(job_id))
    pipe.delete(_key(job_id))
    value, _ = pipe.execute()
    return value.decode("utf-8") if value else None

