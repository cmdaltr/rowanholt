"""What counts as a Rowanholt container or image, and which actions are refused.

Every operation resolves its target from the engine and checks it here, so a
name or ID supplied by a caller is never trusted on its own.
"""

from __future__ import annotations

import os
from typing import Iterable, Optional

PROJECT_LABEL = "com.docker.compose.project"
SERVICE_LABEL = "com.docker.compose.service"
PROJECT = os.environ.get("ROWANHOLT_COMPOSE_PROJECT", "rowanholt")
NAME_PREFIX = "rowanholt-"

ANDURIL_SERVICE = "anduril"
# Stopping these while Elrond runs orphans the job: the worker loses its
# broker or database and marks the job failed while elrond.py keeps going.
JOB_SENSITIVE_SERVICES = frozenset({"celery-worker", "postgres", "redis"})
JOB_PROCESS_MARKERS = ("elrond.py",)


class ScopeError(Exception):
    """The target is not a Rowanholt resource, or the action is not allowed on it."""


class BusyError(Exception):
    """The action would interrupt a running Rowanholt job."""


def _labels(container: dict) -> dict:
    return container.get("Labels") or (container.get("Config") or {}).get("Labels") or {}


def container_name(container: dict) -> str:
    """Name without the leading slash, from a list entry or an inspect result."""
    names = container.get("Names") or [container.get("Name", "")]
    return names[0].lstrip("/")


def container_service(container: dict) -> str:
    return _labels(container).get(SERVICE_LABEL, "")


def container_in_scope(container: dict, project: str = PROJECT) -> bool:
    """Both the compose project label and the rowanholt- name prefix must match."""
    return _labels(container).get(PROJECT_LABEL) == project and container_name(container).startswith(NAME_PREFIX)


def image_is_built(image: dict, project: str = PROJECT) -> bool:
    """Images compose built for the project carry its project label."""
    return (image.get("Labels") or {}).get(PROJECT_LABEL) == project


def image_in_scope(image: dict, scoped_image_ids: Iterable[str], project: str = PROJECT) -> bool:
    """Built by the project, or used by one of its containers."""
    return image_is_built(image, project) or image.get("Id") in set(scoped_image_ids)


def image_users(image_id: str, containers: Iterable[dict], project: str = PROJECT) -> tuple[list[str], list[str]]:
    """(Rowanholt container names, other container names) using an image."""
    ours, others = [], []
    for c in containers:
        if c.get("ImageID") != image_id:
            continue
        (ours if container_in_scope(c, project) else others).append(container_name(c))
    return ours, others


def check_image_removable(image: dict, containers: Iterable[dict], scoped_image_ids: Iterable[str], project: str = PROJECT) -> None:
    """Raise ScopeError unless the image is ours and nothing outside Rowanholt uses it."""
    if not image_in_scope(image, scoped_image_ids, project):
        raise ScopeError(f"Image {image.get('Id', '')[:19]} is not a Rowanholt image")
    ours, others = image_users(image["Id"], containers, project)
    if others:
        raise ScopeError(f"Image is also used by non-Rowanholt containers: {', '.join(others)}")
    if ours:
        raise ScopeError(f"Image is in use by {', '.join(ours)}; stop and update those first")


def check_action(service: str, action: str, job_processes: list[str], force: bool, allow_self: bool = False) -> None:
    """Refuse actions that would cut off administration or interrupt a job."""
    if service == ANDURIL_SERVICE and not allow_self:
        raise ScopeError("Anduril can only be stopped or updated from the host CLI (rowanholt anduril disable)")
    if service in JOB_SENSITIVE_SERVICES and job_processes and not force:
        raise BusyError(
            f"Refusing to {action} {service}: Elrond is running in the worker "
            f"({'; '.join(job_processes)}). Use force to override."
        )


def split_image_ref(ref: str) -> tuple[str, str]:
    """Split 'repo[:tag]' into (repo, tag); the tag defaults to latest."""
    if "@" in ref:
        repo, digest = ref.split("@", 1)
        return repo, digest
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        return ref[:colon], ref[colon + 1 :]
    return ref, "latest"


def find_job_processes(top: Optional[dict]) -> list[str]:
    """Job command lines from a worker's /top output."""
    if not top:
        return []
    titles = top.get("Titles") or []
    col = titles.index("COMMAND") if "COMMAND" in titles else len(titles) - 1
    found = []
    for row in top.get("Processes") or []:
        cmd = row[col] if col < len(row) else " ".join(row)
        if any(m in cmd for m in JOB_PROCESS_MARKERS):
            found.append(cmd[:160])
    return found
