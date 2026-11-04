"""
What Rowanholt knows about the machines it made: the template each came from, so the page can
show its OS and what it records, and provisioning knows which script to run. Docker and Tart
don't record that, so Rowanholt keeps it. One small JSON file in the lab's config directory
(it describes this host, not the repository). Machines made outside Rowanholt are still listed,
just without a template.
"""

import json
import os
import threading
from typing import Dict, Optional

LAB_DIR = os.environ.get("ROWANHOLT_LAB_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".config", "rowanholt-lab")
_PATH = os.path.join(LAB_DIR, "mordor-machines.json")
_lock = threading.Lock()


def _key(engine: str, name: str) -> str:
    return f"{engine}/{name}"


def _load() -> Dict:
    try:
        with open(_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: Dict):
    os.makedirs(LAB_DIR, exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, _PATH)


def record(engine: str, name: str, template_id: str, os_name: str, image: str, created: bool = False):
    """Remember a machine Rowanholt made (created=True: it may delete it) or was told the OS of."""
    with _lock:
        data = _load()
        existing = data.get(_key(engine, name), {})
        data[_key(engine, name)] = {"template": template_id, "os": os_name, "image": image,
                                    "provisioned": existing.get("provisioned", []),
                                    "created": created or existing.get("created", False)}
        _save(data)


def get(engine: str, name: str) -> Optional[Dict]:
    return _load().get(_key(engine, name))


def mark_provisioned(engine: str, name: str, step: str):
    with _lock:
        data = _load()
        entry = data.get(_key(engine, name))
        if entry is not None:
            steps = entry.setdefault("provisioned", [])
            if step not in steps:
                steps.append(step)
            _save(data)


def forget(engine: str, name: str):
    with _lock:
        data = _load()
        if data.pop(_key(engine, name), None) is not None:
            _save(data)
