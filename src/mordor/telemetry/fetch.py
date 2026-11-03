"""GitHub downloads for the telemetry sources: the repository tree, raw files and Git LFS objects.

Standard library only (Archer used requests), so the Dernvale backend can run a rebuild
without another dependency.
"""

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, List
from urllib.parse import quote

HEADERS = {"User-Agent": "Dernvale (telemetry datasets)"}
WORKERS = 8


def _get(url: str, timeout: int, headers: dict = None):
    """The open response; raises urllib.error.HTTPError on a 4xx/5xx, as raise_for_status did."""
    return urllib.request.urlopen(urllib.request.Request(url, headers={**HEADERS, **(headers or {})}), timeout=timeout)


def tree(repo: str, branch: str = "master") -> List[dict]:
    with _get(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1", 60) as r:
        return json.load(r)["tree"]


def raw(repo: str, path: str, branch: str = "master", timeout: int = 60) -> bytes:
    with _get(f"https://raw.githubusercontent.com/{repo}/{branch}/{quote(path.lstrip('/'))}", timeout) as r:
        return r.read()


def lfs(repo: str, path: str, cap: int, branch: str = "master", timeout: int = 120) -> bytes:
    """A Git LFS file's first `cap` bytes (a Range request; GitHub's media host serves LFS without a client)."""
    with _get(f"https://media.githubusercontent.com/media/{repo}/{branch}/{path.lstrip('/')}", timeout,
              {"Range": f"bytes=0-{cap - 1}"}) as r:
        return r.read(cap)


def pool(fn: Callable, items: Iterable, log=print) -> Iterable:
    """fn over items, WORKERS at a time; an item that fails is logged and skipped."""
    def safe(item):
        try:
            return fn(item)
        except Exception as e:
            log(f"  {item}: {e}")
            return None

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for result in ex.map(safe, items):
            if result is not None:
                yield result
