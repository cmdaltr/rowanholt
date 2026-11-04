"""Scoped administration of Rowanholt's Docker containers and images.

Only resources labelled with the Rowanholt compose project and named
``rowanholt-*`` are visible or touchable; see ``scope.py``.
"""

from .admin import DockerAdmin
from .engine import Engine, EngineError, EngineUnavailable, candidate_sockets, find_socket
from .scope import BusyError, ScopeError

__all__ = [
    "DockerAdmin",
    "Engine",
    "EngineError",
    "EngineUnavailable",
    "BusyError",
    "ScopeError",
    "candidate_sockets",
    "find_socket",
]
