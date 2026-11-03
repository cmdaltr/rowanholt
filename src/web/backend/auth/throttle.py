"""
Failed password sign-ins, counted in Redis so they survive restarts and are shared by
every backend process.

A username is locked per client address: someone guessing at a colleague's account from
their own machine locks themselves out, not the colleague. A much higher count across
every address catches guessing spread over many machines; reaching it locks the username
everywhere, which costs an attacker ten times the attempts that used to lock it.

Without Redis (it's down, or host-side tools) the counts are kept in this process.
"""

import logging
import time
from typing import Dict, Optional, Tuple

try:
    from ..config import settings
except ImportError:
    from config import settings

logger = logging.getLogger(__name__)

PREFIX = "rivendell:signin:"
# Failures across all addresses that lock a username everywhere, as a multiple of the
# per-address limit
EVERYWHERE = 10
RETRY_REDIS = 60  # seconds before trying Redis again after it failed


class SignInThrottle:
    """Counts failed sign-ins per (username, address) and per username."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.redis_url
        self._redis = None
        self._redis_down_until = 0.0
        self._memory: Dict[str, Tuple[int, float]] = {}  # key: (count, expires at)

    # ── storage ──────────────────────────────────────────────────────────────

    def _client(self):
        if self._redis is not None or time.time() < self._redis_down_until:
            return self._redis
        try:
            import redis
            client = redis.Redis.from_url(self.redis_url, socket_timeout=1, socket_connect_timeout=1)
            client.ping()
            self._redis = client
        except Exception as exc:  # redis missing, refused, unresolvable
            logger.warning(f"Sign-in lockouts held in memory: Redis unavailable ({exc})")
            self._redis_down_until = time.time() + RETRY_REDIS
        return self._redis

    def _call(self, redis_op, memory_op):
        client = self._client()
        if client is not None:
            try:
                return redis_op(client)
            except Exception as exc:
                logger.warning(f"Sign-in lockouts held in memory: Redis failed ({exc})")
                self._redis = None
                self._redis_down_until = time.time() + RETRY_REDIS
        return memory_op()

    def _count(self, key: str) -> Tuple[int, int]:
        """(failures, seconds until they're forgotten)"""
        def redis_op(client):
            count, ttl = client.pipeline().get(PREFIX + key).ttl(PREFIX + key).execute()
            return int(count or 0), max(int(ttl or 0), 0)

        def memory_op():
            count, expires = self._memory.get(key, (0, 0.0))
            left = int(expires - time.time())
            return (count, left) if left > 0 else (0, 0)
        return self._call(redis_op, memory_op)

    def _add(self, key: str, window: int, cap: int) -> None:
        """One more failure. The count is forgotten `window` seconds after the first, and
        reaching `cap` restarts the window, so a lockout always lasts the full window."""
        def redis_op(client):
            pipe = client.pipeline()
            pipe.incr(PREFIX + key)
            pipe.expire(PREFIX + key, window, nx=True)
            count = pipe.execute()[0]
            if count == cap:
                client.expire(PREFIX + key, window)

        def memory_op():
            count, left = self._count(key)
            count += 1
            self._memory[key] = (count, time.time() + (window if count == cap or not left else left))
        self._call(redis_op, memory_op)

    def _clear(self, key: str) -> None:
        self._call(lambda client: client.delete(PREFIX + key), lambda: self._memory.pop(key, None))

    # ── policy ───────────────────────────────────────────────────────────────

    @staticmethod
    def _keys(username: str, address: str) -> Tuple[str, str]:
        name = username.strip().lower()
        return f"{name}|{address}", f"{name}|*"

    def locked_for(self, username: str, address: str) -> int:
        """Seconds until `username` may try again from `address`; 0 when it may now."""
        limit = settings.max_login_attempts
        here, everywhere = self._keys(username, address)
        waits = [left for key, cap in ((here, limit), (everywhere, limit * EVERYWHERE))
                 for count, left in [self._count(key)] if count >= cap]
        return max(waits, default=0)

    def failed(self, username: str, address: str) -> None:
        """Count a failed sign-in; the lockout window starts at the first failure."""
        window = settings.lockout_duration_minutes * 60
        limit = settings.max_login_attempts
        here, everywhere = self._keys(username, address)
        self._add(here, window, limit)
        self._add(everywhere, window, limit * EVERYWHERE)

    def succeeded(self, username: str, address: str) -> None:
        """Forget this address's failures (the username-wide count runs its course)."""
        self._clear(self._keys(username, address)[0])


throttle = SignInThrottle()
