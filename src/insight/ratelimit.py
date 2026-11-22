"""In-process token-bucket rate limiting for the JSON API.

Each caller (the signed-in operator, or the API key) gets its own bucket per policy, so a runaway script
cannot use up the operator's budget and vice versa. A bucket holds ``limit`` requests and refills continuously
at ``limit / window`` per second: short bursts are fine, a sustained flood is not.

State lives in this process, like sessions and the sign-in throttle. Run one worker (``insight serve`` does).
Moving to several workers or hosts means replacing :class:`RateLimiter` with a shared store (e.g. Redis);
callers only use :meth:`RateLimiter.hit`, so that is a local change.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Policy:
    """``limit`` requests per ``window`` seconds; also the largest burst allowed after a quiet period."""

    name: str
    limit: int
    window: float

    @property
    def rate(self) -> float:
        """Tokens added per second."""
        return self.limit / self.window


#: Authenticated API reads (GET/HEAD), per caller.
READ: Final = Policy('read', 300, 60)
#: Authenticated API writes (POST): ingest, triage, notes, demo, sync and enrichment requests, per caller.
WRITE: Final = Policy('write', 60, 60)
#: Cross-report IOC exports (up to 100,000 mentions each, built in memory), per caller.
IOC_EXPORT: Final = Policy('ioc-export', 30, 3600)
#: TAXII collection reads (each page is built from a full, validated snapshot), per API key (ADR 0026).
TAXII: Final = Policy('taxii', 240, 3600)
#: Requests with an invalid API key, per client address. Valid keys are never counted or refused by this.
AUTH_FAILURES: Final = Policy('auth-failures', 10, 60)


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    policy: Policy
    remaining: int
    #: Seconds until the bucket is full again.
    reset_after: float
    #: Seconds until this request would be allowed (0 when it was).
    retry_after: float

    def headers(self) -> dict[str, str]:
        """``RateLimit-Policy``/``RateLimit`` (IETF httpapi draft) and, when refused, ``Retry-After``."""
        name, policy = self.policy.name, self.policy
        headers = {
            'RateLimit-Policy': f'"{name}";q={policy.limit};w={math.ceil(policy.window)}',
            'RateLimit': f'"{name}";r={self.remaining};t={math.ceil(self.reset_after)}',
        }
        if not self.allowed:
            headers['Retry-After'] = str(max(1, math.ceil(self.retry_after)))
        return headers


class RateLimiter:
    """Thread-safe token buckets keyed by ``(policy, caller)``; memory is bounded by ``max_buckets``."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_buckets: int = 10_000) -> None:
        #: Seconds, monotonic. Replaceable so tests can freeze or advance time.
        self.clock = clock
        self._max_buckets = max_buckets
        #: (policy, caller) -> (tokens, updated_at, full_again_at)
        self._buckets: dict[tuple[str, str], tuple[float, float, float]] = {}
        self._lock = threading.Lock()

    def hit(self, caller: str, policy: Policy, cost: int = 1) -> Decision:
        """Take ``cost`` tokens from the caller's bucket if it has them; never blocks."""
        key = (policy.name, caller)
        with self._lock:
            now = self.clock()
            tokens, updated, _ = self._buckets.get(key, (float(policy.limit), now, now))
            # Clamped: a clock that steps backwards must never drain a bucket (and lock the caller out).
            tokens = min(float(policy.limit), tokens + max(0.0, now - updated) * policy.rate)
            allowed = tokens >= cost
            if allowed:
                tokens -= cost
            reset_after = (policy.limit - tokens) / policy.rate
            if key not in self._buckets and len(self._buckets) >= self._max_buckets:
                self._prune(now)
            self._buckets[key] = (tokens, now, now + reset_after)
        return Decision(
            allowed=allowed,
            policy=policy,
            remaining=math.floor(tokens),
            reset_after=reset_after,
            retry_after=0.0 if allowed else (cost - tokens) / policy.rate,
        )

    def _prune(self, now: float) -> None:
        """Forget buckets that have refilled completely (equivalent to never having seen them)."""
        for key, (_, _, full_at) in list(self._buckets.items()):
            if full_at <= now:
                del self._buckets[key]
        if len(self._buckets) >= self._max_buckets:  # Still full: drop the least recently used half.
            for key in sorted(self._buckets, key=lambda k: self._buckets[k][1])[: len(self._buckets) // 2]:
                del self._buckets[key]
