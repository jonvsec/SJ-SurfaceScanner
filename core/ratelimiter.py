"""
core/ratelimiter.py — centralized async rate limiter shared by all modules.

All modules call await limiter.acquire("shodan") (or the service name matching
their rate_limits config key) before making any external request. No module
enforces its own rate limiting — this file is the single enforcement point.

Why centralized: when passive modules run concurrently, each module having its
own limiter allows independent counters that together breach API quotas. One
shared limiter sees the aggregate request rate and prevents that.

Algorithm: per-service minimum-interval enforcer backed by asyncio.Lock.
Each service gets a lock so concurrent callers queue correctly. The interval
is 1 / rate_per_second. Falls back to the "default" rate for unknown services.
"""
from __future__ import annotations

import asyncio
import contextlib
import time
from typing import AsyncIterator

import structlog

from core.config import RateLimits

log = structlog.get_logger(__name__)


# Module-level state, shared by every RateLimiter instance in this process.
#
# Every module constructs its own `RateLimiter(config.rate_limits)` (the
# function signature in the module contract has no room for an injected
# limiter), so per-instance state would let concurrent modules each pace
# themselves independently to e.g. "1 req/s for shodan" — two modules running
# concurrently would then produce 2 req/s in aggregate, breaching the real
# API limit. Keeping `_last`/`_locks` at module scope makes the limiter truly
# centralized regardless of how many RateLimiter() instances exist.
_last:  dict[str, float]       = {}
_locks: dict[str, asyncio.Lock] = {}


class RateLimiter:
    """
    Shared rate limiter. Instantiate once, inject everywhere.

    Usage:
        await limiter.acquire("shodan")
        response = await client.get(url)

        # or as a context manager:
        async with limiter.throttle("hunter"):
            response = await client.get(url)
    """

    def __init__(self, limits: RateLimits) -> None:
        self._limits = limits
        self._last  = _last
        self._locks = _locks

    def _lock_for(self, service: str) -> asyncio.Lock:
        """Return (creating if needed) the per-service lock."""
        if service not in self._locks:
            self._locks[service] = asyncio.Lock()
        return self._locks[service]

    async def acquire(self, service: str = "default") -> None:
        """
        Block until the next request to `service` is permitted, then return.

        Callers with the same service name queue behind a per-service lock so
        concurrent coroutines never both read a "slot available" state and
        then both proceed without waiting.
        """
        rate     = self._limits.get(service)   # requests per second
        interval = 1.0 / rate                   # minimum seconds between requests

        async with self._lock_for(service):
            now  = time.monotonic()
            last = self._last.get(service, 0.0)
            wait = (last + interval) - now
            if wait > 0:
                log.debug("ratelimiter.waiting", service=service, wait_s=round(wait, 3))
                await asyncio.sleep(wait)
            self._last[service] = time.monotonic()

    @contextlib.asynccontextmanager
    async def throttle(self, service: str = "default") -> AsyncIterator[None]:
        """Async context manager that acquires a rate-limit slot then yields."""
        await self.acquire(service)
        yield

    def reset(self, service: str | None = None) -> None:
        """
        Reset the rate state for a service (or all services).
        Useful in tests and between pipeline phases.
        """
        if service is None:
            self._last.clear()
        else:
            self._last.pop(service, None)
