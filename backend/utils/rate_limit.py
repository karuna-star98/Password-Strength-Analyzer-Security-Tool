"""Tiny in-memory sliding-window rate limiter (per client IP). Production: use a shared store / gateway."""
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit_per_min):
        self.limit = limit_per_min
        self.hits = defaultdict(deque)

    def allow(self, key):
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True
