"""
Rate Limiter Implementation
"""

import time
from threading import Lock
from datetime import datetime, timedelta
from typing import List, Optional


class RateLimiter:
    """Thread-safe rate limiter for API calls."""

    def __init__(self, max_calls: int, period: int = 60):
        self.max_calls = max_calls
        self.period = period
        self.calls: List[float] = []
        self.lock = Lock()

    def can_call(self) -> bool:
        """Check if a call can be made within rate limits."""
        with self.lock:
            now = time.time()
            cutoff = now - self.period
            self.calls = [call_time for call_time in self.calls if call_time > cutoff]
            return len(self.calls) < self.max_calls

    def add_call(self) -> None:
        """Record a call."""
        with self.lock:
            self.calls.append(time.time())

    def time_until_next_slot(self) -> float:
        """Get seconds until next available slot."""
        with self.lock:
            if len(self.calls) < self.max_calls:
                return 0.0

            now = time.time()
            cutoff = now - self.period
            self.calls = [call_time for call_time in self.calls if call_time > cutoff]

            if len(self.calls) < self.max_calls:
                return 0.0

            oldest = min(self.calls)
            return max(0, (oldest + self.period) - now)


class TokenBucket:
    """Token bucket for more flexible rate limiting."""

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if successful."""
        with self.lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now

    def wait_time(self, tokens: int = 1) -> float:
        """Calculate wait time for tokens to become available."""
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                return 0.0
            needed = tokens - self.tokens
            return needed / self.refill_rate
