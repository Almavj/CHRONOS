"""
Cache Implementation
"""

import json
import hashlib
import time
from typing import Dict, Any, Optional, Tuple
from threading import Lock
from dataclasses import dataclass, field


@dataclass
class CacheEntry:
    value: Any
    timestamp: float
    ttl: float
    hits: int = 0

    def is_expired(self) -> bool:
        if self.ttl <= 0:
            return False
        return time.time() - self.timestamp > self.ttl


class LRUCache:
    """Thread-safe LRU cache with TTL support."""

    def __init__(self, max_size: int = 1000, default_ttl: float = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order: list = []
        self.lock = Lock()

    def _generate_key(self, data: Dict[str, Any], fields: Optional[list] = None) -> str:
        """Generate cache key from data."""
        if fields:
            filtered = {k: data.get(k) for k in fields if k in data}
        else:
            filtered = data

        key_data = json.dumps(filtered, sort_keys=True)
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self.lock:
            if key not in self.cache:
                return None

            entry = self.cache[key]
            if entry.is_expired():
                del self.cache[key]
                self.access_order.remove(key)
                return None

            entry.hits += 1
            self.access_order.remove(key)
            self.access_order.append(key)
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache."""
        with self.lock:
            if key in self.cache:
                self.access_order.remove(key)

            while len(self.cache) >= self.max_size and self.access_order:
                oldest_key = self.access_order.pop(0)
                if oldest_key in self.cache:
                    del self.cache[oldest_key]

            entry = CacheEntry(
                value=value,
                timestamp=time.time(),
                ttl=ttl if ttl is not None else self.default_ttl,
            )
            self.cache[key] = entry
            self.access_order.append(key)

    def delete(self, key: str) -> bool:
        """Delete value from cache."""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                self.access_order.remove(key)
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.access_order.clear()

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns count of removed entries."""
        removed = 0
        with self.lock:
            expired_keys = [k for k, v in self.cache.items() if v.is_expired()]
            for key in expired_keys:
                del self.cache[key]
                self.access_order.remove(key)
                removed += 1
        return removed

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_hits = sum(e.hits for e in self.cache.values())
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "total_hits": total_hits,
                "expired": sum(1 for e in self.cache.values() if e.is_expired()),
            }


def generate_cache_key(alert_data: Dict[str, Any]) -> str:
    """Generate cache key for alert analysis."""
    important_fields = {
        "title": alert_data.get("title"),
        "technique": alert_data.get("technique"),
        "indicators": sorted(alert_data.get("indicators", [])),
        "severity": alert_data.get("severity"),
    }
    key_data = json.dumps(important_fields, sort_keys=True)
    return hashlib.sha256(key_data.encode()).hexdigest()
