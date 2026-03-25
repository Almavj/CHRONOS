"""
Elasticsearch Client for CHRONOS
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from elasticsearch import Elasticsearch

    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    logger.warning("Elasticsearch not available")


class ElasticsearchClient:
    """Elasticsearch client for event and alert storage."""

    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.hosts = hosts
        self.username = username
        self.password = password
        self.client: Optional[Any] = None

        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize Elasticsearch client."""
        if not ES_AVAILABLE:
            logger.info("Using mock Elasticsearch client (elasticsearch not installed)")
            self.client = None
            return

        try:
            if self.username and self.password:
                self.client = Elasticsearch(
                    self.hosts, basic_auth=(self.username, self.password)
                )
            else:
                self.client = Elasticsearch(self.hosts)
            logger.info(f"Elasticsearch client initialized: {self.hosts}")
        except Exception as e:
            logger.error(f"Failed to initialize Elasticsearch client: {e}")
            self.client = None

    def index_event(self, index: str, event: Dict[str, Any]) -> bool:
        """Index a security event."""
        if not self.client:
            logger.debug(f"[MOCK] Event indexed to {index}")
            return True

        try:
            result = self.client.index(index=index, document=event, id=event.get("id"))
            return result.get("result") in ["created", "updated"]
        except Exception as e:
            logger.error(f"Failed to index event: {e}")
            return False

    def index_alert(self, index: str, alert: Dict[str, Any]) -> bool:
        """Index a security alert."""
        if not self.client:
            logger.debug(f"[MOCK] Alert indexed to {index}: {alert.get('title')}")
            return True

        try:
            result = self.client.index(index=index, document=alert, id=alert.get("id"))
            return result.get("result") in ["created", "updated"]
        except Exception as e:
            logger.error(f"Failed to index alert: {e}")
            return False

    def search_events(
        self, index: str, query: Dict[str, Any], size: int = 100
    ) -> List[Dict[str, Any]]:
        """Search for events."""
        if not self.client:
            return []

        try:
            result = self.client.search(index=index, query=query, size=size)
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Failed to search events: {e}")
            return []

    def get_alerts(
        self,
        index: str,
        severity: Optional[str] = None,
        time_range: Optional[Dict[str, str]] = None,
        size: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get alerts with optional filtering."""
        if not self.client:
            return []

        must = []

        if severity:
            must.append({"term": {"severity": severity}})

        if time_range:
            must.append({"range": {"timestamp": time_range}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}

        return self.search_events(index, query, size)

    def create_index_if_not_exists(self, index: str, mappings: Dict[str, Any]) -> bool:
        """Create index with mappings if it doesn't exist."""
        if not self.client:
            return True

        try:
            if not self.client.indices.exists(index=index):
                self.client.indices.create(index=index, mappings=mappings)
                logger.info(f"Created index: {index}")
                return True
            return True
        except Exception as e:
            logger.error(f"Failed to create index: {e}")
            return False

    def close(self) -> None:
        """Close the client."""
        if self.client:
            self.client.close()
            logger.info("Elasticsearch client closed")
