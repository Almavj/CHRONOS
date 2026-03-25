"""
Kafka Alert Producer for CHRONOS
"""

import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from kafka import KafkaProducer

    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logger.warning("Kafka not available. Using mock producer.")


class KafkaAlertProducer:
    """Kafka producer for security alerts."""

    def __init__(self, bootstrap_servers: str, topic: str):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.producer: Optional[Any] = None

        self._initialize_producer()

    def _initialize_producer(self) -> None:
        """Initialize Kafka producer."""
        if not KAFKA_AVAILABLE:
            logger.info("Using mock Kafka producer (kafka-python not installed)")
            self.producer = None
            return

        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                retries=3,
            )
            logger.info(f"Kafka producer initialized for topic: {self.topic}")
        except Exception as e:
            logger.error(f"Failed to initialize Kafka producer: {e}")
            self.producer = None

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert to Kafka topic."""
        alert["produced_at"] = datetime.utcnow().isoformat()

        if not self.producer:
            self._mock_send_alert(alert)
            return True

        try:
            future = self.producer.send(self.topic, key=alert.get("id"), value=alert)

            record_metadata = future.get(timeout=10)
            logger.debug(
                f"Alert sent to {record_metadata.topic}:{record_metadata.partition}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False

    def _mock_send_alert(self, alert: Dict[str, Any]) -> None:
        """Mock send alert for testing."""
        logger.info(
            f"[MOCK] Alert sent: {alert.get('title')} (Severity: {alert.get('severity')})"
        )

    def close(self) -> None:
        """Close the producer."""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            logger.info("Kafka producer closed")
