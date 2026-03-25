"""
Kafka Event Consumer for CHRONOS
"""

import json
import logging
from typing import Callable, Dict, Any, Optional
from threading import Thread, Event

from chronos.config import config

logger = logging.getLogger(__name__)

try:
    from kafka import KafkaConsumer

    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logger.warning("Kafka not available. Using mock consumer.")


class KafkaEventConsumer:
    """Kafka consumer for security events."""

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
        event_handler: Callable[[Dict[str, Any]], Any],
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.event_handler = event_handler

        self.consumer: Optional[Any] = None
        self.running = Event()
        self.consume_thread: Optional[Thread] = None

        self._initialize_consumer()

    def _initialize_consumer(self) -> None:
        """Initialize Kafka consumer."""
        if not KAFKA_AVAILABLE:
            logger.info("Using mock Kafka consumer (kafka-python not installed)")
            self.consumer = None
            return

        try:
            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                enable_auto_commit=True,
                max_poll_interval_ms=300000,
            )
            logger.info(f"Kafka consumer initialized for topic: {self.topic}")
        except Exception as e:
            logger.error(f"Failed to initialize Kafka consumer: {e}")
            self.consumer = None

    def start_consuming(self) -> None:
        """Start consuming events."""
        if self.running.is_set():
            logger.warning("Consumer already running")
            return

        self.running.set()
        self.consume_thread = Thread(target=self._consume_loop, daemon=True)
        self.consume_thread.start()
        logger.info("Event consumer started")

    def stop_consuming(self) -> None:
        """Stop consuming events."""
        if not self.running.is_set():
            return

        self.running.clear()

        if self.consume_thread:
            self.consume_thread.join(timeout=10)

        if self.consumer:
            self.consumer.close()

        logger.info("Event consumer stopped")

    def _consume_loop(self) -> None:
        """Main consume loop."""
        if not self.consumer:
            self._mock_consume_loop()
            return

        logger.info("Starting Kafka consume loop")

        while self.running.is_set():
            try:
                records = self.consumer.poll(timeout_ms=1000)

                for topic_partition, messages in records.items():
                    for message in messages:
                        try:
                            event = message.value
                            self.event_handler(event)
                        except Exception as e:
                            logger.error(f"Error processing event: {e}")

            except Exception as e:
                logger.error(f"Error in consume loop: {e}")
                import time

                time.sleep(5)

    def _mock_consume_loop(self) -> None:
        """Mock consume loop for testing without Kafka."""
        logger.info("Running mock consume loop")

        import time

        sample_events = [
            {
                "event_type": "network_connection",
                "source_ip": "10.0.10.100",
                "destination_ip": "192.168.1.50",
                "destination_port": 443,
                "timestamp": "2026-03-08T10:00:00Z",
            },
            {
                "event_type": "authentication",
                "user": "jsmith",
                "source_ip": "10.0.10.105",
                "success": True,
                "timestamp": "2026-03-08T10:05:00Z",
            },
            {
                "event_type": "dns_query",
                "query_name": "malicious-c2.evil.com",
                "timestamp": "2026-03-08T10:10:00Z",
            },
        ]

        event_index = 0
        while self.running.is_set():
            event = sample_events[event_index % len(sample_events)].copy()
            event["timestamp"] = f"2026-03-08T10:{event_index % 60:02d}Z"

            try:
                self.event_handler(event)
            except Exception as e:
                logger.error(f"Error processing mock event: {e}")

            event_index += 1
            time.sleep(5)
