#!/usr/bin/env python3
"""
Event Sender - Sends security events to Kafka for testing
Usage: python event_sender.py [--count N] [--interval SECONDS]
"""

import json
import argparse
import time
import random
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

SAMPLE_EVENTS = [
    {
        "event_type": "authentication",
        "user": "jsmith",
        "source_ip": "10.0.10.105",
        "destination_ip": "192.168.1.10",
        "success": True,
        "timestamp": "",
    },
    {
        "event_type": "authentication",
        "user": "admin",
        "source_ip": "10.0.10.200",
        "destination_ip": "192.168.1.10",
        "success": False,
        "failed_login": 1,
        "timestamp": "",
    },
    {
        "event_type": "network_connection",
        "source_ip": "10.0.10.100",
        "destination_ip": "45.33.32.156",
        "destination_port": 443,
        "protocol": "TCP",
        "bytes_out": 2048,
        "timestamp": "",
    },
    {
        "event_type": "network_connection",
        "source_ip": "10.0.10.100",
        "destination_ip": "185.234.219.47",
        "destination_port": 443,
        "protocol": "TCP",
        "bytes_out": 524288,
        "timestamp": "",
    },
    {
        "event_type": "dns_query",
        "query_name": "malicious-c2.evil.com",
        "source_ip": "10.0.10.100",
        "timestamp": "",
    },
    {
        "event_type": "dns_query",
        "query_name": "api.stealcware.com",
        "source_ip": "10.0.10.105",
        "timestamp": "",
    },
    {
        "event_type": "process_creation",
        "command": "powershell -enc SQBFAFgAIAA=",
        "parent_process": "explorer.exe",
        "hostname": "WORKSTATION-01",
        "user": "jsmith",
        "timestamp": "",
    },
    {
        "event_type": "file_access",
        "hostname": "FILE-SERVER-01",
        "file_name": "confidential.xlsx",
        "user": "admin",
        "timestamp": "",
    },
    {
        "event_type": "authentication",
        "user": "testuser",
        "source_ip": "203.0.113.50",
        "source_geo": {"latitude": 35.6762, "longitude": 139.6503},
        "destination_ip": "192.168.1.10",
        "success": True,
        "timestamp": "",
    },
    {
        "event_type": "authentication",
        "user": "testuser",
        "source_ip": "198.51.100.25",
        "source_geo": {"latitude": 51.5074, "longitude": -0.1278},
        "destination_ip": "192.168.1.10",
        "success": True,
        "timestamp": "",
    },
]


def send_events(bootstrap_servers: str, topic: str, count: int, interval: float):
    """Send events to Kafka."""
    try:
        from kafka import KafkaProducer

        producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
        logger.info(f"Connected to Kafka at {bootstrap_servers}")
    except ImportError:
        logger.error("kafka-python not installed. Run: pip install kafka-python")
        return
    except Exception as e:
        logger.error(f"Failed to connect to Kafka: {e}")
        return

    for i in range(count):
        event = random.choice(SAMPLE_EVENTS).copy()
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["event_id"] = f"evt-{i}-{int(time.time())}"

        if event["event_type"] == "authentication":
            event["failed_login"] = (
                random.randint(1, 15) if not event.get("success") else 0
            )

        try:
            producer.send(topic, value=event)
            logger.info(
                f"Sent event {i + 1}/{count}: {event['event_type']} from {event.get('source_ip', 'unknown')}"
            )
        except Exception as e:
            logger.error(f"Failed to send event: {e}")

        if interval > 0 and i < count - 1:
            time.sleep(interval)

    producer.flush()
    producer.close()
    logger.info(f"Sent {count} events to {topic}")


def main():
    parser = argparse.ArgumentParser(description="Send security events to Kafka")
    parser.add_argument(
        "--kafka", default="localhost:9092", help="Kafka bootstrap servers"
    )
    parser.add_argument("--topic", default="chronos-events", help="Kafka topic")
    parser.add_argument(
        "--count", type=int, default=10, help="Number of events to send"
    )
    parser.add_argument(
        "--interval", type=float, default=1.0, help="Interval between events (seconds)"
    )
    parser.add_argument(
        "--continuous", action="store_true", help="Send events continuously"
    )

    args = parser.parse_args()

    if args.continuous:
        logger.info(f"Starting continuous event generation (Ctrl+C to stop)")
        try:
            i = 0
            while True:
                send_events(args.kafka, args.topic, 1, 0)
                time.sleep(args.interval)
                i += 1
                if i % 10 == 0:
                    logger.info(f"Sent {i} events so far...")
        except KeyboardInterrupt:
            logger.info(f"Stopped after sending {i} events")
    else:
        send_events(args.kafka, args.topic, args.count, args.interval)


if __name__ == "__main__":
    main()
