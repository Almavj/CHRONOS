#!/usr/bin/env python3
"""
Data Collection Orchestrator
Manages all data collectors (Sysmon, Zeek, CloudTrail) and forwards to Kafka
"""

import os
import sys
import logging
import signal
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime

import yaml

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class DataCollectionOrchestrator:
    """Orchestrates all data collectors."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.collectors = []
        self.running = False
        self.kafka_producer = None

    def _create_kafka_producer(self):
        """Create Kafka producer."""
        kafka_config = self.config.get("kafka", {})
        bootstrap_servers = kafka_config.get("bootstrap_servers", "localhost:9092")

        try:
            from chronos.data.pipeline.kafka_producer import KafkaEventProducer

            self.kafka_producer = KafkaEventProducer(
                bootstrap_servers,
                kafka_config.get("topics", {}).get("events", "chronos-events"),
            )
            logger.info(f"Kafka producer connected to {bootstrap_servers}")
            return True
        except Exception as e:
            logger.error(f"Failed to create Kafka producer: {e}")
            return False

    def _start_sysmon_collector(self):
        """Start Sysmon collector."""
        sysmon_config = self.config.get("data_sources", {}).get("sysmon", {})
        if not sysmon_config.get("enabled"):
            logger.info("Sysmon collector disabled")
            return

        try:
            from chronos.data.collectors.windows.sysmon_collector import SysmonCollector

            collector = SysmonCollector(sysmon_config, self.kafka_producer)
            thread = threading.Thread(target=collector.run, daemon=True)
            thread.start()
            self.collectors.append(("sysmon", thread))
            logger.info("Sysmon collector started")
        except Exception as e:
            logger.error(f"Failed to start Sysmon collector: {e}")

    def _start_zeek_collector(self):
        """Start Zeek collector."""
        zeek_config = self.config.get("data_sources", {}).get("zeek", {})
        if not zeek_config.get("enabled"):
            logger.info("Zeek collector disabled")
            return

        try:
            from chronos.data.collectors.network.zeek_collector import ZeekCollector

            collector = ZeekCollector(zeek_config, self.kafka_producer)
            thread = threading.Thread(target=collector.run, daemon=True)
            thread.start()
            self.collectors.append(("zeek", thread))
            logger.info("Zeek collector started")
        except Exception as e:
            logger.error(f"Failed to start Zeek collector: {e}")

    def _start_cloudtrail_collector(self):
        """Start CloudTrail collector."""
        cloudtrail_config = self.config.get("data_sources", {}).get("cloudtrail", {})
        if not cloudtrail_config.get("enabled"):
            logger.info("CloudTrail collector disabled")
            return

        try:
            from chronos.data.collectors.aws.cloudtrail_collector import (
                CloudTrailCollector,
            )

            collector = CloudTrailCollector(cloudtrail_config, self.kafka_producer)
            thread = threading.Thread(target=collector.run, daemon=True)
            thread.start()
            self.collectors.append(("cloudtrail", thread))
            logger.info("CloudTrail collector started")
        except Exception as e:
            logger.error(f"Failed to start CloudTrail collector: {e}")

    def _start_windows_events_collector(self):
        """Start Windows Events collector."""
        windows_config = self.config.get("data_sources", {}).get("windows_events", {})
        if not windows_config.get("enabled"):
            logger.info("Windows Events collector disabled")
            return

        logger.info("Windows Events collector uses Sysmon collector (same source)")

    def start(self):
        """Start all collectors."""
        logger.info("=" * 50)
        logger.info("Starting CHRONOS Data Collection Orchestrator")
        logger.info("=" * 50)

        self.running = True

        if self.config.get("services", {}).get("kafka", {}).get("enabled", False):
            self._create_kafka_producer()
        else:
            logger.warning("Kafka not enabled - collectors will run without output")

        self._start_sysmon_collector()
        self._start_zeek_collector()
        self._start_cloudtrail_collector()
        self._start_windows_events_collector()

        if not self.collectors:
            logger.warning("No collectors were started!")

        logger.info(f"Started {len(self.collectors)} collectors")

    def stop(self):
        """Stop all collectors."""
        logger.info("Stopping data collectors...")
        self.running = False

        if self.kafka_producer:
            self.kafka_producer.close()

        logger.info("All collectors stopped")

    def wait(self):
        """Wait for all collectors."""
        try:
            while self.running:
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                import time

                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Config file not found: {config_path}")
        return {}
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return {}


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="CHRONOS Data Collection Orchestrator")
    parser.add_argument(
        "--config", default="config/config.yaml", help="Config file path"
    )
    parser.add_argument("--kafka", help="Override Kafka bootstrap servers")

    args = parser.parse_args()

    config = load_config(args.config)

    if args.kafka:
        if "kafka" not in config:
            config["kafka"] = {}
        config["kafka"]["bootstrap_servers"] = args.kafka

    orchestrator = DataCollectionOrchestrator(config)

    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        orchestrator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    orchestrator.start()
    orchestrator.wait()


if __name__ == "__main__":
    main()
