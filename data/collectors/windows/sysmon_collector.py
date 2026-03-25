#!/usr/bin/env python3
"""
Windows Sysmon Collector
Collects Windows Sysmon events and forwards to Kafka
"""

import os
import sys
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field

import yaml

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


SYSMON_EVENT_IDS = {
    1: "ProcessCreate",
    2: "FileCreateTime",
    3: "NetworkConnection",
    4: "SysmonServiceStateChange",
    5: "ProcessTerminated",
    6: "DriverLoad",
    7: "ImageLoad",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEvent",
    13: "RegistryEvent",
    14: "RegistryEvent",
    15: "FileCreateStreamHash",
    16: "ServiceConfigurationChange",
    17: "NamedPipeEvent",
    18: "NamedPipeEvent",
    19: "WmiEvent",
    20: "WmiEvent",
    21: "WmiEvent",
    22: "DNSEvent",
    23: "FileDelete",
    24: "ClipboardChange",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
    27: "FileBlockExecutable",
    28: "FileBlockExecutable",
}


@dataclass
class SysmonEvent:
    """Sysmon event data structure."""

    event_id: int
    event_name: str
    timestamp: str
    computer: str
    user: str
    process_id: int
    process_name: str
    process_path: str
    process_command_line: str
    parent_process_id: int = 0
    parent_process_name: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: int = 0
    protocol: str = ""
    image_loaded: str = ""
    target_object: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": f"sysmon_{self.event_name.lower()}",
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "computer": self.computer,
            "user": self.user,
            "process": {
                "pid": self.process_id,
                "name": self.process_name,
                "path": self.process_path,
                "command_line": self.process_command_line,
                "parent_pid": self.parent_process_id,
                "parent_name": self.parent_process_name,
            },
            "network": {
                "source_ip": self.source_ip,
                "destination_ip": self.destination_ip,
                "destination_port": self.destination_port,
                "protocol": self.protocol,
            },
            "details": self.details,
        }


class WindowsEventLogCollector:
    """Windows Event Log collector using win32evtlog."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.event_ids = config.get("event_ids", list(SYSMON_EVENT_IDS.keys()))
        self.last_position = {}

    def parse_sysmon_event(self, event_data: Dict[str, Any]) -> Optional[SysmonEvent]:
        """Parse raw Windows event into SysmonEvent."""
        try:
            event_id = int(event_data.get("EventID", 0))
            if event_id not in SYSMON_EVENT_IDS:
                return None

            system = event_data.get("System", {})
            event_data_xml = event_data.get("EventData", {})

            def get_field(name: str) -> str:
                return event_data_xml.get(name, "")

            timestamp = system.get("TimeCreated", {}).get(
                "@SystemTime", datetime.utcnow().isoformat()
            )
            computer = system.get("Computer", "")
            user = event_data_xml.get("User", "")

            if event_id == 1:
                return SysmonEvent(
                    event_id=event_id,
                    event_name=SYSMON_EVENT_IDS[event_id],
                    timestamp=timestamp,
                    computer=computer,
                    user=user,
                    process_id=int(get_field("ProcessId") or 0),
                    process_name=get_field("Image"),
                    process_path=get_field("Image"),
                    process_command_line=get_field("CommandLine"),
                    parent_process_id=int(get_field("ParentProcessId") or 0),
                    parent_process_name=get_field("ParentImage"),
                    details={
                        "integrity_level": get_field("IntegrityLevel"),
                        "session_id": get_field("SessionId"),
                    },
                )

            elif event_id == 3:
                return SysmonEvent(
                    event_id=event_id,
                    event_name=SYSMON_EVENT_IDS[event_id],
                    timestamp=timestamp,
                    computer=computer,
                    user=user,
                    process_id=int(get_field("ProcessId") or 0),
                    process_name=get_field("Image"),
                    process_path=get_field("Image"),
                    process_command_line=get_field("CommandLine"),
                    source_ip=get_field("SourceIp"),
                    destination_ip=get_field("DestinationIp"),
                    destination_port=int(get_field("DestinationPort") or 0),
                    protocol=get_field("Protocol"),
                    details={
                        "initiated": get_field("Initiated"),
                        "source_port": get_field("SourcePort"),
                    },
                )

            elif event_id == 7:
                return SysmonEvent(
                    event_id=event_id,
                    event_name=SYSMON_EVENT_IDS[event_id],
                    timestamp=timestamp,
                    computer=computer,
                    user=user,
                    process_id=int(get_field("ProcessId") or 0),
                    process_name=get_field("Image"),
                    process_path=get_field("Image"),
                    process_command_line="",
                    image_loaded=get_field("ImageLoaded"),
                    details={
                        "signed": get_field("Signed"),
                        "signature": get_field("Signature"),
                    },
                )

            elif event_id == 10:
                return SysmonEvent(
                    event_id=event_id,
                    event_name=SYSMON_EVENT_IDS[event_id],
                    timestamp=timestamp,
                    computer=computer,
                    user=user,
                    process_id=int(get_field("SourceProcessId") or 0),
                    process_name=get_field("SourceImage"),
                    process_path=get_field("SourceImage"),
                    process_command_line="",
                    target_object=get_field("TargetImage"),
                    details={
                        "granted_access": get_field("GrantedAccess"),
                        "call_trace": get_field("CallTrace"),
                    },
                )

            elif event_id == 11:
                return SysmonEvent(
                    event_id=event_id,
                    event_name=SYSMON_EVENT_IDS[event_id],
                    timestamp=timestamp,
                    computer=computer,
                    user=user,
                    process_id=int(get_field("ProcessId") or 0),
                    process_name=get_field("Image"),
                    process_path=get_field("Image"),
                    process_command_line="",
                    target_object=get_field("TargetFilename"),
                    details={"creation_time": get_field("CreationUtcTime")},
                )

            elif event_id in [12, 13, 14]:
                return SysmonEvent(
                    event_id=event_id,
                    event_name=SYSMON_EVENT_IDS[event_id],
                    timestamp=timestamp,
                    computer=computer,
                    user=user,
                    process_id=int(get_field("ProcessId") or 0),
                    process_name=get_field("Image"),
                    process_path=get_field("Image"),
                    process_command_line="",
                    target_object=get_field("TargetObject"),
                    details={"operation": get_field("EventType")},
                )

            elif event_id == 22:
                return SysmonEvent(
                    event_id=event_id,
                    event_name=SYSMON_EVENT_IDS[event_id],
                    timestamp=timestamp,
                    computer=computer,
                    user=user,
                    process_id=0,
                    process_name="dns",
                    process_path="",
                    process_command_line="",
                    destination_ip=get_field("QueryResults"),
                    details={
                        "query_name": get_field("QueryName"),
                        "query_status": get_field("QueryStatus"),
                    },
                )

            elif event_id == 23:
                return SysmonEvent(
                    event_id=event_id,
                    event_name=SYSMON_EVENT_IDS[event_id],
                    timestamp=timestamp,
                    computer=computer,
                    user=user,
                    process_id=int(get_field("ProcessId") or 0),
                    process_name=get_field("Image"),
                    process_path=get_field("Image"),
                    process_command_line="",
                    target_object=get_field("TargetFilename"),
                    details={
                        "archived": get_field("Archived"),
                        "is_executable": get_field("IsExecutable"),
                    },
                )

            return SysmonEvent(
                event_id=event_id,
                event_name=SYSMON_EVENT_IDS.get(event_id, "Unknown"),
                timestamp=timestamp,
                computer=computer,
                user=user,
                process_id=0,
                process_name="",
                process_path="",
                process_command_line="",
            )

        except Exception as e:
            logger.error(f"Error parsing Sysmon event: {e}")
            return None


class ElasticsearchSysmonReader:
    """Read Sysmon events from Elasticsearch."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.index_pattern = config.get("index", "windows-sysmon-*")
        self.event_ids = config.get("event_ids", list(SYSMON_EVENT_IDS.keys()))
        self.client = None
        self.last_timestamp = None

    def connect(self) -> bool:
        """Connect to Elasticsearch."""
        try:
            from elasticsearch import Elasticsearch

            hosts = self.config.get("hosts", ["http://localhost:9200"])
            username = self.config.get("username")
            password = self.config.get("password")

            if username and password:
                self.client = Elasticsearch(hosts, basic_auth=(username, password))
            else:
                self.client = Elasticsearch(hosts)

            logger.info(f"Connected to Elasticsearch: {hosts}")
            return True

        except ImportError:
            logger.error("elasticsearch-py not installed")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            return False

    def fetch_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch Sysmon events from Elasticsearch."""
        if not self.client:
            return []

        try:
            query = {
                "query": {"bool": {"must": [{"terms": {"event_id": self.event_ids}}]}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": limit,
            }

            if self.last_timestamp:
                query["query"]["bool"]["must"].append(
                    {"range": {"@timestamp": {"gt": self.last_timestamp}}}
                )

            result = self.client.search(index=self.index_pattern, body=query)
            events = []

            for hit in result["hits"]["hits"]:
                source = hit["_source"]
                if "@timestamp" in source:
                    self.last_timestamp = source["@timestamp"]
                events.append(source)

            logger.info(f"Fetched {len(events)} Sysmon events from Elasticsearch")
            return events

        except Exception as e:
            logger.error(f"Error fetching Sysmon events: {e}")
            return []


class SysmonCollector:
    """Main Sysmon collector orchestrator."""

    def __init__(self, config: Dict[str, Any], kafka_producer):
        self.config = config
        self.kafka_producer = kafka_producer

        self.source_type = config.get("source_type", "elasticsearch")

        if self.source_type == "elasticsearch":
            self.reader = ElasticsearchSysmonReader(config.get("elasticsearch", {}))
        else:
            self.reader = WindowsEventLogCollector(config)

        self.parser = WindowsEventLogCollector(config)

    def run(self):
        """Run the Sysmon collector."""
        logger.info("Starting Sysmon Collector...")

        if isinstance(self.reader, ElasticsearchSysmonReader):
            if not self.reader.connect():
                logger.error("Failed to connect to Elasticsearch, exiting")
                return

        while True:
            try:
                events = self.reader.fetch_events(limit=100)

                for event_data in events:
                    sysmon_event = self.parser.parse_sysmon_event(event_data)
                    if sysmon_event:
                        event_dict = sysmon_event.to_dict()
                        if self.kafka_producer:
                            self.kafka_producer.send_event(event_dict)
                        else:
                            logger.debug(f"Sysmon event: {event_dict['event_type']}")

                import time

                interval = self.config.get("interval", 5)
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Sysmon collector stopped")
                break
            except Exception as e:
                logger.error(f"Error in Sysmon collector: {e}")
                import time

                time.sleep(5)


def main():
    """Standalone Sysmon collector entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Sysmon Event Collector")
    parser.add_argument(
        "--config", default="config/config.yaml", help="Config file path"
    )
    parser.add_argument("--kafka", help="Kafka bootstrap servers")
    parser.add_argument("--elasticsearch", help="Elasticsearch hosts (comma-separated)")

    args = parser.parse_args()

    config = {
        "source_type": "elasticsearch",
        "elasticsearch": {
            "hosts": args.elasticsearch.split(",")
            if args.elasticsearch
            else ["http://localhost:9200"],
            "index": "windows-sysmon-*",
            "event_ids": list(SYSMON_EVENT_IDS.keys()),
        },
        "kafka": {
            "bootstrap_servers": args.kafka or "localhost:9092",
            "topic": "chronos-events",
        },
        "interval": 5,
    }

    kafka_producer = None
    if args.kafka:
        try:
            from chronos.data.pipeline.kafka_producer import KafkaEventProducer

            kafka_producer = KafkaEventProducer(
                config["kafka"]["bootstrap_servers"], config["kafka"]["topic"]
            )
        except Exception as e:
            logger.warning(f"Kafka producer not available: {e}")

    collector = SysmonCollector(config, kafka_producer)
    collector.run()


if __name__ == "__main__":
    main()
