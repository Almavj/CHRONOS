#!/usr/bin/env python3
"""
Zeek Network Log Collector
Collects and parses Zeek network logs (conn.log, dns.log, http.log, etc.)
"""

import os
import sys
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass
import threading

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class ZeekConnection:
    """Zeek connection log entry."""

    timestamp: str
    uid: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    duration: float
    bytes_sent: int
    bytes_received: int
    state: str

    def to_event(self) -> Dict[str, Any]:
        return {
            "event_type": "network_connection",
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.dest_ip,
            "destination_port": self.dest_port,
            "protocol": self.protocol,
            "duration": self.duration,
            "bytes_out": self.bytes_sent,
            "bytes_in": self.bytes_received,
            "state": self.state,
            "uid": self.uid,
        }


@dataclass
class ZeekDNS:
    """Zeek DNS log entry."""

    timestamp: str
    uid: str
    query_name: str
    query_type: str
    query_class: str
    rcode: str
    answers: List[str]
    source_ip: str
    dest_ip: str

    def to_event(self) -> Dict[str, Any]:
        return {
            "event_type": "dns_query",
            "timestamp": self.timestamp,
            "uid": self.uid,
            "query_name": self.query_name,
            "query_type": self.query_type,
            "query_class": self.query_class,
            "rcode": self.rcode,
            "answers": self.answers,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
        }


@dataclass
class ZeekHTTP:
    """Zeek HTTP log entry."""

    timestamp: str
    uid: str
    source_ip: str
    dest_ip: str
    dest_port: int
    method: str
    host: str
    uri: str
    user_agent: str
    status_code: int
    request_body_len: int
    response_body_len: int

    def to_event(self) -> Dict[str, Any]:
        return {
            "event_type": "http_request",
            "timestamp": self.timestamp,
            "uid": self.uid,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "method": self.method,
            "host": self.host,
            "uri": self.uri,
            "user_agent": self.user_agent,
            "status_code": self.status_code,
            "request_body_len": self.request_body_len,
            "response_body_len": self.response_body_len,
        }


@dataclass
class ZeekSSL:
    """Zeek SSL/TLS log entry."""

    timestamp: str
    uid: str
    source_ip: str
    dest_ip: str
    dest_port: int
    version: str
    cipher: str
    server_name: str
    subject: str
    issuer: str

    def to_event(self) -> Dict[str, Any]:
        return {
            "event_type": "ssl_connection",
            "timestamp": self.timestamp,
            "uid": self.uid,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "version": self.version,
            "cipher": self.cipher,
            "server_name": self.server_name,
            "subject": self.subject,
            "issuer": self.issuer,
        }


class ZeekLogParser:
    """Parser for Zeek log files."""

    @staticmethod
    def parse_zeek_tsv(line: str, fields: List[str]) -> Optional[Dict[str, Any]]:
        """Parse a Zeek TSV line into a dictionary."""
        if not line or line.startswith("#"):
            return None

        parts = line.split("\t")
        if len(parts) < len(fields):
            return None

        try:
            record = {}
            for i, field in enumerate(fields):
                value = parts[i] if i < len(parts) else "-"
                if value == "-" or value == "":
                    record[field] = None
                elif value.isdigit():
                    record[field] = int(value)
                elif re.match(r"^-?\d+\.?\d*$", value):
                    record[field] = float(value)
                else:
                    record[field] = value
            return record
        except Exception as e:
            logger.debug(f"Error parsing Zeek line: {e}")
            return None

    @staticmethod
    def parse_connection(
        fields: List[str], values: Dict[str, Any]
    ) -> Optional[ZeekConnection]:
        """Parse connection log entry."""
        try:
            return ZeekConnection(
                timestamp=values.get("ts", datetime.utcnow().isoformat()),
                uid=values.get("uid", ""),
                source_ip=values.get("id.orig_h", ""),
                source_port=int(values.get("id.orig_p", 0) or 0),
                dest_ip=values.get("id.resp_h", ""),
                dest_port=int(values.get("id.resp_p", 0) or 0),
                protocol=values.get("proto", "").lower(),
                duration=float(values.get("duration", 0) or 0),
                bytes_sent=int(values.get("orig_bytes", 0) or 0),
                bytes_received=int(values.get("resp_bytes", 0) or 0),
                state=values.get("conn_state", ""),
            )
        except Exception as e:
            logger.debug(f"Error parsing connection: {e}")
            return None

    @staticmethod
    def parse_dns(fields: List[str], values: Dict[str, Any]) -> Optional[ZeekDNS]:
        """Parse DNS log entry."""
        try:
            answers = []
            if values.get("answers"):
                answers = str(values["answers"]).split(",")

            return ZeekDNS(
                timestamp=values.get("ts", datetime.utcnow().isoformat()),
                uid=values.get("uid", ""),
                query_name=values.get("query", ""),
                query_type=values.get("qtype", ""),
                query_class=values.get("qclass", ""),
                rcode=values.get("rcode", ""),
                answers=answers,
                source_ip=values.get("id.orig_h", ""),
                dest_ip=values.get("id.resp_h", ""),
            )
        except Exception as e:
            logger.debug(f"Error parsing DNS: {e}")
            return None

    @staticmethod
    def parse_http(fields: List[str], values: Dict[str, Any]) -> Optional[ZeekHTTP]:
        """Parse HTTP log entry."""
        try:
            return ZeekHTTP(
                timestamp=values.get("ts", datetime.utcnow().isoformat()),
                uid=values.get("uid", ""),
                source_ip=values.get("id.orig_h", ""),
                dest_ip=values.get("id.resp_h", ""),
                dest_port=int(values.get("id.resp_p", 0) or 0),
                method=values.get("method", ""),
                host=values.get("host", ""),
                uri=values.get("uri", ""),
                user_agent=values.get("user_agent", ""),
                status_code=int(values.get("status_code", 0) or 0),
                request_body_len=int(values.get("request_body_len", 0) or 0),
                response_body_len=int(values.get("response_body_len", 0) or 0),
            )
        except Exception as e:
            logger.debug(f"Error parsing HTTP: {e}")
            return None

    @staticmethod
    def parse_ssl(fields: List[str], values: Dict[str, Any]) -> Optional[ZeekSSL]:
        """Parse SSL/TLS log entry."""
        try:
            return ZeekSSL(
                timestamp=values.get("ts", datetime.utcnow().isoformat()),
                uid=values.get("uid", ""),
                source_ip=values.get("id.orig_h", ""),
                dest_ip=values.get("id.resp_h", ""),
                dest_port=int(values.get("id.resp_p", 0) or 0),
                version=values.get("version", ""),
                cipher=values.get("cipher", ""),
                server_name=values.get("server_name", ""),
                subject=values.get("subject", ""),
                issuer=values.get("issuer", ""),
            )
        except Exception as e:
            logger.debug(f"Error parsing SSL: {e}")
            return None


CONN_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
]

DNS_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.resp_h",
    "query",
    "qtype",
    "qclass",
    "rcode",
    "answers",
]

HTTP_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.resp_h",
    "id.resp_p",
    "method",
    "host",
    "uri",
    "user_agent",
    "status_code",
    "request_body_len",
    "response_body_len",
]

SSL_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.resp_h",
    "id.resp_p",
    "version",
    "cipher",
    "server_name",
    "subject",
    "issuer",
]


class ZeekLogWatcher:
    """Watches Zeek log directory for new entries."""

    def __init__(self, log_dir: str, log_types: List[str], kafka_producer):
        self.log_dir = Path(log_dir)
        self.log_types = log_types
        self.kafka_producer = kafka_producer
        self.parser = ZeekLogParser()
        self.running = False
        self.file_positions = {}
        self.parsers = {
            "conn": (CONN_FIELDS, self.parser.parse_connection),
            "dns": (DNS_FIELDS, self.parser.parse_dns),
            "http": (HTTP_FIELDS, self.parser.parse_http),
            "ssl": (SSL_FIELDS, self.parser.parse_ssl),
        }

    def process_log_file(self, log_path: Path, log_type: str):
        """Process a single Zeek log file."""
        if log_type not in self.parsers:
            return

        fields, parse_func = self.parsers[log_type]
        file_key = str(log_path)

        if file_key not in self.file_positions:
            self.file_positions[file_key] = 0

        position = self.file_positions[file_key]

        try:
            with open(log_path, "r") as f:
                f.seek(position)
                for line in f:
                    if line.startswith("#"):
                        continue

                    values = self.parser.parse_zeek_tsv(line, fields)
                    if values:
                        event_data = parse_func(fields, values)
                        if event_data:
                            event = event_data.to_event()
                            if self.kafka_producer:
                                self.kafka_producer.send_event(event)
                            else:
                                logger.debug(f"Zeek event: {event['event_type']}")

                self.file_positions[file_key] = f.tell()

        except FileNotFoundError:
            del self.file_positions[file_key]
        except Exception as e:
            logger.error(f"Error processing {log_path}: {e}")

    def scan_logs(self):
        """Scan for new log files and process them."""
        for log_type in self.log_types:
            pattern = f"*.{log_type}.log"
            for log_path in self.log_dir.glob(pattern):
                self.process_log_file(log_path, log_type)

    def run(self):
        """Run the Zeek log watcher."""
        logger.info(f"Starting Zeek log watcher on {self.log_dir}")
        self.running = True

        while self.running:
            try:
                self.scan_logs()
            except Exception as e:
                logger.error(f"Error in Zeek watcher: {e}")

            import time

            time.sleep(5)

    def stop(self):
        """Stop the watcher."""
        self.running = False


class ZeekCollector:
    """Main Zeek collector orchestrator."""

    def __init__(self, config: Dict[str, Any], kafka_producer):
        self.config = config
        self.kafka_producer = kafka_producer

        self.log_path = config.get("log_path", "/opt/zeek/logs/current")
        self.log_types = config.get("log_types", ["conn", "dns", "http", "ssl"])

    def run(self):
        """Run the Zeek collector."""
        logger.info("Starting Zeek Collector...")

        watcher = ZeekLogWatcher(self.log_path, self.log_types, self.kafka_producer)

        try:
            watcher.run()
        except KeyboardInterrupt:
            logger.info("Zeek collector stopped")
            watcher.stop()


def main():
    """Standalone Zeek collector entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Zeek Log Collector")
    parser.add_argument(
        "--log-path", default="/opt/zeek/logs/current", help="Zeek log directory"
    )
    parser.add_argument("--kafka", help="Kafka bootstrap servers")
    parser.add_argument(
        "--log-types", default="conn,dns,http,ssl", help="Comma-separated log types"
    )

    args = parser.parse_args()

    kafka_producer = None
    if args.kafka:
        try:
            from chronos.data.pipeline.kafka_producer import KafkaEventProducer

            kafka_producer = KafkaEventProducer(args.kafka, "chronos-events")
        except Exception as e:
            logger.warning(f"Kafka producer not available: {e}")

    config = {
        "log_path": args.log_path,
        "log_types": args.log_types.split(","),
    }

    collector = ZeekCollector(config, kafka_producer)
    collector.run()


if __name__ == "__main__":
    main()
