#!/usr/bin/env python3
"""
AWS CloudTrail Collector
Collects AWS CloudTrail events and forwards to Kafka
"""

import os
import sys
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import threading

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


EVENT_MAP = {
    "ConsoleLogin": "authentication",
    "CreateUser": "user_creation",
    "DeleteUser": "user_deletion",
    "CreateRole": "role_creation",
    "DeleteRole": "role_deletion",
    "AttachUserPolicy": "policy_change",
    "DetachUserPolicy": "policy_change",
    "PutUserPolicy": "policy_change",
    "DeleteUserPolicy": "policy_change",
    "CreateAccessKey": "credential_creation",
    "DeleteAccessKey": "credential_deletion",
    "CreateInstance": "resource_creation",
    "RunInstances": "resource_creation",
    "TerminateInstances": "resource_termination",
    "CreateSecurityGroup": "security_group_change",
    "DeleteSecurityGroup": "security_group_change",
    "AuthorizeSecurityGroupIngress": "security_group_change",
    "RevokeSecurityGroupIngress": "security_group_change",
    "CreateBucket": "storage_creation",
    "DeleteBucket": "storage_deletion",
    "PutObject": "data_upload",
    "DeleteObject": "data_deletion",
    "CreateFunction": "lambda_creation",
    "UpdateFunction": "lambda_update",
    "CreateTrail": "cloudtrail_change",
    "UpdateTrail": "cloudtrail_change",
    "StopLogging": "cloudtrail_change",
    "AssumeRole": "authentication",
    "SwitchRole": "authentication",
}


@dataclass
class CloudTrailEvent:
    """CloudTrail event data structure."""

    event_id: str
    event_name: str
    event_type: str
    timestamp: str
    account_id: str
    region: str
    user_identity: str
    user_arn: str
    source_ip: str
    user_agent: str
    event_source: str
    request_parameters: Dict[str, Any]
    response_elements: Dict[str, Any]
    aws_region: str
    recipient_account: str

    def to_event(self) -> Dict[str, Any]:
        return {
            "event_type": f"cloudtrail_{self.event_type}",
            "event_id": self.event_id,
            "event_name": self.event_name,
            "timestamp": self.timestamp,
            "account_id": self.account_id,
            "region": self.region,
            "user": self.user_identity,
            "user_arn": self.user_arn,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "event_source": self.event_source,
            "request_parameters": self.request_parameters,
            "response_elements": self.response_elements,
            "cloud_provider": "aws",
        }


class CloudTrailCollector:
    """AWS CloudTrail event collector."""

    def __init__(self, config: Dict[str, Any], kafka_producer):
        self.config = config
        self.kafka_producer = kafka_producer

        self.region = config.get("region", "us-east-1")
        self.s3_bucket = config.get("s3_bucket")
        self.cloudtrail_client = None
        self.s3_client = None

        self.event_history = []
        self.last_processed_time = None

    def connect(self) -> bool:
        """Connect to AWS."""
        try:
            import boto3

            self.cloudtrail_client = boto3.client(
                "cloudtrail",
                region_name=self.region,
            )

            if self.s3_bucket:
                self.s3_client = boto3.client(
                    "s3",
                    region_name=self.region,
                )

            logger.info(f"Connected to AWS CloudTrail in {self.region}")
            return True

        except ImportError:
            logger.error("boto3 not installed. Run: pip install boto3")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to AWS: {e}")
            return False

    def parse_event(self, event: Dict[str, Any]) -> CloudTrailEvent:
        """Parse CloudTrail event."""
        event_name = event.get("EventName", "Unknown")
        event_type = EVENT_MAP.get(event_name, "unknown")

        user_identity = "Unknown"
        user_arn = ""
        if "userIdentity" in event:
            ui = event["userIdentity"]
            if ui.get("type") == "Root":
                user_identity = "root"
            else:
                user_identity = ui.get("userName", ui.get("arn", "Unknown"))
            user_arn = ui.get("arn", "")

        return CloudTrailEvent(
            event_id=event.get("EventID", ""),
            event_name=event_name,
            event_type=event_type,
            timestamp=event.get("EventTime", datetime.utcnow().isoformat()),
            account_id=event.get("RecipientAccountId", ""),
            region=event.get("AWSRegion", ""),
            user_identity=user_identity,
            user_arn=user_arn,
            source_ip=event.get("sourceIPAddress", ""),
            user_agent=event.get("userAgent", ""),
            event_source=event.get("eventSource", ""),
            request_parameters=event.get("requestParameters", {}),
            response_elements=event.get("responseElements", {}),
            aws_region=event.get("AWSRegion", ""),
            recipient_account=event.get("RecipientAccountId", ""),
        )

    def lookup_events(
        self, start_time: datetime = None, max_results: int = 50
    ) -> List[CloudTrailEvent]:
        """Lookup CloudTrail events."""
        if not self.cloudtrail_client:
            return []

        try:
            lookup_attrs = []

            if start_time:
                lookup_attrs.append(
                    {
                        "AttributeKey": "StartTime",
                        "AttributeValue": start_time.isoformat(),
                    }
                )

            params = {"MaxResults": max_results}
            if lookup_attrs:
                params["LookupAttributes"] = lookup_attrs

            response = self.cloudtrail_client.lookup_events(**params)

            events = []
            for event_dict in response.get("Events", []):
                ct_event = self.parse_event(event_dict)
                events.append(ct_event)

                if (
                    self.last_processed_time is None
                    or ct_event.timestamp > self.last_processed_time
                ):
                    self.last_processed_time = ct_event.timestamp

            return events

        except Exception as e:
            logger.error(f"Error looking up CloudTrail events: {e}")
            return []

    def process_s3_objects(self):
        """Process CloudTrail logs from S3."""
        if not self.s3_client or not self.s3_bucket:
            return

        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.s3_bucket, Prefix="AWSLogs/"
            )

            for obj in response.get("Contents", [])[-10:]:
                key = obj["Key"]
                logger.debug(f"Processing: {key}")

        except Exception as e:
            logger.error(f"Error processing S3 objects: {e}")

    def send_events(self, events: List[CloudTrailEvent]):
        """Send events to Kafka."""
        for event in events:
            event_dict = event.to_event()

            if self.kafka_producer:
                self.kafka_producer.send_event(event_dict)
            else:
                logger.debug(
                    f"CloudTrail event: {event_dict['event_type']} - {event_dict['event_name']}"
                )

    def run(self):
        """Run the CloudTrail collector."""
        logger.info("Starting CloudTrail Collector...")

        if not self.connect():
            logger.error("Failed to connect to AWS, exiting")
            return

        while True:
            try:
                events = self.lookup_events(max_results=100)

                if events:
                    self.send_events(events)
                    logger.info(f"Processed {len(events)} CloudTrail events")

                import time

                interval = self.config.get("interval", 30)
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("CloudTrail collector stopped")
                break
            except Exception as e:
                logger.error(f"Error in CloudTrail collector: {e}")
                import time

                time.sleep(60)


class CloudWatchCloudTrailCollector:
    """Alternative: Collect CloudTrail events via CloudWatch Logs."""

    def __init__(self, config: Dict[str, Any], kafka_producer):
        self.config = config
        self.kafka_producer = kafka_producer
        self.region = config.get("region", "us-east-1")
        self.logs_client = None
        self.log_group = f"arn:aws:logs:{self.region}:{config.get('account_id', '')}:log-group:CloudTrail:*"

    def connect(self) -> bool:
        """Connect to CloudWatch."""
        try:
            import boto3

            self.logs_client = boto3.client(
                "logs",
                region_name=self.region,
            )

            logger.info(f"Connected to CloudWatch Logs in {self.region}")
            return True

        except ImportError:
            logger.error("boto3 not installed")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to CloudWatch: {e}")
            return False

    def fetch_events(self, limit: int = 100):
        """Fetch CloudTrail events from CloudWatch Logs."""
        if not self.logs_client:
            return []

        try:
            response = self.logs_client.filter_log_events(
                logGroupName=f"CloudTrail/{self.region}",
                limit=limit,
            )

            events = []
            for event in response.get("events", []):
                try:
                    message = json.loads(event["message"])
                    ct_event = self.parse_event(message)
                    events.append(ct_event)
                except:
                    pass

            return events

        except Exception as e:
            logger.error(f"Error fetching CloudWatch events: {e}")
            return []


def main():
    """Standalone CloudTrail collector entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="AWS CloudTrail Collector")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--s3-bucket", help="S3 bucket for CloudTrail logs")
    parser.add_argument("--kafka", help="Kafka bootstrap servers")

    args = parser.parse_args()

    kafka_producer = None
    if args.kafka:
        try:
            from chronos.data.pipeline.kafka_producer import KafkaEventProducer

            kafka_producer = KafkaEventProducer(args.kafka, "chronos-events")
        except Exception as e:
            logger.warning(f"Kafka producer not available: {e}")

    config = {
        "region": args.region,
        "s3_bucket": args.s3_bucket,
        "interval": 30,
    }

    collector = CloudTrailCollector(config, kafka_producer)
    collector.run()


if __name__ == "__main__":
    main()
