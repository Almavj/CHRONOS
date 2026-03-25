"""CHRONOS Main Detection Engine"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import signal
import sys

from chronos.config import config
from chronos.core.analytics.temporal import TemporalAnalyzer
from chronos.core.analytics.graph import GraphDetector
from chronos.core.analytics.identity import IdentityDetector
from chronos.data.pipeline.kafka_consumer import KafkaEventConsumer
from chronos.data.collectors.elasticsearch_client import ElasticsearchClient
from chronos.core.detection.alert import Alert, AlertSeverity
from chronos.soar.orchestration.response_orchestrator import ResponseOrchestrator
from chronos.data.pipeline.kafka_producer import KafkaAlertProducer

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Main detection engine coordinating all detection modules."""

    def __init__(self):
        self.config = config
        self.running = False
        self.temporal_analyzer = None
        self.graph_detector = None
        self.identity_detector = None
        self.event_consumer = None
        self.alert_producer = None
        self.orchestrator = None
        self.es_client = None
        self.detection_threads = []
        self.event_buffer: List[Dict[str, Any]] = []
        self.buffer_lock = threading.Lock()

    def initialize(self) -> None:
        """Initialize all detection components."""
        logger.info("Initializing CHRONOS Detection Engine...")

        tba_config = self.config.get("tba", {})
        beaconing_enabled = tba_config.get("beaconing", {}).get("enabled", False)
        dga_enabled = tba_config.get("dga", {}).get("enabled", False)

        if beaconing_enabled or dga_enabled:
            self.temporal_analyzer = TemporalAnalyzer(tba_config)
            logger.info(
                f"Temporal Behavior Analysis module initialized (beaconing={beaconing_enabled}, dga={dga_enabled})"
            )
        else:
            logger.info("Temporal Behavior Analysis module disabled in config")

        graph_config = self.config.get("graph", {})
        lm_enabled = graph_config.get("lateral_movement", {}).get("enabled", False)

        if lm_enabled:
            self.graph_detector = GraphDetector(graph_config, self.config.neo4j_config)
            logger.info("Graph-based Detection module initialized")
        else:
            logger.info("Graph-based Detection module disabled in config")

        identity_config = self.config.get("identity", {})
        it_enabled = identity_config.get("impossible_travel", {}).get("enabled", False)

        if it_enabled:
            self.identity_detector = IdentityDetector(identity_config)
            logger.info("Identity Threat Detection module initialized")
        else:
            logger.info("Identity Threat Detection module disabled in config")

        kafka_config = self.config.kafka_config
        kafka_servers = kafka_config.get("bootstrap_servers")
        kafka_topic = kafka_config.get("topics", {}).get("events", "chronos-events")

        logger.info(f"Connecting to Kafka: {kafka_servers}, topic: {kafka_topic}")

        self.event_consumer = KafkaEventConsumer(
            kafka_servers,
            kafka_topic,
            kafka_config.get("consumer_group", "chronos-detectors"),
            self._process_event,
        )

        self.alert_producer = KafkaAlertProducer(
            kafka_servers,
            kafka_config.get("topics", {}).get("alerts", "chronos-alerts"),
        )

        soar_config = self.config.get("soar", {})
        self.orchestrator = ResponseOrchestrator(soar_config.get("auto_response", {}))

        es_config = self.config.elasticsearch_config
        self.es_client = ElasticsearchClient(
            es_config.get("hosts"), es_config.get("username"), es_config.get("password")
        )

        logger.info("CHRONOS Detection Engine initialized successfully")

    def _process_event(self, event: Dict[str, Any]) -> None:
        """Process a single event through all detection modules."""
        with self.buffer_lock:
            self.event_buffer.append(event)
            if len(self.event_buffer) > 1000:
                self.event_buffer = self.event_buffer[-500:]

        event_type = event.get("event_type", "")

        if event_type in ["dns_query", "network_connection"] and self.temporal_analyzer:
            try:
                beacon_alerts = self.temporal_analyzer.detect_beaconing([event])
                for alert in beacon_alerts:
                    self._handle_alert(alert)
            except Exception as e:
                logger.error(f"Error in temporal analysis: {e}")

            try:
                dga_alerts = self.temporal_analyzer.detect_dga([event])
                for alert in dga_alerts:
                    self._handle_alert(alert)
            except Exception as e:
                logger.error(f"Error in DGA detection: {e}")

        if event_type == "authentication" and self.identity_detector:
            try:
                auth_alerts = self.identity_detector.analyze_authentication(event)
                for alert in auth_alerts:
                    self._handle_alert(alert)
            except Exception as e:
                logger.error(f"Error in identity analysis: {e}")

        if (
            event_type in ["process_creation", "network_connection"]
            and self.graph_detector
        ):
            try:
                lateral_alerts = self.graph_detector.analyze_event(event)
                for alert in lateral_alerts:
                    self._handle_alert(alert)
            except Exception as e:
                logger.error(f"Error in graph analysis: {e}")

    def _run_detection_cycle(self) -> None:
        """Run periodic detection on buffered events."""
        logger.debug("Running detection cycle...")

        if self.temporal_analyzer:
            with self.buffer_lock:
                events = list(self.event_buffer)

            if events:
                try:
                    alerts = self.temporal_analyzer.batch_analyze(events)
                    for alert in alerts:
                        self._handle_alert(alert)
                except Exception as e:
                    logger.error(f"Batch analysis error: {e}")

    def _handle_alert(self, alert: Alert) -> None:
        """Handle detected alert."""
        logger.info(f"Alert generated: {alert.title} (Severity: {alert.severity})")

        self.alert_producer.send_alert(alert.to_dict())

        if self.orchestrator:
            self.orchestrator.evaluate_response(alert)

    def start(self) -> None:
        """Start the detection engine."""
        if self.running:
            logger.warning("Engine already running")
            return

        self.running = True
        logger.info("Starting CHRONOS Detection Engine...")

        self.event_consumer.start_consuming()

        detection_thread = threading.Thread(target=self._detection_loop, daemon=True)
        detection_thread.start()
        self.detection_threads.append(detection_thread)

        logger.info("CHRONOS Detection Engine is running")

    def stop(self) -> None:
        """Stop the detection engine."""
        logger.info("Stopping CHRONOS Detection Engine...")
        self.running = False

        if self.event_consumer:
            self.event_consumer.stop_consuming()

        for thread in self.detection_threads:
            thread.join(timeout=5)

        if self.alert_producer:
            self.alert_producer.close()

        logger.info("CHRONOS Detection Engine stopped")

    def _detection_loop(self) -> None:
        """Main detection loop."""
        while self.running:
            try:
                self._run_detection_cycle()
            except Exception as e:
                logger.error(f"Detection loop error: {e}")
            finally:
                import time

                time.sleep(5)

    def get_status(self) -> Dict[str, Any]:
        """Get current engine status."""
        return {
            "running": self.running,
            "event_buffer_size": len(self.event_buffer),
            "modules": {
                "temporal": self.temporal_analyzer is not None,
                "graph": self.graph_detector is not None,
                "identity": self.identity_detector is not None,
            },
        }


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info("Received shutdown signal")
    sys.exit(0)


def main():
    """Main entry point for the detection engine."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    engine = DetectionEngine()
    engine.initialize()
    engine.start()

    logger.info("Detection engine running. Press Ctrl+C to stop.")

    try:
        while engine.running:
            status = engine.get_status()
            logger.info(
                f"Status: running={status['running']}, "
                f"buffer_size={status['event_buffer_size']}, "
                f"modules=temporal:{status['modules']['temporal']} "
                f"graph:{status['modules']['graph']} "
                f"identity:{status['modules']['identity']}"
            )
            import time

            time.sleep(30)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        logger.info("Engine stopped")


if __name__ == "__main__":
    main()
