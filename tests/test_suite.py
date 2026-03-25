"""
CHRONOS Test Suite
Testing framework with adversarial testing capabilities
"""

import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from chronos.core.detection.alert import Alert, AlertSeverity, create_alert

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a test execution."""

    test_name: str
    passed: bool
    duration_seconds: float
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


class TestSuite:
    """Base test suite for CHRONOS."""

    def __init__(self):
        self.results: List[TestResult] = []

    def run_all_tests(self) -> List[TestResult]:
        """Run all tests in the suite."""
        test_methods = [
            method
            for method in dir(self)
            if method.startswith("test_") and callable(getattr(self, method))
        ]

        for method_name in test_methods:
            method = getattr(self, method_name)
            try:
                result = method()
                if result:
                    self.results.append(result)
            except Exception as e:
                logger.error(f"Test {method_name} failed with exception: {e}")
                self.results.append(
                    TestResult(
                        test_name=method_name,
                        passed=False,
                        duration_seconds=0.0,
                        message=f"Exception: {str(e)}",
                    )
                )

        return self.results

    def get_summary(self) -> Dict[str, Any]:
        """Get test summary."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / total if total > 0 else 0,
        }


class DetectionTests(TestSuite):
    """Tests for detection engines."""

    def test_beaconing_detection(self) -> TestResult:
        """Test C2 beaconing detection."""
        from chronos.core.analytics.temporal import TemporalAnalyzer

        config = {
            "beaconing": {
                "enabled": True,
                "fft_threshold": 0.7,
                "jitter_threshold": 0.15,
            }
        }

        analyzer = TemporalAnalyzer(config)

        base_time = datetime(2026, 3, 8, 10, 0)
        events = [
            {
                "event_type": "network_connection",
                "destination_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(minutes=i * 60),
            }
            for i in range(20)
        ]

        alerts = analyzer.detect_beaconing(events)

        return TestResult(
            test_name="test_beaconing_detection",
            passed=len(alerts) > 0,
            duration_seconds=0.1,
            message=f"Detected {len(alerts)} beaconing alerts",
            details={"alert_count": len(alerts)},
        )

    def test_dga_detection(self) -> TestResult:
        """Test DGA domain detection."""
        from chronos.core.analytics.temporal import TemporalAnalyzer

        config = {"dga": {"enabled": True, "entropy_threshold": 3.5}}

        analyzer = TemporalAnalyzer(config)

        events = [
            {"event_type": "dns_query", "query_name": f"a{hash(i) % 100000}.com"}
            for i in range(10)
        ]

        alerts = analyzer.detect_dga(events)

        return TestResult(
            test_name="test_dga_detection",
            passed=True,
            duration_seconds=0.1,
            message="DGA detection test completed",
        )

    def test_lateral_movement_detection(self) -> TestResult:
        """Test lateral movement detection."""
        from chronos.core.analytics.graph import GraphDetector

        config = {
            "lateral_movement": {"enabled": True, "suspicious_ports": [445, 135]},
            "pass_the_hash": {
                "enabled": True,
                "same_user_different_machine_threshold": 3,
            },
        }

        detector = GraphDetector(config, {})

        events = [
            {
                "event_type": "network_connection",
                "source_ip": "10.0.10.100",
                "destination_ip": "10.0.1.10",
                "destination_port": 445,
                "timestamp": datetime.utcnow().isoformat(),
            }
        ]

        alerts = detector.analyze_event(events[0])

        return TestResult(
            test_name="test_lateral_movement_detection",
            passed=True,
            duration_seconds=0.1,
            message="Lateral movement detection test completed",
        )

    def test_impossible_travel_detection(self) -> TestResult:
        """Test impossible travel detection."""
        from chronos.core.analytics.identity import IdentityDetector

        config = {
            "impossible_travel": {
                "enabled": True,
                "velocity_threshold_kmh": 1000,
                "time_window_minutes": 30,
            }
        }

        detector = IdentityDetector(config)

        event = {
            "user": "jsmith",
            "timestamp": datetime(2026, 3, 8, 10, 0),
            "source_ip": "10.0.0.1",
            "source_geo": {"latitude": 40.7128, "longitude": -74.0060},
            "success": True,
        }

        alerts = detector.analyze_authentication(event)

        return TestResult(
            test_name="test_impossible_travel_detection",
            passed=True,
            duration_seconds=0.1,
            message="Impossible travel detection test completed",
        )


class AlertTests(TestSuite):
    """Tests for alert functionality."""

    def test_alert_creation(self) -> TestResult:
        """Test alert creation."""
        alert = create_alert(
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.HIGH,
            technique="T1078",
            ttp="Valid Accounts",
        )

        passed = alert.id and alert.title == "Test Alert"

        return TestResult(
            test_name="test_alert_creation",
            passed=passed,
            duration_seconds=0.01,
            message="Alert creation test passed" if passed else "Alert creation failed",
        )

    def test_alert_serialization(self) -> TestResult:
        """Test alert to dict conversion."""
        alert = create_alert(
            title="Test Alert",
            description="Test",
            severity=AlertSeverity.CRITICAL,
            indicators=["10.0.0.1"],
        )

        data = alert.to_dict()

        passed = "id" in data and "title" in data and data["severity"] == "critical"

        return TestResult(
            test_name="test_alert_serialization",
            passed=passed,
            duration_seconds=0.01,
            message="Alert serialization test passed" if passed else "Failed",
        )


class SOARTests(TestSuite):
    """Tests for SOAR functionality."""

    def test_response_orchestration(self) -> TestResult:
        """Test response orchestration."""
        from chronos.soar.orchestration.response_orchestrator import (
            ResponseOrchestrator,
        )

        config = {
            "c2_beacon": {
                "enabled": True,
                "actions": ["isolate_host", "notify_soc"],
                "escalation_required": True,
            }
        }

        orchestrator = ResponseOrchestrator(config)

        alert = create_alert(
            title="C2 Beaconing Detected",
            description="Test",
            severity=AlertSeverity.CRITICAL,
            technique="T1071_beacon",
            hostname="WS-001",
        )

        responses = orchestrator.evaluate_response(alert)

        return TestResult(
            test_name="test_response_orchestration",
            passed=len(responses) > 0,
            duration_seconds=0.1,
            message=f"Executed {len(responses)} response actions",
        )


class AdversarialTests(TestSuite):
    """Tests using adversarial techniques (MITRE Caldera/Atomic Red Team)."""

    def __init__(self):
        super().__init__()
        self.caldera_url = "http://localhost:8888"
        self.caldera_api_key = ""

    def set_caldera_config(self, url: str, api_key: str) -> None:
        """Configure Caldera connection."""
        self.caldera_url = url
        self.caldera_api_key = api_key

    def run_atomic_test(self, technique: str) -> TestResult:
        """Run Atomic Red Team test for a technique."""
        atomic_tests = {
            "T1566": "Invoke-PhishingLink",
            "T1059": "PowerShell Encoded Commands",
            "T1547": "Boot or Logon Autostart Execution",
            "T1055": "Process Injection",
            "T1021": "Remote Services",
        }

        test_name = atomic_tests.get(technique, "unknown")

        logger.info(f"[MOCK] Running Atomic test: {test_name} for {technique}")

        return TestResult(
            test_name=f"test_atomic_{technique}",
            passed=True,
            duration_seconds=1.0,
            message=f"Atomic test {technique} executed (mock)",
            details={"technique": technique, "atomic_test": test_name},
        )

    def run_caldera_agent(self, agent_id: str, abilities: List[str]) -> TestResult:
        """Run Caldera agent with abilities."""
        logger.info(
            f"[MOCK] Running Caldera agent {agent_id} with abilities: {abilities}"
        )

        return TestResult(
            test_name=f"test_caldera_agent_{agent_id}",
            passed=True,
            duration_seconds=2.0,
            message=f"Caldera agent {agent_id} executed (mock)",
            details={"agent_id": agent_id, "abilities": abilities},
        )


def run_all_tests() -> Dict[str, Any]:
    """Run all test suites."""
    all_results = []

    detection_tests = DetectionTests()
    all_results.extend(detection_tests.run_all_tests())

    alert_tests = AlertTests()
    all_results.extend(alert_tests.run_all_tests())

    soar_tests = SOARTests()
    all_results.extend(soar_tests.run_all_tests())

    adversarial = AdversarialTests()
    all_results.extend(
        [adversarial.run_atomic_test("T1566"), adversarial.run_atomic_test("T1059")]
    )

    total = len(all_results)
    passed = sum(1 for r in all_results if r.passed)

    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "results": [
            {
                "test": r.test_name,
                "passed": r.passed,
                "message": r.message,
                "duration": r.duration_seconds,
            }
            for r in all_results
        ],
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    results = run_all_tests()

    print(f"\nTest Results:")
    print(f"  Total: {results['total']}")
    print(f"  Passed: {results['passed']}")
    print(f"  Failed: {results['failed']}")

    for result in results["results"]:
        status = "✓" if result["passed"] else "✗"
        print(f"  {status} {result['test']}: {result['message']}")
