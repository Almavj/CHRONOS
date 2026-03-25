#!/usr/bin/env python3
"""
CHRONOS CLI
Command-line interface for the CHRONOS APT Detection Platform
"""

import sys
import argparse
import logging

sys.path.insert(0, "/home/alma/Documents")

from chronos.core.detection.engine import DetectionEngine
from chronos.core.detection.alert import AlertSeverity
from chronos.tests.test_suite import run_all_tests
from chronos.visualization.dashboard import DashboardGenerator


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def run_engine():
    """Run the detection engine."""
    logger.info("Starting CHRONOS Detection Engine...")
    engine = DetectionEngine()
    engine.initialize()
    engine.start()

    logger.info("Engine running. Press Ctrl+C to stop.")

    try:
        import time

        while True:
            status = engine.get_status()
            logger.info(f"Status: {status}")
            time.sleep(30)
    except KeyboardInterrupt:
        logger.info("Stopping engine...")
        engine.stop()


def run_tests():
    """Run the test suite."""
    logger.info("Running CHRONOS test suite...")
    results = run_all_tests()

    print(f"\n{'=' * 50}")
    print(f"CHRONOS Test Results")
    print(f"{'=' * 50}")
    print(f"Total: {results['total']}")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"{'=' * 50}")

    for result in results["results"]:
        status = "✓" if result["passed"] else "✗"
        print(f"  {status} {result['test']}: {result['message']}")

    return 0 if results["failed"] == 0 else 1


def show_dashboard():
    """Show dashboard metrics."""
    logger.info("Generating CHRONOS dashboard...")

    dashboard = DashboardGenerator()

    metrics = dashboard.metrics
    print(f"\n{'=' * 50}")
    print(f"CHRONOS SOC Metrics")
    print(f"{'=' * 50}")
    print(f"MTTD: {metrics.mttd_hours:.2f} hours")
    print(f"MTTR: {metrics.mttr_hours:.2f} hours")
    print(f"Alert Quality Ratio: {metrics.alert_quality_ratio:.1%}")
    print(f"MITRE Coverage: {metrics.mitre_coverage:.1%}")
    print(f"{'=' * 50}")

    print(f"\nTop Attack Techniques:")
    for tech in dashboard.get_top_attack_techniques()[:5]:
        print(f"  - {tech['technique']}: {tech['count']} alerts")

    print(f"\nHost Risk Scores:")
    for host in dashboard.get_host_risk_scores()[:5]:
        print(
            f"  - {host['hostname']}: {host['risk_score']} (alerts: {host['alerts']})"
        )

    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="CHRONOS APT Detection Platform")

    parser.add_argument(
        "command", choices=["engine", "test", "dashboard"], help="Command to execute"
    )

    args = parser.parse_args()

    if args.command == "engine":
        run_engine()
    elif args.command == "test":
        return run_tests()
    elif args.command == "dashboard":
        return show_dashboard()

    return 0


if __name__ == "__main__":
    sys.exit(main())
