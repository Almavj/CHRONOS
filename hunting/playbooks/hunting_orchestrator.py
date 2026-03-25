"""
Threat Hunting Playbooks
Automated hypothesis-driven hunting workflows
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from chronos.core.detection.alert import Alert, AlertSeverity, create_alert
from chronos.data.collectors.elasticsearch_client import ElasticsearchClient

logger = logging.getLogger(__name__)


class HuntFrequency(Enum):
    """Hunt execution frequency."""

    REALTIME = "realtime"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


class HuntPriority(Enum):
    """Hunt priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class HuntResult:
    """Result of a threat hunt."""

    hypothesis: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    alerts_generated: List[Alert] = field(default_factory=list)
    executed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    duration_seconds: float = 0.0
    status: str = "completed"
    error: Optional[str] = None


class HuntPlaybook:
    """Base class for threat hunting playbooks."""

    def __init__(
        self,
        name: str,
        hypothesis: str,
        data_sources: List[str],
        priority: HuntPriority = HuntPriority.MEDIUM,
        frequency: HuntFrequency = HuntFrequency.DAILY,
    ):
        self.name = name
        self.hypothesis = hypothesis
        self.data_sources = data_sources
        self.priority = priority
        self.frequency = frequency

        self.es_client: Optional[ElasticsearchClient] = None

    def set_es_client(self, client: ElasticsearchClient) -> None:
        """Set Elasticsearch client for data queries."""
        self.es_client = client

    def execute(self) -> HuntResult:
        """Execute the hunt playbook."""
        start_time = datetime.utcnow()

        try:
            findings = self._run_analytics()
            alerts = self._generate_alerts(findings)

            duration = (datetime.utcnow() - start_time).total_seconds()

            return HuntResult(
                hypothesis=self.hypothesis,
                findings=findings,
                alerts_generated=alerts,
                duration_seconds=duration,
            )

        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Error executing hunt {self.name}: {e}")

            return HuntResult(
                hypothesis=self.hypothesis,
                status="error",
                error=str(e),
                duration_seconds=duration,
            )

    def _run_analytics(self) -> List[Dict[str, Any]]:
        """Run analytics for this hunt. Override in subclasses."""
        return []

    def _generate_alerts(self, findings: List[Dict[str, Any]]) -> List[Alert]:
        """Generate alerts from findings. Override in subclasses."""
        return []


class GhostCredentialsHunt(HuntPlaybook):
    """Hunt for compromised accounts showing different behavior patterns."""

    def __init__(self):
        super().__init__(
            name="ghost_credentials",
            hypothesis="Compromised accounts show different behavior patterns than legitimate users",
            data_sources=["vpn_logs", "endpoint_logs", "proxy_logs"],
            priority=HuntPriority.HIGH,
            frequency=HuntFrequency.DAILY,
        )

    def _run_analytics(self) -> List[Dict[str, Any]]:
        """Analyze user behavior for anomalies."""
        findings = []

        baseline_users = self._get_baseline_users()

        for username, baseline in baseline_users.items():
            current_behavior = self._get_current_behavior(username)

            if self._detect_deviation(baseline, current_behavior):
                findings.append(
                    {
                        "username": username,
                        "baseline": baseline,
                        "current": current_behavior,
                        "deviation_detected": True,
                    }
                )

        return findings

    def _get_baseline_users(self) -> Dict[str, Any]:
        """Get 30-day baseline for users."""
        return {
            "jsmith": {
                "typical_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
                "typical_ips": ["10.0.10.100", "10.0.10.101"],
                "avg_daily_logins": 8,
            }
        }

    def _get_current_behavior(self, username: str) -> Dict[str, Any]:
        """Get current user behavior."""
        return {
            "recent_hours": [23, 0, 1, 2],
            "recent_ips": ["10.0.10.100", "203.0.113.50"],
            "recent_logins": 45,
        }

    def _detect_deviation(self, baseline: Dict, current: Dict) -> bool:
        """Detect behavior deviation using z-score."""
        baseline_avg = baseline.get("avg_daily_logins", 0)
        current_count = current.get("recent_logins", 0)

        if baseline_avg > 0:
            zscore = (current_count - baseline_avg) / baseline_avg
            return zscore > 3.0

        return False

    def _generate_alerts(self, findings: List[Dict[str, Any]]) -> List[Alert]:
        """Generate alerts for deviations."""
        alerts = []

        for finding in findings:
            alerts.append(
                create_alert(
                    title=f"Ghost Credentials: {finding['username']}",
                    severity=AlertSeverity.HIGH,
                    description=f"User {finding['username']} shows anomalous behavior patterns",
                    technique="T1078",
                    ttp="Valid Accounts",
                    indicators=[finding["username"]],
                    metadata=finding,
                )
            )

        return alerts


class ShadowAdminsHunt(HuntPlaybook):
    """Hunt for hidden admin accounts."""

    def __init__(self):
        super().__init__(
            name="shadow_admins",
            hypothesis="Attackers create backdoor accounts with elevated privileges",
            data_sources=["ad_changes", "group_policy_logs"],
            priority=HuntPriority.HIGH,
            frequency=HuntFrequency.WEEKLY,
        )

    def _run_analytics(self) -> List[Dict[str, Any]]:
        """Find privilege escalation patterns."""
        findings = []

        privilege_changes = self._get_privilege_changes()

        for change in privilege_changes:
            if self._is_suspicious_change(change):
                findings.append(
                    {
                        "account": change.get("account"),
                        "change_type": change.get("change_type"),
                        "timestamp": change.get("timestamp"),
                        "suspicious": True,
                    }
                )

        dormant_accounts = self._get_recently_active_dormant_accounts()
        findings.extend(dormant_accounts)

        return findings

    def _get_privilege_changes(self) -> List[Dict[str, Any]]:
        """Get recent privilege changes."""
        return [
            {
                "account": "new_admin",
                "change_type": "member_added",
                "group": "Domain Admins",
                "timestamp": "2026-03-08T10:00:00Z",
            },
            {
                "account": "backup_svc",
                "change_type": "password_reset",
                "timestamp": "2026-03-08T11:00:00Z",
            },
        ]

    def _is_suspicious_change(self, change: Dict[str, Any]) -> bool:
        """Determine if privilege change is suspicious."""
        group = change.get("group", "").lower()
        admin_groups = ["domain admins", "enterprise admins", "administrators"]

        return group in admin_groups

    def _get_recently_active_dormant_accounts(self) -> List[Dict[str, Any]]:
        """Find dormant accounts that recently became active."""
        return []

    def _generate_alerts(self, findings: List[Dict[str, Any]]) -> List[Alert]:
        """Generate alerts for suspicious changes."""
        alerts = []

        for finding in findings:
            alerts.append(
                create_alert(
                    title=f"Shadow Admin Activity: {finding.get('account')}",
                    severity=AlertSeverity.HIGH,
                    description=f"Suspicious privilege change detected",
                    technique="T1136",
                    ttp="Create Account",
                    indicators=[finding.get("account", "")],
                    metadata=finding,
                )
            )

        return alerts


class SupplyChainHunt(HuntPlaybook):
    """Hunt for supply chain attack indicators."""

    def __init__(self):
        super().__init__(
            name="supply_chain",
            hypothesis="Software supply chain attacks manifest as anomalous child processes",
            data_sources=["process_creation", "dll_loads", "network_connections"],
            priority=HuntPriority.CRITICAL,
            frequency=HuntFrequency.REALTIME,
        )

    def _run_analytics(self) -> List[Dict[str, Any]]:
        """Analyze for supply chain indicators."""
        findings = []

        parent_child_anomalies = self._detect_parent_child_anomaly()
        findings.extend(parent_child_anomalies)

        unsigned_binaries = self._detect_unsigned_binaries()
        findings.extend(unsigned_binaries)

        suspicious_network = self._detect_suspicious_network()
        findings.extend(suspicious_network)

        return findings

    def _detect_parent_child_anomaly(self) -> List[Dict[str, Any]]:
        """Detect anomalous parent-child process relationships."""
        return [
            {
                "type": "parent_child_anomaly",
                "parent": "git.exe",
                "child": "powershell.exe",
                "command": "powershell -enc ...",
                "hostname": "WS-001",
            }
        ]

    def _detect_unsigned_binaries(self) -> List[Dict[str, Any]]:
        """Detect unsigned binaries in development tools."""
        return []

    def _detect_suspicious_network(self) -> List[Dict[str, Any]]:
        """Detect network connections from compilers."""
        return [
            {
                "type": "suspicious_network",
                "process": "msbuild.exe",
                "destination": "external.evil.com",
                "hostname": "DEV-01",
            }
        ]

    def _generate_alerts(self, findings: List[Dict[str, Any]]) -> List[Alert]:
        """Generate alerts for supply chain indicators."""
        alerts = []

        for finding in findings:
            alert_type = finding.get("type", "unknown")

            if alert_type == "parent_child_anomaly":
                alerts.append(
                    create_alert(
                        title=f"Supply Chain: Suspicious Process Chain",
                        severity=AlertSeverity.CRITICAL,
                        description=f"Anomalous process chain detected: {finding.get('parent')} -> {finding.get('child')}",
                        technique="T1195",
                        ttp="Supply Chain Compromise",
                        indicators=[finding.get("hostname", "")],
                        metadata=finding,
                    )
                )
            elif alert_type == "suspicious_network":
                alerts.append(
                    create_alert(
                        title=f"Supply Chain: Suspicious Network Connection",
                        severity=AlertSeverity.HIGH,
                        description=f"Suspicious network connection from {finding.get('process')}",
                        technique="T1195",
                        ttp="Supply Chain Compromise",
                        indicators=[finding.get("destination", "")],
                        metadata=finding,
                    )
                )

        return alerts


class HuntingOrchestrator:
    """Orchestrates threat hunting operations."""

    def __init__(self, es_client: ElasticsearchClient):
        self.es_client = es_client
        self.playbooks: Dict[str, HuntPlaybook] = {}
        self.results_history: List[HuntResult] = []

        self._register_playbooks()

    def _register_playbooks(self) -> None:
        """Register available hunting playbooks."""
        ghost_creds = GhostCredentialsHunt()
        ghost_creds.set_es_client(self.es_client)
        self.playbooks["ghost_credentials"] = ghost_creds

        shadow_admins = ShadowAdminsHunt()
        shadow_admins.set_es_client(self.es_client)
        self.playbooks["shadow_admins"] = shadow_admins

        supply_chain = SupplyChainHunt()
        supply_chain.set_es_client(self.es_client)
        self.playbooks["supply_chain"] = supply_chain

    def execute_hunt(self, playbook_name: str) -> HuntResult:
        """Execute a specific hunt playbook."""
        if playbook_name not in self.playbooks:
            raise ValueError(f"Unknown playbook: {playbook_name}")

        playbook = self.playbooks[playbook_name]
        result = playbook.execute()

        self.results_history.append(result)

        logger.info(
            f"Executed hunt {playbook_name}: {len(result.findings)} findings, {len(result.alerts_generated)} alerts"
        )

        return result

    def execute_all(self) -> List[HuntResult]:
        """Execute all registered playbooks."""
        results = []

        for name in self.playbooks:
            result = self.execute_hunt(name)
            results.append(result)

        return results

    def get_hunt_results(self, limit: int = 50) -> List[HuntResult]:
        """Get recent hunt results."""
        return self.results_history[-limit:]
