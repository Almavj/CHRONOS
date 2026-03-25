"""
Identity Threat Detection
Detects compromised credentials, impossible travel, privilege escalation
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import math

from chronos.core.detection.alert import Alert, AlertSeverity, create_alert

logger = logging.getLogger(__name__)


class IdentityDetector:
    """Identity-based threat detection."""

    def __init__(self, identity_config: Dict[str, Any]):
        self.config = identity_config

        self.impossible_travel_config = identity_config.get("impossible_travel", {})
        self.credential_stuffing_config = identity_config.get("credential_stuffing", {})
        self.privilege_escalation_config = identity_config.get(
            "privilege_escalation", {}
        )
        self.service_account_config = identity_config.get("service_account_abuse", {})

        self.auth_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.user_baselines: Dict[str, Dict[str, Any]] = {}

        self.failed_logins: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        self.role_changes: List[Dict[str, Any]] = []

    def analyze_authentication(self, event: Dict[str, Any]) -> List[Alert]:
        """Analyze authentication event for identity threats."""
        alerts = []

        username = event.get("user", "")
        if not username:
            return alerts

        timestamp = event.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        source_ip = event.get("source_ip", "")
        source_geo = event.get("source_geo", {})
        success = event.get("success", True)

        auth_event = {
            "username": username,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "source_geo": source_geo,
            "success": success,
        }

        self.auth_history[username].append(auth_event)

        if len(self.auth_history[username]) > 1000:
            self.auth_history[username] = self.auth_history[username][-500:]

        if self.impossible_travel_config.get("enabled", True):
            alerts.extend(self._detect_impossible_travel(username, auth_event))

        if self.credential_stuffing_config.get("enabled", True):
            alerts.extend(self._detect_credential_stuffing(username, event))

        if self.privilege_escalation_config.get("enabled", True):
            alerts.extend(self._detect_privilege_escalation(event))

        return alerts

    def _detect_impossible_travel(
        self, username: str, current_auth: Dict[str, Any]
    ) -> List[Alert]:
        """Detect impossible travel between authentication events."""
        alerts = []

        velocity_threshold = self.impossible_travel_config.get(
            "velocity_threshold_kmh", 1000
        )
        time_window = self.impossible_travel_config.get("time_window_minutes", 30)

        if not current_auth.get("source_geo"):
            return alerts

        current_geo = current_auth.get("source_geo", {})
        current_lat = current_geo.get("latitude")
        current_lon = current_geo.get("longitude")

        if current_lat is None or current_lon is None:
            return alerts

        current_time = current_auth.get("timestamp")

        recent_auths = [
            a
            for a in self.auth_history[username][-20:]
            if a.get("timestamp")
            and a.get("source_geo")
            and (current_time - a.get("timestamp")).total_seconds() < time_window * 60
        ]

        for prev_auth in recent_auths:
            if prev_auth == current_auth:
                continue

            prev_geo = prev_auth.get("source_geo", {})
            prev_lat = prev_geo.get("latitude")
            prev_lon = prev_geo.get("longitude")

            if prev_lat is None or prev_lon is None:
                continue

            distance_km = self._haversine_distance(
                current_lat, current_lon, prev_lat, prev_lon
            )

            time_diff = (
                current_time - prev_auth.get("timestamp")
            ).total_seconds() / 3600

            if time_diff > 0:
                velocity = distance_km / time_diff

                if velocity > velocity_threshold:
                    alerts.append(
                        create_alert(
                            title=f"Impossible Travel: {username}",
                            severity=AlertSeverity.CRITICAL,
                            description=f"Impossible travel detected for {username}. "
                            f"Velocity: {velocity:.0f} km/h",
                            technique="T1078",
                            ttp="Valid Accounts",
                            indicators=[username, current_auth.get("source_ip", "")],
                            metadata={
                                "username": username,
                                "current_location": current_geo,
                                "previous_location": prev_geo,
                                "velocity_kmh": velocity,
                                "time_diff_hours": time_diff,
                                "distance_km": distance_km,
                            },
                        )
                    )

        return alerts

    def _haversine_distance(
        self, lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Calculate distance between two coordinates using Haversine formula."""
        R = 6371

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        )

        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    def _detect_credential_stuffing(
        self, username: str, event: Dict[str, Any]
    ) -> List[Alert]:
        """Detect credential stuffing attacks."""
        alerts = []

        threshold = self.credential_stuffing_config.get("failed_login_threshold", 10)
        time_window = self.credential_stuffing_config.get("time_window_minutes", 15)
        ip_variation = self.credential_stuffing_config.get("ip_variation_threshold", 3)

        timestamp = event.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        failed_auth = {
            "username": username,
            "timestamp": timestamp,
            "source_ip": event.get("source_ip", ""),
            "success": event.get("success", True),
        }

        if not failed_auth["success"]:
            self.failed_logins[username].append(failed_auth)

        recent_failures = [
            f
            for f in self.failed_logins[username]
            if f.get("timestamp")
            and (timestamp - f.get("timestamp")).total_seconds() < time_window * 60
        ]

        if len(recent_failures) >= threshold:
            unique_ips = set(
                f.get("source_ip") for f in recent_failures if f.get("source_ip")
            )

            if len(unique_ips) >= ip_variation:
                alerts.append(
                    create_alert(
                        title=f"Possible Credential Stuffing: {username}",
                        severity=AlertSeverity.HIGH,
                        description=f"Multiple failed login attempts from {len(unique_ips)} different IPs",
                        technique="T1110",
                        ttp="Brute Force",
                        indicators=[username],
                        metadata={
                            "username": username,
                            "failed_attempts": len(recent_failures),
                            "unique_ips": list(unique_ips),
                            "ip_count": len(unique_ips),
                        },
                    )
                )

        return alerts

    def _detect_privilege_escalation(self, event: Dict[str, Any]) -> List[Alert]:
        """Detect privilege escalation attempts."""
        alerts = []

        event_id = event.get("event_id", 0)

        if event_id == 4672:
            alerts.append(
                create_alert(
                    title=f"Special Privileges Assigned: {event.get('user', 'unknown')}",
                    severity=AlertSeverity.HIGH,
                    description=f"Special privileges assigned to user",
                    technique="T1068",
                    ttp="Exploitation for Privilege Escalation",
                    indicators=[event.get("user", "")],
                    metadata={
                        "user": event.get("user", ""),
                        "privileges": event.get("assigned_privileges", []),
                    },
                )
            )

        elif event_id == 4720:
            alerts.append(
                create_alert(
                    title=f"User Account Created: {event.get('new_user', 'unknown')}",
                    severity=AlertSeverity.MEDIUM,
                    description=f"New user account created",
                    technique="T1136",
                    ttp="Create Account",
                    indicators=[event.get("new_user", "")],
                    metadata={
                        "new_user": event.get("new_user", ""),
                        "created_by": event.get("creator_user", ""),
                    },
                )
            )

        elif event_id == 4726:
            alerts.append(
                create_alert(
                    title=f"User Account Deleted: {event.get('deleted_user', 'unknown')}",
                    severity=AlertSeverity.MEDIUM,
                    description=f"User account deleted",
                    technique="T1531",
                    ttp="Account Access Removal",
                    indicators=[event.get("deleted_user", "")],
                    metadata={
                        "deleted_user": event.get("deleted_user", ""),
                        "deleted_by": event.get("deleter_user", ""),
                    },
                )
            )

        return alerts

    def analyze_role_change(self, event: Dict[str, Any]) -> List[Alert]:
        """Analyze role/privilege changes."""
        alerts = []

        user = event.get("user", "")
        old_role = event.get("old_role", "")
        new_role = event.get("new_role", "")

        if old_role != new_role:
            self.role_changes.append(event)

            if new_role == "admin" or new_role == "super_admin":
                alerts.append(
                    create_alert(
                        title=f"Privilege Escalation: {user}",
                        severity=AlertSeverity.HIGH,
                        description=f"User {user} role changed from {old_role} to {new_role}",
                        technique="T1068",
                        ttp="Exploitation for Privilege Escalation",
                        indicators=[user],
                        metadata={
                            "user": user,
                            "old_role": old_role,
                            "new_role": new_role,
                            "timestamp": event.get("timestamp"),
                        },
                    )
                )

        return alerts

    def analyze_service_account(self, event: Dict[str, Any]) -> List[Alert]:
        """Analyze service account behavior."""
        alerts = []

        if not self.service_account_config.get("enabled", True):
            return alerts

        username = event.get("user", "")

        if not username.endswith("$") and not username.startswith("svc_"):
            return alerts

        threshold = self.service_account_config.get("baseline_deviation_threshold", 2.5)

        alerts.append(
            create_alert(
                title=f"Service Account Activity: {username}",
                severity=AlertSeverity.INFO,
                description=f"Service account activity detected",
                technique="T1078",
                ttp="Valid Accounts",
                indicators=[username],
                metadata={
                    "username": username,
                    "source_ip": event.get("source_ip", ""),
                },
            )
        )

        return alerts

    def build_user_baseline(self, username: str, days: int = 30) -> Dict[str, Any]:
        """Build behavioral baseline for a user."""
        auths = self.auth_history.get(username, [])

        if not auths:
            return {}

        hours = [a.get("timestamp").hour for a in auths if a.get("timestamp")]
        ips = [a.get("source_ip") for a in auths if a.get("source_ip")]

        baseline = {
            "typical_hours": list(set(hours)),
            "unique_ips": len(set(ips)),
            "auth_count": len(auths),
        }

        self.user_baselines[username] = baseline

        return baseline

    def detect_baseline_deviation(
        self, username: str, current_event: Dict[str, Any]
    ) -> List[Alert]:
        """Detect deviation from user baseline."""
        alerts = []

        baseline = self.user_baselines.get(username)

        if not baseline:
            self.build_user_baseline(username)
            return alerts

        current_hour = (
            current_event.get("timestamp").hour if current_event.get("timestamp") else 0
        )
        current_ip = current_event.get("source_ip", "")

        if current_hour not in baseline.get("typical_hours", []):
            alerts.append(
                create_alert(
                    title=f"User Behavior Anomaly: {username}",
                    severity=AlertSeverity.MEDIUM,
                    description=f"User {username} logged in at unusual hour: {current_hour}",
                    technique="T1078",
                    ttp="Valid Accounts",
                    indicators=[username],
                    metadata={
                        "username": username,
                        "current_hour": current_hour,
                        "baseline_hours": baseline.get("typical_hours", []),
                    },
                )
            )

        return alerts
