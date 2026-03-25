"""
Graph-Based Lateral Movement Detection
Models network as graph and detects anomalous paths
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import threading

try:
    from chronos.core.detection.alert import Alert, AlertSeverity, create_alert
except ImportError:
    Alert = None
    AlertSeverity = None
    create_alert = None

logger = logging.getLogger(__name__)


class GraphDetector:
    """Graph-based detection for lateral movement patterns."""

    def __init__(self, graph_config: Dict[str, Any], neo4j_config: Dict[str, Any]):
        self.config = graph_config
        self.neo4j_config = neo4j_config

        self.lm_config = graph_config.get("lateral_movement", {})
        self.pth_config = graph_config.get("pass_the_hash", {})

        self.graph: Dict[str, Dict[str, Any]] = {}
        self.connections: List[Dict[str, Any]] = []
        self.auth_events: List[Dict[str, Any]] = []
        self.graph_lock = threading.Lock()

        self.computers: Dict[str, Dict[str, Any]] = {}
        self.users: Dict[str, Dict[str, Any]] = {}

        self.neo4j_available = False
        logger.info("Graph detector initialized")

    def analyze_event(self, event: Dict[str, Any]) -> List[Alert]:
        """Analyze an event for lateral movement patterns."""
        alerts = []

        event_type = event.get("event_type", "")

        if event_type == "authentication":
            alerts.extend(self._analyze_authentication(event))

        elif event_type == "network_connection":
            alerts.extend(self._analyze_network_connection(event))

        elif event_type == "process_creation":
            alerts.extend(self._analyze_process_creation(event))

        return alerts

    def _analyze_authentication(self, event: Dict[str, Any]) -> List[Alert]:
        """Analyze authentication events for lateral movement."""
        alerts = []

        username = event.get("user", "")
        source_ip = event.get("source_ip", "")
        dest_ip = event.get("destination_ip", "")

        if not username or not dest_ip:
            return alerts

        with self.graph_lock:
            self.auth_events.append(
                {
                    "username": username,
                    "source_ip": source_ip,
                    "destination_ip": dest_ip,
                    "timestamp": event.get("timestamp", datetime.utcnow().isoformat()),
                    "event_type": "authentication",
                }
            )

        if self.pth_config.get("enabled", True):
            alerts.extend(self._detect_pass_the_hash(username, dest_ip))

        return alerts

    def _detect_pass_the_hash(self, username: str, new_ip: str) -> List[Alert]:
        """Detect potential pass-the-hash attacks."""
        alerts = []

        threshold = self.pth_config.get("same_user_different_machine_threshold", 3)

        user_auths = [e for e in self.auth_events if e.get("username") == username]
        unique_ips = set(
            e.get("destination_ip") for e in user_auths if e.get("destination_ip")
        )

        if len(unique_ips) >= threshold:
            alerts.append(
                create_alert(
                    title=f"Potential Pass-the-Hash: {username}",
                    severity=AlertSeverity.HIGH,
                    description=f"User {username} authenticated to {len(unique_ips)} different machines",
                    technique="T1550.002",
                    ttp="Use Alternate Authentication Material: Pass the Hash",
                    indicators=[username],
                    metadata={
                        "username": username,
                        "unique_ips": list(unique_ips),
                        "auth_count": len(user_auths),
                    },
                )
            )

        return alerts

    def _analyze_network_connection(self, event: Dict[str, Any]) -> List[Alert]:
        """Analyze network connections for lateral movement patterns."""
        alerts = []

        source_ip = event.get("source_ip", "")
        dest_ip = event.get("destination_ip", "")
        dest_port = event.get("destination_port", 0)

        if not source_ip or not dest_ip:
            return alerts

        suspicious_ports = self.lm_config.get(
            "suspicious_ports", [445, 135, 3389, 5985]
        )

        with self.graph_lock:
            self.connections.append(
                {
                    "source_ip": source_ip,
                    "destination_ip": dest_ip,
                    "port": dest_port,
                    "timestamp": event.get("timestamp", datetime.utcnow().isoformat()),
                }
            )

        if dest_port in suspicious_ports:
            alerts.extend(
                self._detect_unusual_admin_access(source_ip, dest_ip, dest_port)
            )

        return alerts

    def _detect_unusual_admin_access(
        self, source_ip: str, dest_ip: str, port: int
    ) -> List[Alert]:
        """Detect unusual admin access patterns."""
        alerts = []

        source_criticality = self._get_criticality(source_ip)
        dest_criticality = self._get_criticality(dest_ip)

        if not self.lm_config.get("low_to_high_criticality", True):
            return alerts

        if source_criticality in ["low", "medium"] and dest_criticality == "critical":
            alerts.append(
                create_alert(
                    title=f"Unusual Admin Access: {source_ip} -> {dest_ip}",
                    severity=AlertSeverity.HIGH,
                    description=f"Connection from low-criticality host {source_ip} to critical host {dest_ip} on port {port}",
                    technique="T1021",
                    ttp="Remote Services",
                    indicators=[source_ip, dest_ip],
                    metadata={
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "port": port,
                        "source_criticality": source_criticality,
                        "dest_criticality": dest_criticality,
                    },
                )
            )

        return alerts

    def _analyze_process_creation(self, event: Dict[str, Any]) -> List[Alert]:
        """Analyze process creation for suspicious patterns."""
        alerts = []

        process_name = event.get("process_name", "").lower()
        parent_process = event.get("parent_process", "").lower()
        command_line = event.get("command_line", "").lower()

        suspicious_parents = [
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
        ]
        suspicious_childs = [
            "mimikatz.exe",
            "procdump.exe",
            "lsass.exe",
            "psexec.exe",
            "reg.exe",
        ]

        if parent_process in suspicious_parents:
            for child in suspicious_childs:
                if child in process_name or child in command_line:
                    alerts.append(
                        create_alert(
                            title=f"Suspicious Process Chain: {parent_process} -> {process_name}",
                            severity=AlertSeverity.HIGH,
                            description=f"Suspicious process execution from {parent_process}",
                            technique="T1059",
                            ttp="Command and Scripting Interpreter",
                            indicators=[process_name, parent_process],
                            metadata={
                                "process_name": process_name,
                                "parent_process": parent_process,
                                "command_line": command_line,
                            },
                        )
                    )

        return alerts

    def _get_criticality(self, ip: str) -> str:
        """Get criticality level of a host by IP."""
        for hostname, info in self.computers.items():
            if info.get("ip") == ip:
                return info.get("criticality", "low")
        return "low"

    def build_attack_path(
        self, start_host: str, end_host: str, max_hops: int = 3
    ) -> List[List[str]]:
        """Find potential attack paths between two hosts."""
        if start_host not in self.graph:
            return []

        paths = []

        def dfs(current: str, path: List[str], visited: Set[str]):
            if len(path) > max_hops:
                return
            if current == end_host:
                paths.append(path)
                return

            visited.add(current)

            for neighbor in self.graph.get(current, {}).get("connections", []):
                if neighbor not in visited:
                    dfs(neighbor, path + [neighbor], visited.copy())

        dfs(start_host, [start_host], set())
        return paths

    def detect_graph_anomalies(self) -> List[Alert]:
        """Run graph-based anomaly detection."""
        alerts = []

        with self.graph_lock:
            auth_by_user = defaultdict(list)
            for auth in self.auth_events:
                username = auth.get("username")
                if username:
                    auth_by_user[username].append(auth)

            for username, auths in auth_by_user.items():
                unique_dests = set(
                    a.get("destination_ip") for a in auths if a.get("destination_ip")
                )

                if len(unique_dests) > self.pth_config.get(
                    "same_user_different_machine_threshold", 3
                ):
                    alerts.append(
                        create_alert(
                            title=f"Widespread Lateral Movement: {username}",
                            severity=AlertSeverity.CRITICAL,
                            description=f"User {username} has authenticated to {len(unique_dests)} unique destinations",
                            technique="T1021",
                            ttp="Lateral Movement",
                            indicators=[username],
                            metadata={
                                "username": username,
                                "destinations": list(unique_dests),
                                "count": len(unique_dests),
                            },
                        )
                    )

        return alerts

    def batch_analyze(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Run graph analysis on batch of events."""
        all_alerts = []

        for event in events:
            alerts = self.analyze_event(event)
            all_alerts.extend(alerts)

        all_alerts.extend(self.detect_graph_anomalies())

        return all_alerts
