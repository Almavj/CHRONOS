"""
Temporal Behavior Analysis Engine
Detects C2 beaconing, DGA domains, abnormal login times, and data staging
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
from scipy import fft
from scipy.stats import entropy
import hashlib
import re

from chronos.core.detection.alert import Alert, AlertSeverity, create_alert
from chronos.config import config

logger = logging.getLogger(__name__)


class TemporalAnalyzer:
    """Temporal Behavior Analysis for APT detection."""

    def __init__(self, tba_config: Dict[str, Any]):
        self.config = tba_config
        self.beaconing_config = tba_config.get("beaconing", {})
        self.dga_config = tba_config.get("dga", {})
        self.working_hours_config = tba_config.get("working_hours", {})
        self.dwell_time_config = tba_config.get("dwell_time", {})

        self.dns_queries: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.network_connections: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.auth_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.file_access: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        self.alexa_top_domains: set = set()
        self._load_alexa_domains()

    def _load_alexa_domains(self) -> None:
        """Load Alexa top domains for DGA detection."""
        common_domains = {
            "google.com",
            "facebook.com",
            "youtube.com",
            "twitter.com",
            "instagram.com",
            "linkedin.com",
            "reddit.com",
            "amazon.com",
            "wikipedia.org",
            "netflix.com",
            "microsoft.com",
            "apple.com",
            "github.com",
            "stackoverflow.com",
            "dropbox.com",
            "salesforce.com",
            "adobe.com",
            "wordpress.com",
            "blogspot.com",
            "yahoo.com",
        }
        self.alexa_top_domains = common_domains

    def detect_beaconing(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Detect C2 beaconing patterns using FFT and jitter analysis."""
        if not self.beaconing_config.get("enabled", True):
            return []

        alerts = []

        destination_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for event in events:
            if event.get("event_type") == "network_connection":
                dest = event.get("destination_ip")
                if dest:
                    destination_events[dest].append(event)

        fft_threshold = self.beaconing_config.get("fft_threshold", 0.7)
        jitter_threshold = self.beaconing_config.get("jitter_threshold", 0.15)

        for dest_ip, conns in destination_events.items():
            if len(conns) < 10:
                continue

            conns.sort(key=lambda x: x.get("timestamp", ""))

            timestamps = []
            for conn in conns:
                ts = conn.get("timestamp")
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if ts:
                    timestamps.append(ts)

            if len(timestamps) < 10:
                continue

            intervals = []
            for i in range(1, len(timestamps)):
                delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
                intervals.append(delta)

            if not intervals:
                continue

            intervals_array = np.array(intervals)
            mean_interval = np.mean(intervals_array)

            if mean_interval < 1:
                continue

            normalized = intervals_array / mean_interval

            fft_result = np.abs(fft.fft(normalized))
            fft_normalized = fft_result / np.max(fft_result)

            dominant_freq_idx = (
                np.argmax(fft_normalized[1 : len(fft_normalized) // 2]) + 1
            )
            spectral_energy = np.sum(fft_normalized[: len(fft_normalized) // 2] ** 2)

            if spectral_energy > fft_threshold:
                jitter = (
                    np.std(intervals_array) / mean_interval if mean_interval > 0 else 1
                )

                if jitter < jitter_threshold:
                    alerts.append(
                        create_alert(
                            title=f"C2 Beaconing Detected: {dest_ip}",
                            severity=AlertSeverity.CRITICAL,
                            description=f"Periodic beaconing pattern detected to {dest_ip}. "
                            f"Interval: {mean_interval:.1f}s, Jitter: {jitter:.2%}, "
                            f"Spectral energy: {spectral_energy:.2f}",
                            technique="T1071.001",
                            ttp="Application Layer Protocol: DNS",
                            indicators=[dest_ip],
                            metadata={
                                "destination_ip": dest_ip,
                                "mean_interval": mean_interval,
                                "jitter": jitter,
                                "spectral_energy": spectral_energy,
                                "connection_count": len(conns),
                            },
                        )
                    )

        return alerts

    def detect_dga(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Detect Domain Generation Algorithm (DGA) domains."""
        if not self.dga_config.get("enabled", True):
            return []

        alerts = []
        entropy_threshold = self.dga_config.get("entropy_threshold", 3.5)

        for event in events:
            if event.get("event_type") == "dns_query":
                query_name = event.get("query_name", "")

                if not query_name or query_name in self.alexa_top_domains:
                    continue

                entropy_score = self._calculate_entropy(query_name)

                if entropy_score > entropy_threshold:
                    if self._is_likely_dga(query_name):
                        alerts.append(
                            create_alert(
                                title=f"Possible DGA Domain: {query_name}",
                                severity=AlertSeverity.HIGH,
                                description=f"High-entropy domain name detected, possibly generated "
                                f"by DGA. Entropy: {entropy_score:.2f}",
                                technique="T1107",
                                ttp="Indicator Removal",
                                indicators=[query_name],
                                metadata={
                                    "query_name": query_name,
                                    "entropy": entropy_score,
                                    "domain_length": len(query_name),
                                    "digit_ratio": self._digit_ratio(query_name),
                                },
                            )
                        )

        return alerts

    def _calculate_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of domain name."""
        if not domain:
            return 0.0

        char_counts = defaultdict(int)
        for char in domain.lower():
            if char.isalnum() or char in ".-":
                char_counts[char] += 1

        if not char_counts:
            return 0.0

        total = sum(char_counts.values())
        probabilities = [count / total for count in char_counts.values()]

        return entropy(probabilities, base=2)

    def _is_likely_dga(self, domain: str) -> bool:
        """Heuristic check for DGA-generated domains."""
        if len(domain) < 10:
            return False

        digit_ratio = self._digit_ratio(domain)

        if digit_ratio > 0.3:
            return True

        if "-" in domain or "_" in domain:
            return False

        return len(domain) > 20

    def _digit_ratio(self, domain: str) -> float:
        """Calculate ratio of digits in domain."""
        digits = sum(1 for c in domain if c.isdigit())
        return digits / len(domain) if domain else 0

    def detect_abnormal_login_times(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Detect authentication events outside normal working hours."""
        if not self.working_hours_config.get("enabled", True):
            return []

        alerts = []
        zscore_threshold = self.working_hours_config.get("zscore_threshold", 3.0)

        user_baselines: Dict[str, List[int]] = defaultdict(list)

        for event in events:
            if event.get("event_type") == "authentication":
                user = event.get("user")
                if not user:
                    continue

                timestamp = event.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

                if timestamp:
                    hour = timestamp.hour
                    user_baselines[user].append(hour)

        for event in events:
            if event.get("event_type") == "authentication":
                user = event.get("user")
                if not user or user not in user_baselines:
                    continue

                timestamp = event.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

                if not timestamp:
                    continue

                hour = timestamp.hour
                baseline = user_baselines[user]

                if len(baseline) >= 5:
                    mean = np.mean(baseline)
                    std = np.std(baseline)

                    if std > 0:
                        zscore = abs(hour - mean) / std

                        if zscore > zscore_threshold:
                            is_weekend = timestamp.weekday() >= 5

                            alerts.append(
                                create_alert(
                                    title=f"Abnormal Login Time: {user}",
                                    severity=AlertSeverity.MEDIUM,
                                    description=f"User {user} authenticated at unusual time: "
                                    f"{timestamp.strftime('%H:%M')} "
                                    f"(z-score: {zscore:.2f})",
                                    technique="T1078",
                                    ttp="Valid Accounts",
                                    indicators=[user],
                                    metadata={
                                        "user": user,
                                        "login_hour": hour,
                                        "zscore": zscore,
                                        "is_weekend": is_weekend,
                                        "timestamp": timestamp.isoformat(),
                                    },
                                )
                            )

        return alerts

    def detect_data_staging(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Detect patterns indicative of data staging before exfiltration."""
        alerts = []

        file_staging: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for event in events:
            if event.get("event_type") == "file_access":
                hostname = event.get("hostname", "unknown")
                file_staging[hostname].append(event)

        sensitive_extensions = {
            ".zip",
            ".tar",
            ".gz",
            ".7z",
            ".rar",
            ".bak",
            ".sql",
            ".csv",
        }

        for hostname, file_events in file_staging.items():
            sensitive_files = [
                f
                for f in file_events
                if any(
                    f.get("file_name", "").lower().endswith(ext)
                    for ext in sensitive_extensions
                )
            ]

            if len(sensitive_files) > 10:
                alerts.append(
                    create_alert(
                        title=f"Potential Data Staging: {hostname}",
                        severity=AlertSeverity.HIGH,
                        description=f"Large number of sensitive file accesses detected: "
                        f"{len(sensitive_files)} files",
                        technique="T1074",
                        ttp="Data Staged",
                        indicators=[hostname],
                        metadata={
                            "hostname": hostname,
                            "sensitive_file_count": len(sensitive_files),
                            "files": [f.get("file_name") for f in sensitive_files[:10]],
                        },
                    )
                )

        return alerts

    def batch_analyze(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Run all temporal analysis on a batch of events."""
        all_alerts = []

        all_alerts.extend(self.detect_beaconing(events))
        all_alerts.extend(self.detect_dga(events))
        all_alerts.extend(self.detect_abnormal_login_times(events))
        all_alerts.extend(self.detect_data_staging(events))

        for event in events:
            event_type = event.get("event_type", "")

            if event_type in ["dns_query"]:
                self.dns_queries[event.get("query_name", "")].append(event)
            elif event_type in ["network_connection"]:
                dest = event.get("destination_ip")
                if dest:
                    self.network_connections[dest].append(event)
            elif event_type in ["authentication"]:
                user = event.get("user")
                if user:
                    self.auth_events[user].append(event)
            elif event_type in ["file_access"]:
                hostname = event.get("hostname", "unknown")
                self.file_access[hostname].append(event)

        return all_alerts
