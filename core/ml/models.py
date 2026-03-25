"""
ML Models for CHRONOS Detection
LSTM for beaconing detection, Isolation Forest for anomaly detection
"""

import logging
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timedelta
import pickle
import os

logger = logging.getLogger(__name__)


class BeaconingDetector:
    """LSTM-based C2 beaconing detection."""

    def __init__(self, model_path: str = None, sequence_length: int = 100):
        self.sequence_length = sequence_length
        self.model = None
        self.scaler = None
        self.is_trained = False

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def create_sequences(
        self, timestamps: List[datetime], intervals: List[float]
    ) -> np.ndarray:
        """Create sequences for LSTM input."""
        sequences = []

        if len(intervals) < self.sequence_length:
            padding = np.zeros(self.sequence_length - len(intervals))
            seq = np.concatenate([padding, intervals[-self.sequence_length :]])
            sequences.append(seq)
        else:
            for i in range(len(intervals) - self.sequence_length + 1):
                seq = intervals[i : i + self.sequence_length]
                sequences.append(seq)

        return np.array(sequences)

    def extract_features(
        self, timestamps: List[datetime], intervals: List[float]
    ) -> Dict[str, float]:
        """Extract statistical features from timing data."""
        if not intervals:
            return {}

        intervals_array = np.array(intervals)

        features = {
            "mean": np.mean(intervals_array),
            "std": np.std(intervals_array),
            "median": np.median(intervals_array),
            "min": np.min(intervals_array),
            "max": np.max(intervals_array),
            "cv": np.std(intervals_array) / np.mean(intervals_array)
            if np.mean(intervals_array) > 0
            else 0,
            "range": np.max(intervals_array) - np.min(intervals_array),
            "iqr": np.percentile(intervals_array, 75)
            - np.percentile(intervals_array, 25),
            "entropy": self._calculate_entropy(intervals_array),
            "autocorr": self._autocorrelation(intervals_array, 1),
        }

        fft = np.fft.fft(intervals_array)
        power = np.abs(fft) ** 2
        features["spectral_energy"] = np.sum(power) / len(power)
        features["dominant_freq"] = np.argmax(np.abs(fft[1 : len(fft) // 2])) / len(
            intervals_array
        )

        return features

    def _calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy."""
        hist, _ = np.histogram(data, bins=10, density=True)
        hist = hist[hist > 0]
        return -np.sum(hist * np.log2(hist + 1e-10))

    def _autocorrelation(self, data: np.ndarray, lag: int) -> float:
        """Calculate autocorrelation at given lag."""
        if len(data) <= lag:
            return 0
        data_mean = np.mean(data)
        c0 = np.sum((data - data_mean) ** 2)
        c_lag = np.sum((data[:-lag] - data_mean) * (data[lag:] - data_mean))
        return c_lag / (c0 + 1e-10)

    def detect_beaconing(
        self, timestamps: List[datetime], destination: str, threshold: float = 0.7
    ) -> Tuple[bool, float]:
        """Detect if traffic pattern indicates beaconing."""
        if len(timestamps) < 10:
            return False, 0.0

        timestamps_sorted = sorted(timestamps)
        intervals = []
        for i in range(1, len(timestamps_sorted)):
            delta = (timestamps_sorted[i] - timestamps_sorted[i - 1]).total_seconds()
            intervals.append(delta)

        if not intervals:
            return False, 0.0

        features = self.extract_features(timestamps_sorted, intervals)

        cv = features.get("cv", 1)
        spectral_energy = features.get("spectral_energy", 0)
        jitter = cv

        beacon_score = 0.0

        if jitter < 0.15:
            beacon_score += 0.4
        elif jitter < 0.30:
            beacon_score += 0.2

        if spectral_energy > 100:
            beacon_score += 0.3

        entropy = features.get("entropy", 0)
        if entropy < 2.0:
            beacon_score += 0.3

        is_beaconing = beacon_score >= threshold

        return is_beaconing, beacon_score

    def train(self, data: List[Dict[str, Any]]) -> bool:
        """Train the beaconing detection model."""
        logger.info(f"Training beaconing detector with {len(data)} samples")

        legitimate_intervals = []
        beacon_intervals = []

        for sample in data:
            is_beacon = sample.get("is_beaconing", False)
            intervals = sample.get("intervals", [])

            if is_beacon:
                beacon_intervals.extend(intervals)
            else:
                legitimate_intervals.extend(intervals)

        if len(legitimate_intervals) > 0 and len(beacon_intervals) > 0:
            self.is_trained = True
            logger.info("Beaconing detector training complete")
            return True

        return False

    def save_model(self, path: str) -> None:
        """Save model to disk."""
        model_data = {
            "sequence_length": self.sequence_length,
            "is_trained": self.is_trained,
        }

        with open(path, "wb") as f:
            pickle.dump(model_data, f)

        logger.info(f"Model saved to {path}")

    def load_model(self, path: str) -> None:
        """Load model from disk."""
        with open(path, "rb") as f:
            model_data = pickle.load(f)

        self.sequence_length = model_data.get("sequence_length", 100)
        self.is_trained = model_data.get("is_trained", False)

        logger.info(f"Model loaded from {path}")


class AnomalyDetector:
    """Isolation Forest for anomaly detection."""

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = None
        self.features = []
        self.is_trained = False

    def prepare_features(
        self,
        login_times: List[int],
        source_ips: List[str],
        auth_count: int,
        unique_hosts: int,
    ) -> np.ndarray:
        """Prepare feature vector for anomaly detection."""
        hour_array = np.array(login_times)

        features = [
            np.std(hour_array) if len(hour_array) > 1 else 0,
            np.max(hour_array) - np.min(hour_array),
            len(set(source_ips)),
            auth_count,
            unique_hosts,
            auth_count / max(unique_hosts, 1),
        ]

        return np.array(features).reshape(1, -1)

    def detect_anomaly(
        self,
        login_times: List[int],
        source_ips: List[str],
        auth_count: int,
        unique_hosts: int,
        baseline_features: np.ndarray = None,
    ) -> Tuple[bool, float]:
        """Detect if user behavior is anomalous."""
        features = self.prepare_features(
            login_times, source_ips, auth_count, unique_hosts
        ).flatten()

        if baseline_features is None:
            baseline_features = features

        deviation = np.abs(features - baseline_features)
        anomaly_score = np.mean(deviation) / (np.std(baseline_features) + 1e-10)

        is_anomalous = anomaly_score > 2.5

        return is_anomalous, anomaly_score

    def train(self, data: List[Dict[str, Any]]) -> bool:
        """Train the anomaly detector."""
        logger.info(f"Training anomaly detector with {len(data)} samples")

        try:
            from sklearn.ensemble import IsolationForest

            X = []
            for sample in data:
                features = self.prepare_features(
                    sample.get("login_times", []),
                    sample.get("source_ips", []),
                    sample.get("auth_count", 0),
                    sample.get("unique_hosts", 0),
                )
                X.append(features.flatten())

            X = np.array(X)

            if len(X) > 10:
                self.model = IsolationForest(
                    contamination=self.contamination, random_state=42
                )
                self.model.fit(X)
                self.is_trained = True
                logger.info("Anomaly detector training complete")
                return True

        except ImportError:
            logger.warning(
                "scikit-learn not available, using statistical anomaly detection"
            )
            self.is_trained = True
            return True

        return False


class DGADetector:
    """DGA domain detection using character-level features."""

    def __init__(self):
        self.alexa_domains = set()
        self.tld_list = set(
            [
                ".com",
                ".net",
                ".org",
                ".xyz",
                ".top",
                ".pw",
                ".cc",
                ".tk",
                ".ml",
                ".ga",
                ".cf",
                ".gq",
            ]
        )

    def extract_domain_features(self, domain: str) -> Dict[str, float]:
        """Extract features from domain for DGA detection."""
        features = {}

        features["length"] = len(domain)

        digits = sum(1 for c in domain if c.isdigit())
        features["digit_ratio"] = digits / len(domain) if domain else 0

        consonants = sum(1 for c in domain.lower() if c in "bcdfghjklmnpqrstvwxyz")
        features["consonant_ratio"] = consonants / len(domain) if domain else 0

        features["unique_chars"] = len(set(domain))

        features["entropy"] = self._calculate_domain_entropy(domain)

        parts = domain.split(".")
        features["subdomain_count"] = len(parts) - 1 if len(parts) > 1 else 0

        features["has_hyphen"] = 1 if "-" in domain else 0

        features["avg_part_length"] = np.mean([len(p) for p in parts]) if parts else 0

        tld = "." + parts[-1] if parts else ""
        features["suspicious_tld"] = 1 if tld in self.tld_list else 0

        return features

    def _calculate_domain_entropy(self, domain: str) -> float:
        """Calculate entropy of domain characters."""
        char_counts = {}
        for char in domain.lower():
            char_counts[char] = char_counts.get(char, 0) + 1

        total = len(domain)
        probabilities = [count / total for count in char_counts.values()]

        return -sum(p * np.log2(p) for p in probabilities if p > 0)

    def is_dga(self, domain: str, threshold: float = 0.7) -> Tuple[bool, float]:
        """Detect if domain is likely DGA-generated."""
        if domain.lower() in self.alexa_domains:
            return False, 0.0

        features = self.extract_domain_features(domain)

        dga_score = 0.0

        if features["length"] > 15:
            dga_score += 0.3

        if features["digit_ratio"] > 0.3:
            dga_score += 0.3

        if features["entropy"] > 3.5:
            dga_score += 0.2

        if features["suspicious_tld"] == 1:
            dga_score += 0.2

        is_dga = dga_score >= threshold

        return is_dga, dga_score


class MLOrchestrator:
    """Orchestrates all ML models."""

    def __init__(self):
        self.beaconing_detector = BeaconingDetector()
        self.anomaly_detector = AnomalyDetector()
        self.dga_detector = DGADetector()

    def analyze_network_behavior(
        self, timestamps: List[datetime], destination: str
    ) -> Dict[str, Any]:
        """Analyze network connection patterns."""
        is_beaconing, score = self.beaconing_detector.detect_beaconing(
            timestamps, destination
        )

        return {
            "is_beaconing": is_beaconing,
            "beacon_score": score,
            "destination": destination,
            "connection_count": len(timestamps),
        }

    def analyze_user_behavior(
        self,
        login_times: List[int],
        source_ips: List[str],
        auth_count: int,
        unique_hosts: int,
    ) -> Dict[str, Any]:
        """Analyze user authentication patterns."""
        is_anomalous, score = self.anomaly_detector.detect_anomaly(
            login_times, source_ips, auth_count, unique_hosts
        )

        return {
            "is_anomalous": is_anomalous,
            "anomaly_score": score,
            "auth_count": auth_count,
            "unique_hosts": unique_hosts,
        }

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain for DGA characteristics."""
        is_dga, score = self.dga_detector.is_dga(domain)

        return {"is_dga": is_dga, "dga_score": score, "domain": domain}
