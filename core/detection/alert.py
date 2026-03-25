"""
Alert data structures and creation utilities
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field, asdict
import uuid


class AlertSeverity(Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Alert processing status."""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Alert:
    """Security alert data structure."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: AlertSeverity = AlertSeverity.INFO
    status: AlertStatus = AlertStatus.NEW
    technique: str = ""
    ttp: str = ""
    indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source: str = "chronos"
    hostname: str = ""
    user: str = ""
    destination_ip: str = ""
    mitre_technique_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        data = asdict(self)
        data["severity"] = (
            self.severity.value
            if isinstance(self.severity, AlertSeverity)
            else self.severity
        )
        data["status"] = (
            self.status.value if isinstance(self.status, AlertStatus) else self.status
        )
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """Create alert from dictionary."""
        if isinstance(data.get("severity"), str):
            data["severity"] = AlertSeverity(data["severity"])
        if isinstance(data.get("status"), str):
            data["status"] = AlertStatus(data["status"])
        return cls(**data)


def create_alert(
    title: str,
    description: str,
    severity: AlertSeverity,
    technique: str = "",
    ttp: str = "",
    indicators: List[str] = None,
    metadata: Dict[str, Any] = None,
    hostname: str = "",
    user: str = "",
    destination_ip: str = "",
    mitre_technique_id: str = "",
) -> Alert:
    """Factory function to create an alert."""
    return Alert(
        title=title,
        description=description,
        severity=severity,
        technique=technique,
        ttp=ttp,
        indicators=indicators or [],
        metadata=metadata or {},
        hostname=hostname,
        user=user,
        destination_ip=destination_ip,
        mitre_technique_id=mitre_technique_id,
    )
