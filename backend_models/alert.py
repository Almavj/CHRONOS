from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
import uuid


@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: str = "info"
    status: str = "new"
    technique: str = ""
    ttp: str = ""
    indicators: List[str] = field(default_factory=list)
    hostname: str = ""
    user: str = ""
    destination_ip: str = ""
    source_ip: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "technique": self.technique,
            "ttp": self.ttp,
            "indicators": self.indicators,
            "hostname": self.hostname,
            "user": self.user,
            "destination_ip": self.destination_ip,
            "source_ip": self.source_ip,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat()
            if self.acknowledged_at
            else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=data.get("severity", "info"),
            status=data.get("status", "new"),
            technique=data.get("technique", ""),
            ttp=data.get("ttp", ""),
            indicators=data.get("indicators", []),
            hostname=data.get("hostname", ""),
            user=data.get("user", ""),
            destination_ip=data.get("destination_ip", ""),
            source_ip=data.get("source_ip", ""),
            metadata=data.get("metadata", {}),
            created_at=datetime.fromisoformat(data["created_at"])
            if data.get("created_at")
            else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"])
            if data.get("updated_at")
            else None,
            acknowledged_at=datetime.fromisoformat(data["acknowledged_at"])
            if data.get("acknowledged_at")
            else None,
            resolved_at=datetime.fromisoformat(data["resolved_at"])
            if data.get("resolved_at")
            else None,
        )


class AlertSeverity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus:
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
