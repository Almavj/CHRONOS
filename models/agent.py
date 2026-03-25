from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
import uuid


@dataclass
class Agent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    hostname: str = ""
    platform: str = ""
    ip_address: str = ""
    os_version: str = ""
    status: str = "active"
    tags: List[str] = field(default_factory=list)
    registered_at: datetime = field(default_factory=datetime.now)
    last_seen: Optional[datetime] = None
    version: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "platform": self.platform,
            "ip_address": self.ip_address,
            "os_version": self.os_version,
            "status": self.status,
            "tags": self.tags,
            "registered_at": self.registered_at.isoformat()
            if self.registered_at
            else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "version": self.version,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Agent":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            agent_id=data.get("agent_id", ""),
            hostname=data.get("hostname", ""),
            platform=data.get("platform", ""),
            ip_address=data.get("ip_address", ""),
            os_version=data.get("os_version", ""),
            status=data.get("status", "active"),
            tags=data.get("tags", []),
            registered_at=datetime.fromisoformat(data["registered_at"])
            if data.get("registered_at")
            else datetime.now(),
            last_seen=datetime.fromisoformat(data["last_seen"])
            if data.get("last_seen")
            else None,
            version=data.get("version", ""),
            metadata=data.get("metadata", {}),
        )


class AgentStatus:
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"
