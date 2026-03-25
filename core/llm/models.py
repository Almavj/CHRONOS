"""
LLM Configuration and Data Models
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from enum import Enum


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"
    OLLAMA = "ollama"


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LLMConfig:
    provider: str
    api_key: str
    api_url: str
    model: str
    max_tokens: int = 2048
    temperature: float = 0.7
    timeout: int = 30
    max_retries: int = 3
    cache_enabled: bool = True
    cache_ttl: int = 3600
    rate_limit_requests: int = 60
    rate_limit_period: int = 60

    @classmethod
    def from_env(cls):
        """Load configuration from environment variables."""
        from chronos.core.llm.utils.env_loader import load_llm_config

        return load_llm_config()


class LLMResponse(BaseModel):
    threat_type: str = "Unknown Threat"
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    description: str = "Security event detected"
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    severity: str = Field(default="medium")
    recommendations: List[str] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = ["low", "medium", "high", "critical"]
        if v.lower() not in valid:
            return "medium"
        return v.lower()


@dataclass
class ThreatAnalysis:
    threat_type: str
    confidence: float
    description: str
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    severity: str = "medium"
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "description": self.description,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "severity": self.severity,
            "recommendations": self.recommendations,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatAnalysis":
        return cls(
            threat_type=data.get("threat_type", "unknown"),
            confidence=data.get("confidence", 0.0),
            description=data.get("description", ""),
            mitre_tactics=data.get("mitre_tactics", []),
            mitre_techniques=data.get("mitre_techniques", []),
            severity=data.get("severity", "medium"),
            recommendations=data.get("recommendations", []),
        )

    @classmethod
    def from_llm_response(cls, response: LLMResponse) -> "ThreatAnalysis":
        return cls(
            threat_type=response.threat_type,
            confidence=response.confidence,
            description=response.description,
            mitre_tactics=response.mitre_tactics,
            mitre_techniques=response.mitre_techniques,
            severity=response.severity,
            recommendations=response.recommendations,
        )


@dataclass
class LLMMetrics:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    cached_responses: int = 0
    total_tokens: int = 0
    response_times: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "cached_responses": self.cached_responses,
            "total_tokens": self.total_tokens,
            "avg_response_time": self.avg_response_time,
            "success_rate": self.success_rate,
        }

    @property
    def avg_response_time(self) -> float:
        if not self.response_times:
            return 0.0
        return sum(self.response_times) / len(self.response_times)

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests

    def record_request(self, success: bool, response_time: float, cached: bool = False):
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        if cached:
            self.cached_responses += 1
        self.response_times.append(response_time)
