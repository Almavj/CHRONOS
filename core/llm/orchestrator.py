"""
LLM Orchestrator - Main entry point
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from chronos.core.llm.models import ThreatAnalysis, LLMConfig
from chronos.core.llm.client import LLMClient
from chronos.core.llm.utils.env_loader import load_llm_config, load_dotenv

logger = logging.getLogger(__name__)


class LLMOrchestrator:
    """Main orchestrator for LLM operations."""

    def __init__(self):
        load_dotenv()
        self.config = load_llm_config()
        self.client = LLMClient(self.config)
        self._request_count = 0

    @property
    def is_enabled(self) -> bool:
        """Check if LLM is enabled."""
        return self.client.enabled if self.client else False

    def analyze_alert(self, alert_data: Dict[str, Any]) -> ThreatAnalysis:
        """Analyze an alert using LLM."""
        self._request_count += 1

        if self.client:
            return self.client.analyze_threat(alert_data)

        return self._basic_analysis(alert_data)

    def suggest_hunt_queries(self, alert_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Suggest hunt queries based on alert analysis."""
        technique = alert_data.get("technique", "")
        indicators = alert_data.get("indicators", [])

        queries = []

        for indicator in indicators:
            if "." in indicator and not indicator.startswith("http"):
                queries.append(
                    {
                        "name": f"Network connections to {indicator}",
                        "query": f"source_ip:{indicator} OR destination_ip:{indicator}",
                        "source": "Network logs",
                    }
                )
            elif "/" in indicator or len(indicator) in (32, 64):
                queries.append(
                    {
                        "name": f"Hash: {indicator}",
                        "query": f"file_hash:{indicator}",
                        "source": "File events",
                    }
                )

        queries.append(
            {
                "name": f"Technique: {technique}",
                "query": f"technique:{technique}",
                "source": "All sources",
            }
        )

        return queries

    def generate_summary(self, alerts: List[Dict[str, Any]]) -> str:
        """Generate a summary of multiple alerts."""
        if not self.client or not self.is_enabled:
            return self._basic_summary(alerts)

        from chronos.core.llm.prompts import PromptBuilder

        prompt = PromptBuilder.build_summary_prompt(alerts)

        try:
            config_dict = {
                "api_key": self.client.config.api_key,
                "api_url": self.client.config.api_url,
                "model": self.client.config.model,
                "max_tokens": 1000,
                "temperature": 0.5,
                "timeout": 30,
            }
            response = self.client.adapter.call(prompt, config_dict)
            return response
        except Exception as e:
            logger.error(f"Summary generation failed: {e}")
            return self._basic_summary(alerts)

    def _basic_analysis(self, alert_data: Dict[str, Any]) -> ThreatAnalysis:
        """Provide basic analysis without LLM."""
        severity = alert_data.get("severity", "medium")

        return ThreatAnalysis(
            threat_type=alert_data.get("technique", "Unknown threat"),
            confidence=0.65,
            description=alert_data.get("description", "Security event detected"),
            mitre_tactics=["initial-access"],
            mitre_techniques=[alert_data.get("technique", "T0000")],
            severity=severity,
            recommendations=[
                "Review alert details",
                "Check related logs",
                "Consider threat intelligence enrichment",
            ],
        )

    def _basic_summary(self, alerts: List[Dict[str, Any]]) -> str:
        """Generate basic summary without LLM."""
        by_severity = {}
        for alert in alerts:
            sev = alert.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return f"""Security Alert Summary
Generated: {datetime.now().isoformat()}
Total Alerts: {len(alerts)}

By Severity:
{chr(10).join(f"  - {k}: {v}" for k, v in by_severity.items())}

Top Techniques:
{chr(10).join(f"  - {a.get('technique', 'Unknown')}" for a in alerts[:5])}

Recommendations:
1. Review critical alerts first
2. Enrich alerts with threat intelligence
3. Investigate patterns across multiple alerts
"""

    @property
    def stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "enabled": self.is_enabled,
            "requests": self._request_count,
            "client_stats": self.client.get_stats() if self.client else {},
        }


_orchestrator_instance: Optional[LLMOrchestrator] = None


def get_orchestrator() -> LLMOrchestrator:
    """Get or create the singleton orchestrator instance."""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = LLMOrchestrator()
    return _orchestrator_instance
