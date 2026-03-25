"""
Prompt builder for threat analysis
"""

from typing import Dict, Any, List
from datetime import datetime


SYSTEM_PROMPT = """You are a security analyst assistant specializing in threat intelligence and incident response.

Analyze security alerts and provide structured threat analysis in JSON format with the following schema:
{
    "threat_type": "string - classification of the threat",
    "confidence": "float (0-1) - confidence in the analysis",
    "description": "string - detailed description of the threat",
    "mitre_tactics": ["array of MITRE ATT&CK tactic names"],
    "mitre_techniques": ["array of MITRE ATT&CK technique IDs"],
    "severity": "string - one of: low, medium, high, critical",
    "recommendations": ["array of recommended response actions"]
}

Be concise and focus on actionable intelligence."""


HUNT_SYSTEM_PROMPT = """You are a threat hunting assistant. Based on the alert context, suggest:
1. hunt queries to run
2. additional data sources to investigate
3. potential IOCs to search for

Provide your response in JSON format:
{
    "suggested_queries": [{"name": "string", "query": "string", "source": "string"}],
    "additional_sources": ["string"],
    "potential_iocs": ["string"],
    "hypothesis": "string - hunting hypothesis to test"
}"""


SUMMARY_SYSTEM_PROMPT = """You are a SOC reporting assistant. Summarize security alerts into a concise incident report.

Provide your response in JSON format:
{
    "executive_summary": "string - 2-3 sentence summary",
    "key_findings": ["string"],
    "affected_systems": ["string"],
    "recommended_actions": ["string"],
    "severity_assessment": "string"
}"""


class PromptBuilder:
    """Build prompts for different LLM use cases."""

    @staticmethod
    def build_analysis_prompt(alert_data: Dict[str, Any]) -> str:
        """Build threat analysis prompt from alert data."""
        context = f"""
Alert Context:
- Title: {alert_data.get("title", "N/A")}
- Description: {alert_data.get("description", "N/A")}
- Severity: {alert_data.get("severity", "N/A")}
- MITRE Technique: {alert_data.get("technique", "N/A")}
- TTP: {alert_data.get("ttp", "N/A")}
- Indicators: {", ".join(alert_data.get("indicators", []) or ["None"])}
- Source: {alert_data.get("source", alert_data.get("hostname", "N/A"))}
- Timestamp: {alert_data.get("timestamp", datetime.now().isoformat())}
- User: {alert_data.get("user", "N/A")}
- Destination IP: {alert_data.get("destination_ip", "N/A")}
"""
        return f"{SYSTEM_PROMPT}\n\n{context}"

    @staticmethod
    def build_hunt_prompt(alert_data: Dict[str, Any]) -> str:
        """Build threat hunting prompt from alert data."""
        context = f"""
Based on this alert, suggest threat hunting activities:

Alert: {alert_data.get("title", "N/A")}
Technique: {alert_data.get("technique", "N/A")}
Indicators: {", ".join(alert_data.get("indicators", []) or ["None"])}
Source: {alert_data.get("source", alert_data.get("hostname", "N/A"))}
"""
        return f"{HUNT_SYSTEM_PROMPT}\n\n{context}"

    @staticmethod
    def build_summary_prompt(alerts: List[Dict[str, Any]]) -> str:
        """Build summary prompt from multiple alerts."""
        alert_list = "\n".join(
            [
                f"- {a.get('title', 'Unknown')}: {a.get('description', 'N/A')[:100]}"
                for a in alerts[:20]
            ]
        )

        summary = f"""
Summarize the following {len(alerts)} security alerts:

{alert_list}
"""
        return f"{SUMMARY_SYSTEM_PROMPT}\n\n{summary}"

    @staticmethod
    def build_ioc_extraction_prompt(text: str) -> str:
        """Build prompt to extract IOCs from text."""
        return f"""Extract Indicators of Compromise (IOCs) from the following text. Return as JSON array of objects with type and value:

Text:
{text}

Return format:
{{
    "iocs": [
        {{"type": "ip|domain|hash|email|url", "value": "string", "context": "string"}}
    ]
}}"""
