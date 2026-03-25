"""
Response parser and validator
"""

import json
import re
import logging
from typing import Dict, Any, Optional
from chronos.core.llm.models import ThreatAnalysis, LLMResponse

logger = logging.getLogger(__name__)

MITRE_TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


class ResponseParser:
    """Parse and validate LLM responses."""

    @staticmethod
    def parse_json_response(response: str) -> Optional[ThreatAnalysis]:
        """Parse JSON response into ThreatAnalysis."""
        text = response.strip()

        json_match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
        if json_match:
            text = json_match.group()
        elif text.startswith("```"):
            lines = text.split("\n")
            json_lines = []
            in_json = False
            for line in lines:
                if line.strip().startswith("```"):
                    in_json = not in_json
                    continue
                if in_json:
                    json_lines.append(line)
                elif line.strip().startswith("{"):
                    in_json = True
                    json_lines.append(line)
                elif json_lines:
                    json_lines.append(line)
            if json_lines:
                text = "\n".join(json_lines)

        try:
            data = json.loads(text)

            field_map = {
                "threat_type": ["threat_type", "classification", "threat", "type"],
                "confidence": ["confidence", "score"],
                "description": ["description", "summary", "analysis"],
                "mitre_tactics": ["mitre_tactics", "tactics", "attack_tactics"],
                "mitre_techniques": [
                    "mitre_techniques",
                    "techniques",
                    "mitre_techniques_list",
                ],
                "severity": ["severity", "risk_level"],
                "recommendations": ["recommendations", "remediation", "actions"],
            }

            normalized = {}
            for field, aliases in field_map.items():
                for alias in aliases:
                    if alias in data:
                        normalized[field] = data[alias]
                        break

            validated = LLMResponse(**normalized)
            return ThreatAnalysis.from_llm_response(validated)
        except json.JSONDecodeError:
            return None
        except Exception as e:
            logger.warning(f"Validation error: {e}")
            return None
        except Exception as e:
            logger.warning(f"Validation error: {e}")
            return None

    @staticmethod
    def parse_text_response(response: str) -> ThreatAnalysis:
        """Parse plain text response as fallback with enhanced extraction."""
        lines = response.strip().split("\n")

        threat_type = "Analyzed Threat"
        confidence = 0.75
        description = response[:500] if len(response) > 500 else response
        mitre_tactics = []
        mitre_techniques = []
        severity = "medium"
        recommendations = ["Review alert details", "Check related logs"]

        response_lower = response.lower()

        for tactic in MITRE_TACTICS:
            if tactic in response_lower:
                mitre_tactics.append(tactic.replace("-", " "))

        techniques = re.findall(r"T\d{4}(?:\.\d{3})?", response)
        mitre_techniques = list(set(techniques))

        for sev in ["critical", "high", "medium", "low"]:
            if sev in response_lower:
                severity = sev
                break

        if "recommend" in response_lower or "suggest" in response_lower:
            sentences = response.split(".")
            for sent in sentences:
                if "recommend" in sent.lower() or "suggest" in sent.lower():
                    cleaned = sent.strip()
                    if len(cleaned) > 10 and len(cleaned) < 200:
                        recommendations.append(cleaned)

        if "threat" in response_lower or "attack" in response_lower:
            words = response.split()
            for i, word in enumerate(words[:3]):
                if any(c.isalpha() for c in word) and len(word) > 3:
                    threat_type = f"Potential {word.capitalize()} Threat"
                    break

        return ThreatAnalysis(
            threat_type=threat_type,
            confidence=confidence,
            description=description,
            mitre_tactics=mitre_tactics[:3],
            mitre_techniques=mitre_techniques[:5],
            severity=severity,
            recommendations=recommendations[:5],
        )

    @classmethod
    def parse_response(cls, response: str) -> ThreatAnalysis:
        """Parse response, trying JSON first, then text fallback."""
        if not response or not response.strip():
            return ThreatAnalysis(
                threat_type="Analysis Unavailable",
                confidence=0.5,
                description="No response from LLM",
                recommendations=["Review manually", "Check system logs"],
            )
        parsed = cls.parse_json_response(response)
        if parsed:
            return parsed
        return cls.parse_text_response(response)


class HuntResponseParser:
    """Parse hunting suggestions response."""

    @staticmethod
    def parse(response: str) -> Dict[str, Any]:
        """Parse hunting suggestions from LLM response."""
        try:
            data = json.loads(response)
            return {
                "suggested_queries": data.get("suggested_queries", []),
                "additional_sources": data.get("additional_sources", []),
                "potential_iocs": data.get("potential_iocs", []),
                "hypothesis": data.get("hypothesis", ""),
            }
        except Exception as e:
            logger.warning(f"Failed to parse hunt response: {e}")
            return cls._fallback(response)

    @staticmethod
    def _fallback(response: str) -> Dict[str, Any]:
        """Fallback parsing for non-JSON response."""
        return {
            "suggested_queries": [],
            "additional_sources": [],
            "potential_iocs": [],
            "hypothesis": response[:500],
        }


class SummaryResponseParser:
    """Parse summary response."""

    @staticmethod
    def parse(response: str) -> Dict[str, Any]:
        """Parse summary from LLM response."""
        try:
            data = json.loads(response)
            return {
                "executive_summary": data.get("executive_summary", ""),
                "key_findings": data.get("key_findings", []),
                "affected_systems": data.get("affected_systems", []),
                "recommended_actions": data.get("recommended_actions", []),
                "severity_assessment": data.get("severity_assessment", "medium"),
            }
        except Exception as e:
            logger.warning(f"Failed to parse summary response: {e}")
            return {
                "executive_summary": response[:500],
                "key_findings": [],
                "affected_systems": [],
                "recommended_actions": [],
                "severity_assessment": "medium",
            }
