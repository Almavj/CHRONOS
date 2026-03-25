"""
Threat Intelligence Integration for CHRONOS
MISP, VirusTotal, AbuseIPDB integration
"""

import logging
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import hashlib
import time

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    """Threat intelligence lookup result."""

    indicator: str
    indicator_type: str
    reputation: str
    score: int
    source: str
    details: Dict[str, Any]
    last_seen: Optional[str] = None


class MISPClient:
    """MISP Threat Intelligence Platform client."""

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Authorization": api_key,  # This format works for MISP
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "MISP-Client/1.0"
        })

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """Make HTTP request with error handling."""
        try:
            url = f"{self.url}{endpoint}"
            response = self.session.request(method, url, timeout=30, **kwargs)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                logger.error("MISP authentication failed - check API key")
                return None
            elif response.status_code == 403:
                logger.error("MISP permission denied")
                return None
            else:
                logger.error(f"MISP error {response.status_code}: {response.text[:200]}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error("MISP request timeout")
        except requests.exceptions.ConnectionError:
            logger.error("MISP connection error - check URL")
        except Exception as e:
            logger.error(f"MISP request error: {e}")
        
        return None

    def search_events(
        self, indicator: str = None, indicator_type: str = None, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Search MISP for indicator."""
        params = {"limit": limit, "returnFormat": "json"}

        # Build search parameters
        if indicator:
            if indicator_type == "ip":
                params["ip"] = indicator
            elif indicator_type == "domain":
                params["domain"] = indicator
            elif indicator_type == "hash":
                params["hash"] = indicator
            elif indicator_type == "url":
                params["url"] = indicator
            elif indicator_type == "email":
                params["email"] = indicator
            else:
                params["value"] = indicator

        response_data = self._make_request("GET", "/events/restSearch", params=params)

        if response_data:
            # MISP can return either a list or dict with 'Event' key
            if "response" in response_data:
                response = response_data["response"]
                if isinstance(response, list):
                    return response
                elif isinstance(response, dict) and "Event" in response:
                    return response["Event"]
            
            return response_data.get("Event", [])

        return []

    def add_event(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Add new event to MISP."""
        response_data = self._make_request("POST", "/events", json=event_data)

        if response_data and "response" in response_data:
            return response_data["response"].get("Event", {}).get("id")

        return None

    def get_indicator_reputation(
        self, indicator: str, indicator_type: str
    ) -> ThreatIntelResult:
        """Get indicator reputation from MISP."""
        events = self.search_events(indicator, indicator_type, limit=1)

        if events:
            event = events[0]
            
            # Calculate confidence score based on event attributes
            attributes = event.get("Attribute", [])
            related_indicators = len(attributes)
            
            # MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined
            threat_level = event.get("threat_level_id", 4)
            threat_level_score = {1: 100, 2: 75, 3: 50, 4: 25}.get(threat_level, 25)
            
            # Combine scores (70% from threat level, 30% from attribute count)
            score = min(100, int((threat_level_score * 0.7) + (min(related_indicators * 5, 30))))

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation="malicious" if score >= 50 else "suspicious",
                score=score,
                source="MISP",
                details={
                    "event_id": event.get("id"),
                    "event_info": event.get("info"),
                    "threat_level_id": threat_level,
                    "analysis": event.get("analysis"),
                    "distribution": event.get("distribution"),
                    "attribute_count": related_indicators,
                    "tags": event.get("Tag", []),
                    "organization": event.get("Orgc", {}).get("name")
                },
                last_seen=event.get("last_seen") or event.get("timestamp"),
            )

        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation="unknown",
            score=0,
            source="MISP",
            details={},
        )

    def test_connection(self) -> bool:
        """Test MISP connection and authentication."""
        response_data = self._make_request("GET", "/servers/getVersion")
        if response_data and "version" in response_data:
            logger.info(f"Connected to MISP version {response_data['version']}")
            return True
        return False


class VirusTotalClient:
    """VirusTotal API client."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "Accept": "application/json"})

    def get_file_report(self, file_hash: str) -> ThreatIntelResult:
        """Get file reputation from VirusTotal."""
        try:
            response = self.session.get(
                f"{self.base_url}/files/{file_hash}", timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                score = int((malicious + suspicious) / total * 100) if total > 0 else 0

                return ThreatIntelResult(
                    indicator=file_hash,
                    indicator_type="hash",
                    reputation="malicious"
                    if score > 50
                    else "suspicious"
                    if score > 25
                    else "clean",
                    score=score,
                    source="VirusTotal",
                    details={
                        "stats": stats,
                        "names": data.get("data", {})
                        .get("attributes", {})
                        .get("meaningful_names", [])[:5],
                    },
                )

        except Exception as e:
            logger.error(f"VirusTotal lookup error: {e}")

        return ThreatIntelResult(
            indicator=file_hash,
            indicator_type="hash",
            reputation="unknown",
            score=0,
            source="VirusTotal",
            details={},
        )

    def get_ip_report(self, ip: str) -> ThreatIntelResult:
        """Get IP reputation from VirusTotal."""
        try:
            response = self.session.get(
                f"{self.base_url}/ip_addresses/{ip}", timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                malicious = stats.get("malicious", 0)
                total = sum(stats.values())

                score = int(malicious / total * 100) if total > 0 else 0

                return ThreatIntelResult(
                    indicator=ip,
                    indicator_type="ip",
                    reputation="malicious"
                    if score > 50
                    else "suspicious"
                    if score > 25
                    else "clean",
                    score=score,
                    source="VirusTotal",
                    details={
                        "country": data.get("data", {})
                        .get("attributes", {})
                        .get("country"),
                        "as_owner": data.get("data", {})
                        .get("attributes", {})
                        .get("as_owner"),
                        "stats": stats,
                    },
                )

        except Exception as e:
            logger.error(f"VirusTotal IP lookup error: {e}")

        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            reputation="unknown",
            score=0,
            source="VirusTotal",
            details={},
        )

    def get_domain_report(self, domain: str) -> ThreatIntelResult:
        """Get domain reputation from VirusTotal."""
        try:
            response = self.session.get(f"{self.base_url}/domains/{domain}", timeout=30)

            if response.status_code == 200:
                data = response.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                score = int((malicious + suspicious) / total * 100) if total > 0 else 0

                return ThreatIntelResult(
                    indicator=domain,
                    indicator_type="domain",
                    reputation="malicious"
                    if score > 50
                    else "suspicious"
                    if score > 25
                    else "clean",
                    score=score,
                    source="VirusTotal",
                    details={
                        "stats": stats,
                        "creation_date": data.get("data", {})
                        .get("attributes", {})
                        .get("creation_date"),
                        "registrar": data.get("data", {})
                        .get("attributes", {})
                        .get("registrar"),
                    },
                )

        except Exception as e:
            logger.error(f"VirusTotal domain lookup error: {e}")

        return ThreatIntelResult(
            indicator=domain,
            indicator_type="domain",
            reputation="unknown",
            score=0,
            source="VirusTotal",
            details={},
        )


class AbuseIPDBClient:
    """AbuseIPDB API client."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.session = requests.Session()
        self.session.headers.update({"Key": api_key, "Accept": "application/json"})

    def check_ip(self, ip: str, max_age_days: int = 30) -> ThreatIntelResult:
        """Check IP reputation from AbuseIPDB."""
        try:
            params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}

            response = self.session.get(
                f"{self.base_url}/check", params=params, timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                ip_data = data.get("data", {})

                abuse_confidence = ip_data.get("abuseConfidenceScore", 0)

                return ThreatIntelResult(
                    indicator=ip,
                    indicator_type="ip",
                    reputation="malicious"
                    if abuse_confidence > 50
                    else "suspicious"
                    if abuse_confidence > 25
                    else "clean",
                    score=abuse_confidence,
                    source="AbuseIPDB",
                    details={
                        "country_code": ip_data.get("countryCode"),
                        "ip_version": ip_data.get("ipVersion"),
                        "is_whitelisted": ip_data.get("isWhitelisted", False),
                        "total_reports": ip_data.get("totalReports", 0),
                        "num_distinct_users": ip_data.get("numDistinctUsers", 0),
                        "last_reported_at": ip_data.get("lastReportedAt"),
                        "categories": ip_data.get("categories", []),
                    },
                    last_seen=ip_data.get("lastReportedAt"),
                )

        except Exception as e:
            logger.error(f"AbuseIPDB lookup error: {e}")

        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            reputation="unknown",
            score=0,
            source="AbuseIPDB",
            details={},
        )


class ThreatIntelOrchestrator:
    """Orchestrates threat intelligence lookups."""

    def __init__(
        self,
        misp_config: Dict[str, str] = None,
        virustotal_config: Dict[str, str] = None,
        abuseipdb_config: Dict[str, str] = None,
    ):
        self.misp = None
        self.virustotal = None
        self.abuseipdb = None

        if misp_config and misp_config.get("url") and misp_config.get("api_key"):
            try:
                self.misp = MISPClient(
                    misp_config.get("url", ""), misp_config.get("api_key", "")
                )
            except Exception as e:
                logger.warning(f"MISP initialization failed: {e}")

        if virustotal_config and virustotal_config.get("api_key"):
            try:
                self.virustotal = VirusTotalClient(virustotal_config.get("api_key", ""))
            except Exception as e:
                logger.warning(f"VirusTotal initialization failed: {e}")

        if abuseipdb_config and abuseipdb_config.get("api_key"):
            try:
                self.abuseipdb = AbuseIPDBClient(abuseipdb_config.get("api_key", ""))
            except Exception as e:
                logger.warning(f"AbuseIPDB initialization failed: {e}")

        if not any([self.misp, self.virustotal, self.abuseipdb]):
            logger.info(
                "No threat intelligence providers configured - enrichment disabled"
            )

    def enrich_indicator(
        self, indicator: str, indicator_type: str = None
    ) -> List[ThreatIntelResult]:
        """Enrich an indicator with threat intelligence."""
        results = []

        if indicator_type is None:
            indicator_type = self._infer_indicator_type(indicator)

        if indicator_type == "ip":
            results.extend(self._enrich_ip(indicator))
        elif indicator_type == "domain":
            results.extend(self._enrich_domain(indicator))
        elif indicator_type == "hash":
            results.extend(self._enrich_hash(indicator))

        return results

    def _infer_indicator_type(self, indicator: str) -> str:
        """Infer indicator type from format."""
        if "." in indicator and "/" not in indicator:
            if indicator.replace(".", "").replace(":", "").isdigit():
                return "ip"
            return "domain"
        elif len(indicator) in [32, 40, 64] and indicator.isalnum():
            return "hash"
        return "unknown"

    def _enrich_ip(self, ip: str) -> List[ThreatIntelResult]:
        """Enrich IP indicator."""
        results = []

        if self.virustotal:
            results.append(self.virustotal.get_ip_report(ip))

        if self.abuseipdb:
            results.append(self.abuseipdb.check_ip(ip))

        if self.misp:
            results.append(self.misp.get_indicator_reputation(ip, "ip"))

        return results

    def _enrich_domain(self, domain: str) -> List[ThreatIntelResult]:
        """Enrich domain indicator."""
        results = []

        if self.virustotal:
            results.append(self.virustotal.get_domain_report(domain))

        if self.misp:
            results.append(self.misp.get_indicator_reputation(domain, "domain"))

        return results

    def _enrich_hash(self, file_hash: str) -> List[ThreatIntelResult]:
        """Enrich file hash indicator."""
        results = []

        if self.virustotal:
            results.append(self.virustotal.get_file_report(file_hash))

        if self.misp:
            results.append(self.misp.get_indicator_reputation(file_hash, "hash"))

        return results

    def get_aggregated_score(self, results: List[ThreatIntelResult]) -> Dict[str, Any]:
        """Calculate aggregated threat score from multiple sources."""
        if not results:
            return {"score": 0, "reputation": "unknown", "sources": []}

        scores = [r.score for r in results if r.score > 0]

        if not scores:
            return {
                "score": 0,
                "reputation": "unknown",
                "sources": [r.source for r in results],
            }

        avg_score = sum(scores) / len(scores)

        reputations = [r.reputation for r in results if r.reputation != "unknown"]

        if "malicious" in reputations:
            final_reputation = "malicious"
        elif "suspicious" in reputations:
            final_reputation = "suspicious"
        else:
            final_reputation = "clean"

        return {
            "score": int(avg_score),
            "reputation": final_reputation,
            "sources": [r.source for r in results],
            "details": [r.details for r in results],
        }
