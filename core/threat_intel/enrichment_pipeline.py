#!/usr/bin/env python3
"""
MISP Threat Intelligence Integration
Real MISP integration with auto-enrichment for IOCs
"""

import os
import sys
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ReputationLevel(Enum):
    """Threat reputation levels."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


@dataclass
class IOCEnrichment:
    """IOC enrichment result."""

    indicator: str
    indicator_type: str
    reputation: ReputationLevel
    score: int
    sources: List[str]
    details: Dict[str, Any]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = None
    malware_families: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.malware_families is None:
            self.malware_families = []


class MISPProvider:
    """MISP Threat Intelligence provider."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.url = config.get("url", "")
        self.api_key = config.get("api_key", "")
        self.verify_ssl = config.get("verify_ssl", True)
        self.client = None
        self.session = None

        if self.url and self.api_key:
            self._connect()

    def _connect(self):
        """Connect to MISP."""
        try:
            import requests

            self.session = requests.Session()
            self.session.verify = self.verify_ssl
            self.session.headers.update(
                {
                    "Authorization": self.api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "MISP-Organisation": "CHRONOS",
                }
            )

            response = self.session.get(f"{self.url}/servers/getVersion", timeout=10)
            if response.status_code == 200:
                version = response.json().get("version", "unknown")
                logger.info(f"Connected to MISP version {version}")
            else:
                logger.warning(f"MISP connection failed: {response.status_code}")

        except ImportError:
            logger.error("requests library not installed")
        except Exception as e:
            logger.error(f"Failed to connect to MISP: {e}")

    def search_indicator(
        self, indicator: str, indicator_type: str = None
    ) -> IOCEnrichment:
        """Search for indicator in MISP."""
        if not self.session:
            return IOCEnrichment(
                indicator=indicator,
                indicator_type=indicator_type or "unknown",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["MISP"],
                details={"error": "Not connected"},
            )

        try:
            if indicator_type == "ip":
                params = {"ip": indicator}
            elif indicator_type == "domain":
                params = {"domain": indicator}
            elif indicator_type == "hash":
                params = {"hash": indicator}
            elif indicator_type == "url":
                params = {"url": indicator}
            elif indicator_type == "email":
                params = {"email": indicator}
            else:
                params = {"value": indicator}

            params["returnFormat"] = "json"
            params["limit"] = 10

            response = self.session.get(
                f"{self.url}/events/restSearch", params=params, timeout=30
            )

            if response.status_code != 200:
                return IOCEnrichment(
                    indicator=indicator,
                    indicator_type=indicator_type or "unknown",
                    reputation=ReputationLevel.UNKNOWN,
                    score=0,
                    sources=["MISP"],
                    details={"error": f"HTTP {response.status_code}"},
                )

            data = response.json()
            events = data.get("response", [])

            if not events:
                return IOCEnrichment(
                    indicator=indicator,
                    indicator_type=indicator_type or "unknown",
                    reputation=ReputationLevel.CLEAN,
                    score=0,
                    sources=["MISP"],
                    details={"found": False},
                )

            event = events[0] if isinstance(events, list) else events.get("Event", {})

            threat_level = event.get("threat_level_id", 4)
            threat_level_map = {1: 100, 2: 75, 3: 50, 4: 25}
            score = threat_level_map.get(threat_level, 25)

            attributes = event.get("Attribute", [])
            if isinstance(attributes, list):
                score = min(100, score + len(attributes) * 5)

            reputation = (
                ReputationLevel.MALICIOUS
                if score >= 50
                else ReputationLevel.SUSPICIOUS
                if score >= 25
                else ReputationLevel.CLEAN
            )

            tags = []
            malware_families = []
            if isinstance(attributes, list):
                for attr in attributes:
                    if attr.get("Tag"):
                        for tag in attr["Tag"]:
                            tags.append(tag.get("name", ""))
                    malware_family = attr.get("malware_family") or attr.get(
                        "comment", ""
                    )
                    if malware_family:
                        malware_families.append(malware_family)

            return IOCEnrichment(
                indicator=indicator,
                indicator_type=indicator_type or "unknown",
                reputation=reputation,
                score=score,
                sources=["MISP"],
                details={
                    "event_id": event.get("id"),
                    "event_info": event.get("info"),
                    "attribute_count": len(attributes)
                    if isinstance(attributes, list)
                    else 0,
                },
                first_seen=event.get("first_seen"),
                last_seen=event.get("last_seen"),
                tags=tags,
                malware_families=malware_families,
            )

        except Exception as e:
            logger.error(f"MISP search error for {indicator}: {e}")
            return IOCEnrichment(
                indicator=indicator,
                indicator_type=indicator_type or "unknown",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["MISP"],
                details={"error": str(e)},
            )

    async def search_indicator_async(
        self, indicator: str, indicator_type: str = None
    ) -> IOCEnrichment:
        """Async version of search."""
        return self.search_indicator(indicator, indicator_type)


class VirusTotalProvider:
    """VirusTotal API provider."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_key = config.get("api_key", "")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = None
        self.rate_limit = config.get("rate_limit", 4)

        if self.api_key:
            self._connect()

    def _connect(self):
        """Initialize VirusTotal session."""
        try:
            import requests

            self.session = requests.Session()
            self.session.headers.update(
                {"x-apikey": self.api_key, "Accept": "application/json"}
            )

            logger.info("VirusTotal client initialized")

        except ImportError:
            logger.error("requests library not installed")

    def infer_type(self, indicator: str) -> str:
        """Infer indicator type."""
        import re

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
            return "ip"

        if "." in indicator and "/" not in indicator:
            return "domain"

        if len(indicator) in [32, 40, 64] and re.match(r"^[a-fA-F0-9]+$", indicator):
            return "hash"

        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"

        return "unknown"

    def search_ip(self, ip: str) -> IOCEnrichment:
        """Search for IP in VirusTotal."""
        if not self.session:
            return IOCEnrichment(
                indicator=ip,
                indicator_type="ip",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["VirusTotal"],
                details={"error": "Not configured"},
            )

        try:
            response = self.session.get(
                f"{self.base_url}/ip_addresses/{ip}", timeout=30
            )

            if response.status_code == 404:
                return IOCEnrichment(
                    indicator=ip,
                    indicator_type="ip",
                    reputation=ReputationLevel.CLEAN,
                    score=0,
                    sources=["VirusTotal"],
                    details={"found": False},
                )

            if response.status_code != 200:
                return IOCEnrichment(
                    indicator=ip,
                    indicator_type="ip",
                    reputation=ReputationLevel.UNKNOWN,
                    score=0,
                    sources=["VirusTotal"],
                    details={"error": f"HTTP {response.status_code}"},
                )

            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())

            score = int((malicious / total) * 100) if total > 0 else 0
            reputation = (
                ReputationLevel.MALICIOUS
                if score >= 50
                else ReputationLevel.SUSPICIOUS
                if score >= 25
                else ReputationLevel.CLEAN
            )

            return IOCEnrichment(
                indicator=ip,
                indicator_type="ip",
                reputation=reputation,
                score=score,
                sources=["VirusTotal"],
                details={
                    "country": attrs.get("country"),
                    "as_owner": attrs.get("as_owner"),
                    "stats": stats,
                    "last_analysis_date": attrs.get("last_analysis_date"),
                },
                last_seen=str(attrs.get("last_analysis_date"))
                if attrs.get("last_analysis_date")
                else None,
            )

        except Exception as e:
            logger.error(f"VirusTotal IP search error: {e}")
            return IOCEnrichment(
                indicator=ip,
                indicator_type="ip",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["VirusTotal"],
                details={"error": str(e)},
            )

    def search_domain(self, domain: str) -> IOCEnrichment:
        """Search for domain in VirusTotal."""
        if not self.session:
            return IOCEnrichment(
                indicator=domain,
                indicator_type="domain",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["VirusTotal"],
                details={"error": "Not configured"},
            )

        try:
            response = self.session.get(f"{self.base_url}/domains/{domain}", timeout=30)

            if response.status_code == 404:
                return IOCEnrichment(
                    indicator=domain,
                    indicator_type="domain",
                    reputation=ReputationLevel.CLEAN,
                    score=0,
                    sources=["VirusTotal"],
                    details={"found": False},
                )

            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            score = int(((malicious + suspicious) / total) * 100) if total > 0 else 0
            reputation = (
                ReputationLevel.MALICIOUS
                if score >= 50
                else ReputationLevel.SUSPICIOUS
                if score >= 25
                else ReputationLevel.CLEAN
            )

            return IOCEnrichment(
                indicator=domain,
                indicator_type="domain",
                reputation=reputation,
                score=score,
                sources=["VirusTotal"],
                details={
                    "creation_date": attrs.get("creation_date"),
                    "registrar": attrs.get("registrar"),
                    "stats": stats,
                },
            )

        except Exception as e:
            logger.error(f"VirusTotal domain search error: {e}")
            return IOCEnrichment(
                indicator=domain,
                indicator_type="domain",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["VirusTotal"],
                details={"error": str(e)},
            )

    def search_hash(self, file_hash: str) -> IOCEnrichment:
        """Search for file hash in VirusTotal."""
        if not self.session:
            return IOCEnrichment(
                indicator=file_hash,
                indicator_type="hash",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["VirusTotal"],
                details={"error": "Not configured"},
            )

        try:
            response = self.session.get(
                f"{self.base_url}/files/{file_hash}", timeout=30
            )

            if response.status_code == 404:
                return IOCEnrichment(
                    indicator=file_hash,
                    indicator_type="hash",
                    reputation=ReputationLevel.CLEAN,
                    score=0,
                    sources=["VirusTotal"],
                    details={"found": False},
                )

            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            score = int(((malicious + suspicious) / total) * 100) if total > 0 else 0
            reputation = (
                ReputationLevel.MALICIOUS
                if score >= 50
                else ReputationLevel.SUSPICIOUS
                if score >= 25
                else ReputationLevel.CLEAN
            )

            return IOCEnrichment(
                indicator=file_hash,
                indicator_type="hash",
                reputation=reputation,
                score=score,
                sources=["VirusTotal"],
                details={
                    "names": attrs.get("meaningful_names", [])[:10],
                    "file_type": attrs.get("magic_string"),
                    "file_size": attrs.get("size"),
                    "stats": stats,
                },
            )

        except Exception as e:
            logger.error(f"VirusTotal hash search error: {e}")
            return IOCEnrichment(
                indicator=file_hash,
                indicator_type="hash",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["VirusTotal"],
                details={"error": str(e)},
            )

    def search(self, indicator: str) -> IOCEnrichment:
        """Auto-detect and search indicator."""
        ioc_type = self.infer_type(indicator)

        if ioc_type == "ip":
            return self.search_ip(indicator)
        elif ioc_type == "domain":
            return self.search_domain(indicator)
        elif ioc_type == "hash":
            return self.search_hash(indicator)

        return IOCEnrichment(
            indicator=indicator,
            indicator_type=ioc_type,
            reputation=ReputationLevel.UNKNOWN,
            score=0,
            sources=["VirusTotal"],
            details={"error": "Unknown indicator type"},
        )


class AbuseIPDBProvider:
    """AbuseIPDB API provider."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_key = config.get("api_key", "")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.session = None

        if self.api_key:
            self._connect()

    def _connect(self):
        """Initialize AbuseIPDB session."""
        try:
            import requests

            self.session = requests.Session()
            self.session.headers.update(
                {"Key": self.api_key, "Accept": "application/json"}
            )

            logger.info("AbuseIPDB client initialized")

        except ImportError:
            logger.error("requests library not installed")

    def check_ip(self, ip: str, max_age_days: int = 30) -> IOCEnrichment:
        """Check IP reputation."""
        if not self.session:
            return IOCEnrichment(
                indicator=ip,
                indicator_type="ip",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["AbuseIPDB"],
                details={"error": "Not configured"},
            )

        try:
            params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}

            response = self.session.get(
                f"{self.base_url}/check", params=params, timeout=30
            )

            if response.status_code != 200:
                return IOCEnrichment(
                    indicator=ip,
                    indicator_type="ip",
                    reputation=ReputationLevel.UNKNOWN,
                    score=0,
                    sources=["AbuseIPDB"],
                    details={"error": f"HTTP {response.status_code}"},
                )

            data = response.json()
            ip_data = data.get("data", {})

            confidence = ip_data.get("abuseConfidenceScore", 0)
            reputation = (
                ReputationLevel.MALICIOUS
                if confidence > 50
                else ReputationLevel.SUSPICIOUS
                if confidence > 25
                else ReputationLevel.CLEAN
            )

            return IOCEnrichment(
                indicator=ip,
                indicator_type="ip",
                reputation=reputation,
                score=confidence,
                sources=["AbuseIPDB"],
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
            logger.error(f"AbuseIPDB check error: {e}")
            return IOCEnrichment(
                indicator=ip,
                indicator_type="ip",
                reputation=ReputationLevel.UNKNOWN,
                score=0,
                sources=["AbuseIPDB"],
                details={"error": str(e)},
            )


class EnrichmentPipeline:
    """Auto-enrichment pipeline orchestrator."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

        self.misp = None
        self.virustotal = None
        self.abuseipdb = None

        misp_config = config.get("misp", {})
        if (
            misp_config.get("enabled")
            and misp_config.get("url")
            and misp_config.get("api_key")
        ):
            self.misp = MISPProvider(misp_config)

        vt_config = config.get("virustotal", {})
        if vt_config.get("enabled") and vt_config.get("api_key"):
            self.virustotal = VirusTotalProvider(vt_config)

        abuse_config = config.get("abuseipdb", {})
        if abuse_config.get("enabled") and abuse_config.get("api_key"):
            self.abuseipdb = AbuseIPDBProvider(abuse_config)

        logger.info(
            f"Enrichment pipeline initialized: MISP={bool(self.misp)}, VT={bool(self.virustotal)}, AbuseIPDB={bool(self.abuseipdb)}"
        )

    def infer_type(self, indicator: str) -> str:
        """Infer indicator type."""
        import re

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
            return "ip"

        if "." in indicator and "/" not in indicator:
            return "domain"

        if len(indicator) in [32, 40, 64] and re.match(r"^[a-fA-F0-9]+$", indicator):
            return "hash"

        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"

        return "unknown"

    def enrich_indicator(
        self, indicator: str, indicator_type: str = None
    ) -> List[IOCEnrichment]:
        """Enrich a single indicator across all providers."""
        results = []

        if indicator_type is None:
            indicator_type = self.infer_type(indicator)

        if self.misp:
            result = self.misp.search_indicator(indicator, indicator_type)
            results.append(result)

        if self.virustotal and indicator_type in ["ip", "domain", "hash"]:
            result = self.virustotal.search(indicator)
            results.append(result)

        if self.abuseipdb and indicator_type == "ip":
            result = self.abuseipdb.check_ip(indicator)
            results.append(result)

        return results

    def get_aggregated_result(self, results: List[IOCEnrichment]) -> Dict[str, Any]:
        """Aggregate results from multiple providers."""
        if not results:
            return {
                "reputation": "unknown",
                "score": 0,
                "sources": [],
                "details": {},
            }

        malicious_count = sum(
            1 for r in results if r.reputation == ReputationLevel.MALICIOUS
        )
        suspicious_count = sum(
            1 for r in results if r.reputation == ReputationLevel.SUSPICIOUS
        )
        clean_count = sum(1 for r in results if r.reputation == ReputationLevel.CLEAN)

        if malicious_count > 0:
            reputation = "malicious"
        elif suspicious_count > 0:
            reputation = "suspicious"
        elif clean_count > 0:
            reputation = "clean"
        else:
            reputation = "unknown"

        scores = [r.score for r in results if r.score > 0]
        avg_score = sum(scores) / len(scores) if scores else 0

        return {
            "reputation": reputation,
            "score": int(avg_score),
            "sources": [r.sources[0] for r in results],
            "details": [r.details for r in results],
            "malicious_found": malicious_count > 0,
            "suspicious_found": suspicious_count > 0,
        }

    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich an alert with threat intelligence."""
        indicators = alert.get("indicators", [])

        if not indicators:
            import re

            text = f"{alert.get('title', '')} {alert.get('description', '')}"
            ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
            domain_matches = re.findall(
                r"\b[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\b", text
            )
            indicators = list(set(ip_matches + domain_matches))

        enrichment_results = []
        for ioc in indicators:
            results = self.enrich_indicator(ioc)
            if results:
                aggregated = self.get_aggregated_result(results)
                enrichment_results.append(
                    {
                        "indicator": ioc,
                        "type": self.infer_type(ioc),
                        **aggregated,
                    }
                )

        return {
            "alert": alert,
            "enrichment": enrichment_results,
            "enriched_at": datetime.utcnow().isoformat(),
        }


def main():
    """Test the enrichment pipeline."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Threat Intelligence Enrichment Pipeline"
    )
    parser.add_argument("--indicator", required=True, help="Indicator to enrich")
    parser.add_argument("--misp-url", help="MISP URL")
    parser.add_argument("--misp-key", help="MISP API key")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--abuse-key", help="AbuseIPDB API key")

    args = parser.parse_args()

    config = {
        "misp": {
            "enabled": bool(args.misp_url and args.misp_key),
            "url": args.misp_url or "",
            "api_key": args.misp_key or "",
        },
        "virustotal": {
            "enabled": bool(args.vt_key),
            "api_key": args.vt_key or "",
        },
        "abuseipdb": {
            "enabled": bool(args.abuse_key),
            "api_key": args.abuse_key or "",
        },
    }

    pipeline = EnrichmentPipeline(config)
    results = pipeline.enrich_indicator(args.indicator)

    print(f"\nEnrichment results for: {args.indicator}")
    print("=" * 50)

    for result in results:
        print(f"\nSource: {result.sources[0]}")
        print(f"  Reputation: {result.reputation.value}")
        print(f"  Score: {result.score}")
        print(f"  Details: {result.details}")


if __name__ == "__main__":
    main()
