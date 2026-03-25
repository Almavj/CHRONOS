"""
MITRE ATT&CK Mapping for CHRONOS
Maps detection rules to MITRE ATT&CK techniques and tactics
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Tactic(Enum):
    """MITRE ATT&CK Tactics."""

    RECON = "reconnaissance"
    RESOURCE_DEV = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIV_ESC = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CRED_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class Technique:
    """MITRE ATT&CK Technique."""

    id: str
    name: str
    tactic: str
    description: str = ""
    detection_methods: List[str] = field(default_factory=list)


@dataclass
class Coverage:
    """Coverage information for a technique."""

    technique_id: str
    technique_name: str
    tactic: str
    rules_count: int = 0
    detection_status: str = "detected"
    gaps: List[str] = field(default_factory=list)


MITRE_TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


TECHNIQUES = {
    "T1566": Technique("T1566", "Phishing", "initial_access", "Phishing campaigns"),
    "T1566.001": Technique("T1566.001", "Spearphishing Attachment", "initial_access"),
    "T1566.002": Technique("T1566.002", "Spearphishing Link", "initial_access"),
    "T1059": Technique("T1059", "Command and Scripting Interpreter", "execution"),
    "T1059.001": Technique("T1059.001", "PowerShell", "execution"),
    "T1059.003": Technique("T1059.003", "Windows Command Shell", "execution"),
    "T1059.004": Technique("T1059.004", "Unix Shell", "execution"),
    "T1204": Technique("T1204", "User Execution", "execution"),
    "T1204.001": Technique("T1204.001", "Malicious Link", "execution"),
    "T1204.002": Technique("T1204.002", "Malicious File", "execution"),
    "T1547": Technique("T1547", "Boot or Logon Autostart Execution", "persistence"),
    "T1547.001": Technique("T1547.001", "Registry Run Keys", "persistence"),
    "T1547.002": Technique("T1547.002", "Startup Folder", "persistence"),
    "T1136": Technique("T1136", "Create Account", "persistence"),
    "T1136.001": Technique("T1136.001", "Local Account", "persistence"),
    "T1136.002": Technique("T1136.002", "Domain Account", "persistence"),
    "T1053": Technique("T1053", "Scheduled Task/Job", "persistence"),
    "T1053.005": Technique("T1053.005", "Scheduled Task", "persistence"),
    "T1543": Technique("T1543", "Create or Modify System Process", "persistence"),
    "T1543.002": Technique("T1543.002", "Windows Service", "persistence"),
    "T1078": Technique("T1078", "Valid Accounts", "persistence"),
    "T1078.001": Technique("T1078.001", "Default Accounts", "persistence"),
    "T1078.002": Technique("T1078.002", "Domain Accounts", "persistence"),
    "T1078.003": Technique("T1078.003", "Local Accounts", "persistence"),
    "T1055": Technique("T1055", "Process Injection", "privilege_escalation"),
    "T1055.001": Technique(
        "T1055.001", "Dynamic-link Library Injection", "privilege_escalation"
    ),
    "T1548": Technique(
        "T1548", "Abuse Elevation Control Mechanism", "privilege_escalation"
    ),
    "T1548.002": Technique(
        "T1548.002", "Bypass User Account Control", "privilege_escalation"
    ),
    "T1218": Technique("T1218", "Signed Binary Proxy Execution", "defense_evasion"),
    "T1218.004": Technique("T1218.004", "MShta", "defense_evasion"),
    "T1218.005": Technique("T1218.005", "Msiexec", "defense_evasion"),
    "T1027": Technique("T1027", "Obfuscated Files or Information", "defense_evasion"),
    "T1027.001": Technique("T1027.001", "Binary Padding", "defense_evasion"),
    "T1562": Technique("T1562", "Impair Defenses", "defense_evasion"),
    "T1562.001": Technique("T1562.001", "Disable or Modify Tools", "defense_evasion"),
    "T1562.002": Technique(
        "T1562.002", "Disable Windows Event Logging", "defense_evasion"
    ),
    "T1574": Technique("T1574", "Hijack Execution Flow", "defense_evasion"),
    "T1574.001": Technique(
        "T1574.001", "DLL Search Order Hijacking", "defense_evasion"
    ),
    "T1003": Technique("T1003", "OS Credential Dumping", "credential_access"),
    "T1003.001": Technique("T1003.001", "LSASS Memory", "credential_access"),
    "T1003.002": Technique(
        "T1003.002", "Security Account Manager", "credential_access"
    ),
    "T1003.003": Technique("T1003.003", "NTDS", "credential_access"),
    "T1110": Technique("T1110", "Brute Force", "credential_access"),
    "T1110.001": Technique("T1110.001", "Password Guessing", "credential_access"),
    "T1110.002": Technique("T1110.002", "Password Cracking", "credential_access"),
    "T1110.003": Technique(
        "T1110.003", "Brute Force: Credentials", "credential_access"
    ),
    "T1555": Technique(
        "T1555", "Credentials from Password Stores", "credential_access"
    ),
    "T1555.003": Technique(
        "T1555.003", "Credentials from Web Browsers", "credential_access"
    ),
    "T1558": Technique("T1558", "Steal or Forge Kerberos Tickets", "credential_access"),
    "T1558.003": Technique("T1558.003", "Kerberoasting", "credential_access"),
    "T1087": Technique("T1087", "Account Discovery", "discovery"),
    "T1087.001": Technique("T1087.001", "Local Account", "discovery"),
    "T1087.002": Technique("T1087.002", "Domain Account", "discovery"),
    "T1082": Technique("T1082", "System Information Discovery", "discovery"),
    "T1083": Technique("T1083", "File and Directory Discovery", "discovery"),
    "T1086": Technique("T1086", "PowerShell Profile", "discovery"),
    "T1021": Technique("T1021", "Remote Services", "lateral_movement"),
    "T1021.001": Technique("T1021.001", "Remote Desktop Protocol", "lateral_movement"),
    "T1021.002": Technique("T1021.002", "SMB/Windows Admin Shares", "lateral_movement"),
    "T1021.004": Technique("T1021.004", "SSH", "lateral_movement"),
    "T1021.005": Technique("T1021.005", "VNC", "lateral_movement"),
    "T1210": Technique("T1210", "Exploitation of Remote Services", "lateral_movement"),
    "T1056": Technique("T1056", "Input Capture", "collection"),
    "T1056.001": Technique("T1056.001", "Keylogging", "collection"),
    "T1119": Technique("T1119", "Automated Collection", "collection"),
    "T1005": Technique("T1005", "Data from Local System", "collection"),
    "T1071": Technique("T1071", "Application Layer Protocol", "command_and_control"),
    "T1071.001": Technique("T1071.001", "Web Protocol", "command_and_control"),
    "T1071.004": Technique("T1071.004", "DNS", "command_and_control"),
    "T1105": Technique("T1105", "Ingress Tool Transfer", "command_and_control"),
    "T1105.001": Technique("T1105.001", "Ingress Tool Transfer", "command_and_control"),
    "T1573": Technique("T1573", "Encrypted Channel", "command_and_control"),
    "T1041": Technique("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    "T1048": Technique(
        "T1048", "Exfiltration Over Alternative Protocol", "exfiltration"
    ),
    "T1486": Technique("T1486", "Data Encrypted for Impact", "impact"),
    "T1489": Technique("T1489", "Service Stop", "impact"),
    "T1490": Technique("T1490", "Inhibit System Recovery", "impact"),
}


class MITREMappings:
    """MITRE ATT&CK mapping manager."""

    def __init__(self):
        self.coverage: Dict[str, Coverage] = {}
        self.detection_rules: Dict[str, List[str]] = {}

    def add_detection(self, technique_id: str, rule_id: str, rule_title: str) -> None:
        """Add a detection mapping."""
        if technique_id not in self.detection_rules:
            self.detection_rules[technique_id] = []

        if rule_id not in self.detection_rules[technique_id]:
            self.detection_rules[technique_id].append(rule_id)

            technique = TECHNIQUES.get(technique_id)
            if technique:
                self.coverage[technique_id] = Coverage(
                    technique_id=technique_id,
                    technique_name=technique.name,
                    tactic=technique.tactic,
                    rules_count=len(self.detection_rules[technique_id]),
                    detection_status="detected",
                )

    def get_coverage_report(self) -> Dict[str, Any]:
        """Generate comprehensive MITRE ATT&CK coverage report."""
        all_techniques = set(TECHNIQUES.keys())
        covered_techniques = set(self.coverage.keys())
        uncovered = all_techniques - covered_techniques

        coverage_by_tactic = {}
        for tech_id in covered_techniques:
            technique = TECHNIQUES.get(tech_id)
            if technique:
                tactic = technique.tactic
                if tactic not in coverage_by_tactic:
                    coverage_by_tactic[tactic] = {"techniques": [], "count": 0}
                coverage_by_tactic[tactic]["techniques"].append(tech_id)
                coverage_by_tactic[tactic]["count"] += 1

        return {
            "summary": {
                "total_techniques": len(all_techniques),
                "covered_techniques": len(covered_techniques),
                "coverage_percentage": round(
                    len(covered_techniques) / len(all_techniques) * 100, 2
                ),
                "total_rules": sum(
                    len(rules) for rules in self.detection_rules.values()
                ),
            },
            "covered_techniques": list(covered_techniques),
            "uncovered_techniques": list(uncovered),
            "coverage_by_tactic": coverage_by_tactic,
            "detection_rules": {
                tech_id: {"technique": TECHNIQUES.get(tech_id, {}).name, "rules": rules}
                for tech_id, rules in self.detection_rules.items()
            },
        }

    def get_coverage_by_tactic(self, tactic: str) -> Dict[str, Any]:
        """Get coverage information for a specific tactic."""
        techniques = [
            (tech_id, tech)
            for tech_id, tech in TECHNIQUES.items()
            if tech.tactic == tactic
        ]

        covered = []
        uncovered = []

        for tech_id, tech in techniques:
            if tech_id in self.coverage:
                covered.append({"id": tech_id, "name": tech.name, "status": "covered"})
            else:
                uncovered.append(
                    {"id": tech_id, "name": tech.name, "status": "not_covered"}
                )

        return {
            "tactic": tactic,
            "tactic_name": MITRE_TACTICS.get(tactic, tactic),
            "total_techniques": len(techniques),
            "covered": len(covered),
            "uncovered": len(uncovered),
            "coverage_percentage": round(len(covered) / len(techniques) * 100, 2)
            if techniques
            else 0,
            "covered_techniques": covered,
            "uncovered_techniques": uncovered,
        }

    def get_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific technique."""
        technique = TECHNIQUES.get(technique_id)
        if not technique:
            return None

        rules = self.detection_rules.get(technique_id, [])

        return {
            "id": technique_id,
            "name": technique.name,
            "tactic": technique.tactic,
            "tactic_name": MITRE_TACTICS.get(technique.tactic, technique.tactic),
            "description": technique.description,
            "detection_rules": rules,
            "coverage_status": "covered" if rules else "not_covered",
            "gap_analysis": self._analyze_gaps(technique_id) if not rules else [],
        }

    def _analyze_gaps(self, technique_id: str) -> List[str]:
        """Analyze detection gaps for a technique."""
        gaps = []

        technique = TECHNIQUES.get(technique_id)
        if not technique:
            return gaps

        gaps.append(f"No detection rules mapped to {technique_id}")
        gaps.append(f"Consider adding behavioral detection for {technique.name}")

        if technique.tactic == "credential_access":
            gaps.append("Add monitoring for credential dumping tools")
            gaps.append("Implement PowerShell logging")

        return gaps
