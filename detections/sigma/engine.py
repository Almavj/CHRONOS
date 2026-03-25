"""
Sigma Rules Engine for CHRONOS
Loads and executes Sigma detection rules
"""

import logging
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
import yaml

logger = logging.getLogger(__name__)


class SigmaRule:
    """Represents a Sigma detection rule."""

    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data.get("id", "")
        self.title = rule_data.get("title", "")
        self.description = rule_data.get("description", "")
        self.author = rule_data.get("author", "")
        self.date = rule_data.get("date", "")
        self.status = rule_data.get("status", "stable")
        self.level = rule_data.get("level", "medium")
        self.tags = rule_data.get("tags", [])
        self.mitre_tactics = []
        self.mitre_techniques = []

        for tag in self.tags:
            if "attack." in tag:
                parts = tag.replace("attack.", "").split(".")
                if len(parts) >= 1:
                    tactic = parts[0]
                    self.mitre_tactics.append(tactic)
                if len(parts) >= 2:
                    technique = ".".join(parts[:2])
                    self.mitre_techniques.append(technique)

        self.detection = rule_data.get("detection", {})
        self.condition = self.detection.get("condition", "")
        self.search = self.detection.get("search", {})
        self.falsepositives = rule_data.get("falsepositives", [])

    def match(self, event: Dict[str, Any]) -> bool:
        """Check if an event matches this rule."""
        try:
            return self._evaluate_condition(event)
        except Exception as e:
            logger.debug(f"Rule {self.id} evaluation error: {e}")
            return False

    def _evaluate_condition(self, event: Dict[str, Any]) -> bool:
        """Evaluate the detection condition against an event."""
        selections = self._evaluate_selections(event)

        if " AND " in self.condition:
            parts = self.condition.split(" AND ")
            return all(self._parse_condition(p.strip(), event) for p in parts)
        elif " OR " in self.condition:
            parts = self.condition.split(" OR ")
            return any(self._parse_condition(p.strip(), event) for p in parts)
        elif "NOT" in self.condition:
            return not selections.get(self.condition.replace("NOT ", "").strip(), False)

        return selections.get(self.condition.strip(), False)

    def _evaluate_selections(self, event: Dict[str, Any]) -> Dict[str, bool]:
        """Evaluate all selection conditions."""
        results = {}

        for key, value in self.search.items():
            if key == "condition":
                continue

            event_value = self._get_nested_value(event, key)
            results[key] = self._compare_values(event_value, value)

        return results

    def _get_nested_value(self, event: Dict[str, Any], key: str) -> Any:
        """Get value from event using dot notation."""
        keys = key.split(".")
        value = event
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, None)
            else:
                return None
        return value

    def _compare_values(self, event_value: Any, rule_value: Any) -> bool:
        """Compare event value against rule value."""
        if event_value is None:
            return False

        if isinstance(rule_value, str):
            if rule_value.startswith("*") and rule_value.endswith("*"):
                pattern = rule_value[1:-1]
                return pattern.lower() in str(event_value).lower()
            elif rule_value.endswith("*"):
                prefix = rule_value[:-1]
                return str(event_value).startswith(prefix)
            elif rule_value.startswith("*"):
                suffix = rule_value[1:]
                return str(event_value).endswith(suffix)
            elif rule_value.startswith("|"):
                return False
            else:
                return str(event_value).lower() == rule_value.lower()

        return event_value == rule_value

    def _parse_condition(self, condition: str, event: Dict[str, Any]) -> bool:
        """Parse a single condition part."""
        selections = self._evaluate_selections(event)

        if condition in selections:
            return selections[condition]

        if "|" in condition:
            pipe_idx = condition.index("|")
            selection = condition[:pipe_idx].strip()
            modifier = condition[pipe_idx + 1 :].strip()

            if selection in selections:
                if "contains" in modifier:
                    return True
                elif "startswith" in modifier:
                    return True
            return False

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "author": self.author,
            "level": self.level,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
        }


class SigmaEngine:
    """Sigma rules detection engine."""

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: List[SigmaRule] = []
        self.rules_by_id: Dict[str, SigmaRule] = {}
        self.rules_by_technique: Dict[str, List[SigmaRule]] = {}
        self.rules_by_tactic: Dict[str, List[SigmaRule]] = {}

        if rules_dir:
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str) -> None:
        """Load Sigma rules from directory."""
        rules_path = Path(rules_dir)

        if not rules_path.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return

        for rule_file in rules_path.glob("**/*.yml"):
            try:
                with open(rule_file, "r") as f:
                    rule_data = yaml.safe_load(f)
                    if rule_data:
                        rule = SigmaRule(rule_data)
                        self.rules.append(rule)
                        self.rules_by_id[rule.id] = rule

                        for technique in rule.mitre_techniques:
                            if technique not in self.rules_by_technique:
                                self.rules_by_technique[technique] = []
                            self.rules_by_technique[technique].append(rule)

                        for tactic in rule.mitre_tactics:
                            if tactic not in self.rules_by_tactic:
                                self.rules_by_tactic[tactic] = []
                            self.rules_by_tactic[tactic].append(rule)

                        logger.info(f"Loaded Sigma rule: {rule.title}")
            except Exception as e:
                logger.error(f"Error loading rule {rule_file}: {e}")

        logger.info(f"Loaded {len(self.rules)} Sigma rules")

    def detect(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run all rules against an event."""
        matches = []

        for rule in self.rules:
            if rule.match(event):
                matches.append(
                    {
                        "rule": rule.to_dict(),
                        "event": event,
                    }
                )

        return matches

    def get_rules_by_technique(self, technique: str) -> List[SigmaRule]:
        """Get rules for a specific MITRE technique."""
        return self.rules_by_technique.get(technique, [])

    def get_rules_by_tactic(self, tactic: str) -> List[SigmaRule]:
        """Get rules for a specific MITRE tactic."""
        return self.rules_by_tactic.get(tactic, [])

    def get_coverage_report(self) -> Dict[str, Any]:
        """Generate MITRE ATT&CK coverage report."""
        techniques = set()
        tactics = set()

        for rule in self.rules:
            techniques.update(rule.mitre_techniques)
            tactics.update(rule.mitre_tactics)

        return {
            "total_rules": len(self.rules),
            "techniques_covered": len(techniques),
            "tactics_covered": len(tactics),
            "techniques": sorted(list(techniques)),
            "tactics": sorted(list(tactics)),
        }
