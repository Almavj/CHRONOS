"""
Community Rules Sharing Module for CHRONOS
Allows users to share and import detection rules
"""

import logging
import json
import hashlib
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import uuid
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SharedRule:
    """Represents a shared detection rule."""

    id: str
    name: str
    description: str
    author: str
    author_contact: str
    created_at: str
    updated_at: str
    version: str
    category: str
    tags: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    rule_content: Dict[str, Any]
    signature: str
    downloads: int = 0
    rating: float = 0.0
    reviews: int = 0


class CommunityRulesManager:
    """Manages community-shared detection rules."""

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = (
            Path(storage_dir) if storage_dir else Path("detections/community")
        )
        self.rules_dir = self.storage_dir / "rules"
        self.rules_dir.mkdir(parents=True, exist_ok=True)

        self.shared_rules: Dict[str, SharedRule] = {}
        self.rules_by_category: Dict[str, List[str]] = {}
        self.rules_by_author: Dict[str, List[str]] = {}

        self._load_shared_rules()

    def _load_shared_rules(self) -> None:
        """Load shared rules from storage."""
        for rule_file in self.rules_dir.glob("*.json"):
            try:
                with open(rule_file, "r") as f:
                    rule_data = json.load(f)
                    rule = SharedRule(**rule_data)
                    self.shared_rules[rule.id] = rule

                    if rule.category not in self.rules_by_category:
                        self.rules_by_category[rule.category] = []
                    self.rules_by_category[rule.category].append(rule.id)

                    if rule.author not in self.rules_by_author:
                        self.rules_by_author[rule.author] = []
                    self.rules_by_author[rule.author].append(rule.id)

            except Exception as e:
                logger.error(f"Error loading shared rule {rule_file}: {e}")

        logger.info(f"Loaded {len(self.shared_rules)} shared rules")

    def share_rule(
        self,
        name: str,
        description: str,
        author: str,
        author_contact: str,
        category: str,
        tags: List[str],
        mitre_tactics: List[str],
        mitre_techniques: List[str],
        rule_content: Dict[str, Any],
    ) -> SharedRule:
        """Share a new detection rule with the community."""
        rule_id = str(uuid.uuid4())[:8]

        signature = self._generate_signature(rule_content)

        rule = SharedRule(
            id=rule_id,
            name=name,
            description=description,
            author=author,
            author_contact=author_contact,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            version="1.0.0",
            category=category,
            tags=tags,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            rule_content=rule_content,
            signature=signature,
        )

        self.shared_rules[rule.id] = rule

        if rule.category not in self.rules_by_category:
            self.rules_by_category[rule.category] = []
        self.rules_by_category[rule.category].append(rule.id)

        if rule.author not in self.rules_by_author:
            self.rules_by_author[rule.author] = []
        self.rules_by_author[rule.author].append(rule.id)

        self._save_rule(rule)

        logger.info(f"Shared rule: {name} (ID: {rule_id})")

        return rule

    def _generate_signature(self, rule_content: Dict[str, Any]) -> str:
        """Generate a signature for rule content."""
        content_str = json.dumps(rule_content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()[:16]

    def _save_rule(self, rule: SharedRule) -> None:
        """Save rule to storage."""
        rule_file = self.rules_dir / f"{rule.id}.json"

        with open(rule_file, "w") as f:
            json.dump(rule.__dict__, f, indent=2)

    def get_rule(self, rule_id: str) -> Optional[SharedRule]:
        """Get a specific rule by ID."""
        return self.shared_rules.get(rule_id)

    def get_rules_by_category(self, category: str) -> List[SharedRule]:
        """Get all rules in a category."""
        rule_ids = self.rules_by_category.get(category, [])
        return [self.shared_rules[rid] for rid in rule_ids if rid in self.shared_rules]

    def get_rules_by_author(self, author: str) -> List[SharedRule]:
        """Get all rules by an author."""
        rule_ids = self.rules_by_author.get(author, [])
        return [self.shared_rules[rid] for rid in rule_ids if rid in self.shared_rules]

    def search_rules(
        self,
        query: str = "",
        category: str = "",
        tags: List[str] = None,
        mitre_techniques: List[str] = None,
    ) -> List[SharedRule]:
        """Search for rules."""
        results = list(self.shared_rules.values())

        if query:
            query_lower = query.lower()
            results = [
                r
                for r in results
                if query_lower in r.name.lower() or query_lower in r.description.lower()
            ]

        if category:
            results = [r for r in results if r.category == category]

        if tags:
            results = [r for r in results if any(tag in r.tags for tag in tags)]

        if mitre_techniques:
            results = [
                r
                for r in results
                if any(tech in r.mitre_techniques for tech in mitre_techniques)
            ]

        return results

    def rate_rule(self, rule_id: str, rating: float) -> bool:
        """Rate a shared rule."""
        rule = self.shared_rules.get(rule_id)
        if not rule:
            return False

        new_rating = ((rule.rating * rule.reviews) + rating) / (rule.reviews + 1)
        rule.rating = round(new_rating, 2)
        rule.reviews += 1

        self._save_rule(rule)

        return True

    def increment_downloads(self, rule_id: str) -> bool:
        """Increment download count for a rule."""
        rule = self.shared_rules.get(rule_id)
        if not rule:
            return False

        rule.downloads += 1
        self._save_rule(rule)

        return True

    def export_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Export a rule for sharing."""
        rule = self.shared_rules.get(rule_id)
        if not rule:
            return None

        return {
            "name": rule.name,
            "description": rule.description,
            "author": rule.author,
            "version": rule.version,
            "category": rule.category,
            "tags": rule.tags,
            "mitre_tactics": rule.mitre_tactics,
            "mitre_techniques": rule.mitre_techniques,
            "rule": rule.rule_content,
            "signature": rule.signature,
        }

    def get_categories(self) -> List[str]:
        """Get all available categories."""
        return list(self.rules_by_category.keys())

    def get_stats(self) -> Dict[str, Any]:
        """Get community rules statistics."""
        categories = {}
        for cat, rule_ids in self.rules_by_category.items():
            categories[cat] = len(rule_ids)

        return {
            "total_rules": len(self.shared_rules),
            "total_categories": len(categories),
            "total_authors": len(self.rules_by_author),
            "categories": categories,
            "top_rated": sorted(
                [
                    (r.name, r.rating, r.id)
                    for r in self.shared_rules.values()
                    if r.reviews > 0
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
            "most_downloaded": sorted(
                [(r.name, r.downloads, r.id) for r in self.shared_rules.values()],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }

    def get_rule_as_sigma(self, rule_id: str) -> Optional[str]:
        """Export a rule in Sigma format."""
        rule = self.shared_rules.get(rule_id)
        if not rule:
            return None

        sigma_rule = f"""title: {rule.name}
id: {rule.id.replace("-", "")}
status: stable
author: {rule.author}
date: {rule.created_at[:10]}
level: medium
tags:
"""
        for tactic in rule.mitre_tactics:
            sigma_rule += f"  - attack.{tactic}\n"

        for technique in rule.mitre_techniques:
            sigma_rule += f"  - attack.{technique.replace('.', '.')}\n"

        sigma_rule += f"""description: {rule.description}
detection:
  selection:
"""

        if "selection" in rule.rule_content:
            for key, value in rule.rule_content["selection"].items():
                sigma_rule += f"    {key}: {value}\n"

        sigma_rule += "  condition: selection\n"

        return sigma_rule
