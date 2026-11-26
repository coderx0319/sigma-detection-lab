"""Load and validate the Sigma rules in this repository."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml

__all__ = ["Rule", "load_rules", "validate_rule"]

REQUIRED_FIELDS = ("title", "id", "status", "description", "logsource", "detection", "level")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


@dataclass
class Rule:
    path: Path
    data: Dict[str, Any]
    errors: List[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return self.data.get("title", self.path.stem)

    @property
    def level(self) -> str:
        return self.data.get("level", "unknown")

    @property
    def platform(self) -> str:
        return self.path.parent.name

    @property
    def techniques(self) -> List[str]:
        """ATT&CK technique IDs pulled from the rule's tags."""
        tags = self.data.get("tags") or []
        return sorted(
            tag.split(".", 1)[1].upper()
            for tag in tags
            if isinstance(tag, str) and tag.lower().startswith("attack.t")
        )

    @property
    def is_valid(self) -> bool:
        return not self.errors


def validate_rule(data: Dict[str, Any]) -> List[str]:
    """Return a list of schema problems; empty means the rule is well-formed."""
    errors: List[str] = []

    if not isinstance(data, dict):
        return ["rule is not a YAML mapping"]

    for key in REQUIRED_FIELDS:
        if key not in data:
            errors.append(f"missing required field: {key}")

    level = data.get("level")
    if level is not None and level not in VALID_LEVELS:
        errors.append(f"invalid level {level!r} (expected one of {sorted(VALID_LEVELS)})")

    status = data.get("status")
    if status is not None and status not in VALID_STATUS:
        errors.append(f"invalid status {status!r}")

    logsource = data.get("logsource")
    if isinstance(logsource, dict):
        if not any(k in logsource for k in ("product", "service", "category")):
            errors.append("logsource needs at least one of product/service/category")
    elif logsource is not None:
        errors.append("logsource is not a mapping")

    detection = data.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("detection block has no condition")
        if len(detection) < 2:
            errors.append("detection block has no selections")
    elif detection is not None:
        errors.append("detection is not a mapping")

    tags = data.get("tags")
    if tags is not None and not isinstance(tags, list):
        errors.append("tags is not a list")

    return errors


def load_rules(rules_dir: Path) -> List[Rule]:
    """Load every .yml rule under `rules_dir`, newest path order, validated."""
    rules: List[Rule] = []

    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            rules.append(Rule(path=path, data={}, errors=[f"YAML parse error: {exc}"]))
            continue

        rules.append(Rule(path=path, data=data or {}, errors=validate_rule(data)))

    # A duplicate rule id silently breaks SIEM deployment, so check for it.
    seen: Dict[str, Path] = {}
    for rule in rules:
        rule_id = rule.data.get("id")
        if not rule_id:
            continue
        if rule_id in seen:
            rule.errors.append(f"duplicate rule id, also used by {seen[rule_id].name}")
        else:
            seen[rule_id] = rule.path

    return rules
