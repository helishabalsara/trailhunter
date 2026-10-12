"""
Rule evaluation engine. Loads YAML detection rules and evaluates them
against normalized CloudTrail events.
"""

import os
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional

import yaml

logger = logging.getLogger(__name__)

OPERATORS = {
    "equals": lambda a, b: str(a).lower() == str(b).lower(),
    "not_equals": lambda a, b: str(a).lower() != str(b).lower(),
    "contains": lambda a, b: str(b).lower() in str(a).lower(),
    "not_contains": lambda a, b: str(b).lower() not in str(a).lower(),
    "starts_with": lambda a, b: str(a).lower().startswith(str(b).lower()),
    "in": lambda a, b: str(a).lower() in [x.lower() for x in (b if isinstance(b, list) else [b])],
    "not_in": lambda a, b: str(a).lower() not in [x.lower() for x in (b if isinstance(b, list) else [b])],
    "is_empty": lambda a, _: not a,
    "is_not_empty": lambda a, _: bool(a),
}


class DetectionEngine:
    def __init__(self, rules_dir: str):
        self.rules = self._load_rules(rules_dir)
        logger.info(f"Loaded {len(self.rules)} detection rules.")

    def _load_rules(self, rules_dir: str) -> List[dict]:
        rules = []
        if not os.path.isdir(rules_dir):
            logger.warning(f"Rules directory not found: {rules_dir}")
            return rules
        for fname in os.listdir(rules_dir):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                path = os.path.join(rules_dir, fname)
                with open(path, "r") as fh:
                    data = yaml.safe_load(fh)
                if isinstance(data, list):
                    rules.extend(data)
                elif isinstance(data, dict):
                    rules.append(data)
        return rules

    def evaluate(self, event: dict) -> List[dict]:
        """Return a list of alert dicts for every rule that fires on this event."""
        alerts = []
        for rule in self.rules:
            if self._rule_matches(rule, event):
                alert = self._build_alert(rule, event)
                alerts.append(alert)
        return alerts

    def _rule_matches(self, rule: dict, event: dict) -> bool:
        condition = rule.get("condition")
        if not condition:
            return False
        logic = rule.get("logic", "AND").upper()
        if isinstance(condition, list):
            results = [self._eval_condition(c, event) for c in condition]
            return all(results) if logic == "AND" else any(results)
        return self._eval_condition(condition, event)

    def _eval_condition(self, condition: dict, event: dict) -> bool:
        field = condition.get("field", "")
        operator = condition.get("operator", "equals")
        value = condition.get("value", "")
        actual = self._get_field(event, field)
        fn = OPERATORS.get(operator)
        if fn is None:
            logger.warning(f"Unknown operator: {operator}")
            return False
        try:
            return fn(actual, value)
        except Exception:
            return False

    def _get_field(self, event: dict, field: str):
        """Support dot-notation field access e.g. 'userIdentity.type'."""
        parts = field.split(".")
        val = event
        for part in parts:
            if isinstance(val, dict):
                val = val.get(part, "")
            else:
                return ""
        return val if val is not None else ""

    def _build_alert(self, rule: dict, event: dict) -> dict:
        return {
            "alert_id": str(uuid.uuid4()),
            "rule_id": rule.get("id", "unknown"),
            "rule_name": rule.get("name", "Unnamed Rule"),
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "medium"),
            "mitre_technique": rule.get("mitre", ""),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "event_time": event.get("event_time", ""),
            "actor": event.get("actor_username") or event.get("actor_arn", ""),
            "actor_type": event.get("actor_type", ""),
            "source_ip": event.get("source_ip", ""),
            "event_name": event.get("event_name", ""),
            "event_source": event.get("event_source", ""),
            "aws_region": event.get("aws_region", ""),
            "error_code": event.get("error_code", ""),
            "raw_event": event.get("_raw", {}),
        }
