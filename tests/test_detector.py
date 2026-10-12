import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from trailhunter.normalizer import normalize
from trailhunter.detector import DetectionEngine

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "trailhunter", "rules")


def make_event(event_name, actor_type="IAMUser", username="testuser", source_ip="1.2.3.4"):
    return {
        "userIdentity": {"type": actor_type, "userName": username, "arn": f"arn:aws:iam::123456789012:user/{username}"},
        "eventTime": "2024-01-01T00:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": source_ip,
        "userAgent": "test-agent",
    }


def test_root_usage_fires():
    engine = DetectionEngine(RULES_DIR)
    event = normalize(make_event("ConsoleLogin", actor_type="Root"))
    alerts = engine.evaluate(event)
    rule_ids = [a["rule_id"] for a in alerts]
    assert "TH-001" in rule_ids, "Root account rule should fire"


def test_create_user_fires():
    engine = DetectionEngine(RULES_DIR)
    event = normalize(make_event("CreateUser"))
    alerts = engine.evaluate(event)
    rule_ids = [a["rule_id"] for a in alerts]
    assert "TH-005" in rule_ids


def test_stop_logging_fires():
    engine = DetectionEngine(RULES_DIR)
    event = normalize(make_event("StopLogging", source_ip="198.51.100.10"))
    alerts = engine.evaluate(event)
    rule_ids = [a["rule_id"] for a in alerts]
    assert "TH-007" in rule_ids, "StopLogging should be critical"


def test_normal_event_no_alert():
    engine = DetectionEngine(RULES_DIR)
    event = normalize(make_event("DescribeInstances"))
    alerts = engine.evaluate(event)
    assert len(alerts) == 0


if __name__ == "__main__":
    test_root_usage_fires()
    test_create_user_fires()
    test_stop_logging_fires()
    test_normal_event_no_alert()
    print("All tests passed.")
