"""
Flatten and normalize raw CloudTrail events into a consistent schema.
"""

from typing import Optional


def normalize(event: dict) -> dict:
    """Return a flat, normalized representation of a CloudTrail event."""
    user_identity = event.get("userIdentity", {})
    return {
        # Core identity
        "actor_type": user_identity.get("type", "Unknown"),
        "actor_arn": user_identity.get("arn", ""),
        "actor_account": user_identity.get("accountId", ""),
        "actor_username": _extract_username(user_identity),
        "assumed_role": _extract_assumed_role(user_identity),

        # Event metadata
        "event_name": event.get("eventName", ""),
        "event_source": event.get("eventSource", ""),
        "event_time": event.get("eventTime", ""),
        "aws_region": event.get("awsRegion", ""),
        "source_ip": event.get("sourceIPAddress", ""),
        "user_agent": event.get("userAgent", ""),
        "request_id": event.get("requestID", ""),

        # Outcome
        "error_code": event.get("errorCode", ""),
        "error_message": event.get("errorMessage", ""),
        "read_only": event.get("readOnly", False),

        # Resources
        "resources": _extract_resources(event),
        "request_parameters": event.get("requestParameters") or {},
        "response_elements": event.get("responseElements") or {},

        # Raw original for forensics
        "_raw": event,
    }


def _extract_username(user_identity: dict) -> str:
    id_type = user_identity.get("type", "")
    if id_type == "IAMUser":
        return user_identity.get("userName", "")
    if id_type == "Root":
        return "root"
    if id_type == "AssumedRole":
        session = user_identity.get("sessionContext", {})
        session_id = session.get("sessionIssuer", {})
        return session_id.get("userName", "")
    if id_type in ("FederatedUser", "WebIdentityUser"):
        return user_identity.get("principalId", "").split(":")[-1]
    return user_identity.get("principalId", "unknown")


def _extract_assumed_role(user_identity: dict) -> Optional[str]:
    if user_identity.get("type") == "AssumedRole":
        return user_identity.get("arn", "").split("/")[-2] if "/" in user_identity.get("arn", "") else None
    return None


def _extract_resources(event: dict) -> list:
    resources = []
    for r in event.get("resources", []) or []:
        resources.append({
            "arn": r.get("ARN", ""),
            "type": r.get("type", ""),
            "account": r.get("accountId", ""),
        })
    return resources
