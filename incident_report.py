
from datetime import datetime


REQUIRED_FIELDS = [
    "timestamp",
    "source_ip",
    "username",
    "rule_triggered",
    "severity",
    "evidence",
]

ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def build_incident_report(alert):
    """Validate an alert and prepare its incident report."""

    if not isinstance(alert, dict):
        raise ValueError("Incident data must be a dictionary.")

    missing_fields = [
        field
        for field in REQUIRED_FIELDS
        if not isinstance(alert.get(field), str)
        or not alert[field].strip()
    ]

    if missing_fields:
        raise ValueError(
            f"Missing or empty required fields: {', '.join(missing_fields)}"
        )

    # Normalize values without modifying the original alert.
    incident_id = str(alert.get("incident_id") or "INC-001").strip()
    timestamp = alert["timestamp"].strip()
    source_ip = alert["source_ip"].strip()
    username = alert["username"].strip()
    rule_triggered = alert["rule_triggered"].strip()
    severity = alert["severity"].strip().upper()
    evidence = alert["evidence"].strip()

    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(
            "Invalid severity. Use LOW, MEDIUM, HIGH, or CRITICAL."
        )

    summary = (
        f"{severity} incident involving user {username} "
        f"from source IP {source_ip}. "
        f"Triggered rule: {rule_triggered}."
    )

    recommended_actions = [
        "Review the surrounding authentication events.",
        "Verify whether the successful login was legitimate.",
        "Check for related activity involving the same source IP.",
        "Preserve relevant logs for further investigation.",
    ]

    return {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "rule_triggered": rule_triggered,
        "severity": severity,
        "evidence": evidence,
        "summary": summary,
        "recommended_actions": recommended_actions,
        "report_generated_at": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
    }
