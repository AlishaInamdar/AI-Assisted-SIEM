# AI-Assisted SIEM
# Payal - Detection Rules and Alert Correlation

from datetime import datetime, timedelta


# ---------------------------------------------------------
# RULE 1: Repeated Failed Logins
# ---------------------------------------------------------

def detect_failed_login_burst(logs):
    """
    Detect 5 or more failed login attempts
    from the same user and source IP within 5 minutes.
    """

    alerts = []

    failed_logs = []

    for log in logs:
        if log["event_type"] == "LOGIN" and log["status"] == "FAILED":

            log_time = datetime.strptime(
                log["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            failed_logs.append({
                "timestamp": log_time,
                "source_ip": log["source_ip"],
                "username": log["username"]
            })

    for first_event in failed_logs:

        window_end = first_event["timestamp"] + timedelta(minutes=5)

        related_events = [
            event for event in failed_logs
            if event["source_ip"] == first_event["source_ip"]
            and event["username"] == first_event["username"]
            and first_event["timestamp"]
            <= event["timestamp"]
            <= window_end
        ]

        if len(related_events) >= 5:

            alert = {
                "rule": "Repeated Failed Logins",
                "username": first_event["username"],
                "source_ip": first_event["source_ip"],
                "event_count": len(related_events),
                "severity": "HIGH",
                "timestamp": first_event["timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "reason": (
                    f"{len(related_events)} failed login attempts "
                    f"detected within 5 minutes"
                )
            }

            alerts.append(alert)

            break

    return alerts


# ---------------------------------------------------------
# RULE 2: Multiple Users From One Source IP
# ---------------------------------------------------------

def detect_multiple_users_from_ip(logs):
    """
    Detect failed login attempts against 5 or more
    different users from the same source IP within 10 minutes.
    """

    alerts = []

    failed_logs = []

    for log in logs:
        if log["event_type"] == "LOGIN" and log["status"] == "FAILED":

            log_time = datetime.strptime(
                log["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            failed_logs.append({
                "timestamp": log_time,
                "source_ip": log["source_ip"],
                "username": log["username"]
            })

    for first_event in failed_logs:

        window_end = first_event["timestamp"] + timedelta(minutes=10)

        related_events = [
            event for event in failed_logs
            if event["source_ip"] == first_event["source_ip"]
            and first_event["timestamp"]
            <= event["timestamp"]
            <= window_end
        ]

        unique_users = set(
            event["username"]
            for event in related_events
        )

        if len(unique_users) >= 5:

            alert = {
                "rule": "Multiple Users From One IP",
                "username": ", ".join(sorted(unique_users)),
                "source_ip": first_event["source_ip"],
                "event_count": len(related_events),
                "severity": "HIGH",
                "timestamp": first_event["timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "reason": (
                    f"Source IP {first_event['source_ip']} "
                    f"attempted failed logins against "
                    f"{len(unique_users)} different users within 10 minutes"
                )
            }

            alerts.append(alert)

            break

    return alerts


# ---------------------------------------------------------
# RULE 3: Successful Login After Failed Login Burst
# ---------------------------------------------------------

def detect_success_after_failed_burst(logs):
    """
    Detect a successful login shortly after
    5 or more failed login attempts for the same
    user and source IP.
    """

    alerts = []

    failed_logs = []

    for log in logs:

        if log["event_type"] == "LOGIN" and log["status"] == "FAILED":

            log_time = datetime.strptime(
                log["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            failed_logs.append({
                "timestamp": log_time,
                "source_ip": log["source_ip"],
                "username": log["username"]
            })

    for success_log in logs:

        if success_log["event_type"] == "LOGIN" and success_log["status"] == "SUCCESS":

            success_time = datetime.strptime(
                success_log["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            username = success_log["username"]
            source_ip = success_log["source_ip"]

            window_start = success_time - timedelta(minutes=5)

            related_failed = [
                event for event in failed_logs
                if event["username"] == username
                and event["source_ip"] == source_ip
                and window_start
                <= event["timestamp"]
                < success_time
            ]

            if len(related_failed) >= 5:

                alert = {
                    "rule": "Successful Login After Failed Burst",
                    "username": username,
                    "source_ip": source_ip,
                    "event_count": len(related_failed) + 1,
                    "severity": "HIGH",
                    "timestamp": success_log["timestamp"],
                    "reason": (
                        f"{len(related_failed)} failed login attempts "
                        f"were followed by a successful login within 5 minutes"
                    )
                }

                alerts.append(alert)

    return alerts


# ---------------------------------------------------------
# ALERT CORRELATION AND DEDUPLICATION
# ---------------------------------------------------------

def correlate_alerts(alerts):
    """
    Group related alerts using username and source IP.
    Remove duplicate alerts for the same rule, user and IP.
    """

    correlated = {}

    for alert in alerts:

        key = (
            alert["username"],
            alert["source_ip"]
        )

        if key not in correlated:

            correlated[key] = {
                "username": alert["username"],
                "source_ip": alert["source_ip"],
                "severity": alert["severity"],
                "rules": [],
                "event_count": 0,
                "timestamp": alert["timestamp"],
                "reasons": []
            }

        group = correlated[key]

        # Add rule only once
        if alert["rule"] not in group["rules"]:
            group["rules"].append(alert["rule"])

        # Add reason only once
        if alert["reason"] not in group["reasons"]:
            group["reasons"].append(alert["reason"])

        # Keep the highest severity
        severity_order = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3
        }

        if severity_order.get(alert["severity"], 0) > severity_order.get(
            group["severity"], 0
        ):
            group["severity"] = alert["severity"]

        group["event_count"] += alert["event_count"]

    return list(correlated.values())


# ---------------------------------------------------------
# RUN ALL DETECTION RULES
# ---------------------------------------------------------

def run_detection_rules(logs):
    """
    Run all detection rules and correlate the generated alerts.
    """

    alerts = []

    alerts.extend(
        detect_failed_login_burst(logs)
    )

    alerts.extend(
        detect_multiple_users_from_ip(logs)
    )

    alerts.extend(
        detect_success_after_failed_burst(logs)
    )

    correlated_alerts = correlate_alerts(alerts)

    return correlated_alerts
