from __future__ import annotations

import csv
import io
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, send_file

BASE_DIR = Path(__file__).resolve().parent
PROCESSED_CSV = BASE_DIR / "processed_logs.csv"
INVALID_CSV = BASE_DIR / "invalid_logs.csv"
ALERTS_CSV = BASE_DIR / "security_alerts.csv"
SAMPLE_UPLOAD_CSV = BASE_DIR / "sample_logs.csv"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "event_time", "date", "datetime", "created_at"),
    "username": ("username", "user", "user_name", "account", "account_name", "user_id"),
    "source_ip": ("source_ip", "src_ip", "source", "src", "ip_address", "client_ip", "source address"),
    "destination_ip": ("destination_ip", "dest_ip", "destination", "dst_ip", "target_ip", "destination address"),
    "event_type": ("event_type", "event", "action", "activity", "type", "event_name", "description"),
    "status": ("status", "outcome", "result", "login_status", "disposition"),
    "severity": ("severity", "priority", "alert_severity", "risk_level"),
    "alert_status": ("alert_status", "status", "state", "workflow_status"),
    "alert_id": ("alert_id", "id", "alertid"),
    "alert_name": ("alert_name", "name", "title", "rule_name", "detection_name", "event_type"),
    "rule_id": ("rule_id", "rule", "rule_name", "detection_rule", "signature"),
    "event_count": ("event_count", "count", "matched_events", "occurrences"),
    "reason": ("reason", "description", "evidence", "message", "details", "alert_reason"),
    "incident_id": ("incident_id", "case_id", "correlation_id", "group_id"),
    "reject_reason": ("reject_reason", "rejection_reason", "validation_error", "error_reason", "reason"),
    "row_number": ("row_number", "row", "line_number", "record_number"),
}

RULE_CATALOG = [
    {
        "rule_id": "AUTH-001",
        "name": "Repeated failed logins",
        "condition": "5 or more failed login attempts for the same username and source IP within 5 minutes.",
        "priority": "High; Critical if a successful login follows the failure burst.",
    },
    {
        "rule_id": "AUTH-002",
        "name": "Multiple usernames targeted",
        "condition": "Failed or denied activity from one source IP against 5 or more distinct usernames within 10 minutes.",
        "priority": "High — review for possible account probing.",
    },
    {
        "rule_id": "BEHAVIOR-003",
        "name": "Suspicious event indicator",
        "condition": "Configured terms such as phishing, PowerShell, suspicious transfer, port scan or exploit appear in event fields.",
        "priority": "High or Critical according to the matched indicator.",
    },
    {
        "rule_id": "POLICY-004",
        "name": "Denied or unusual activity",
        "condition": "A record contains a blocked, denied, policy violation, unusual or anomalous indicator.",
        "priority": "Medium — validate context before escalation.",
    },
]


def _key(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _value(row: dict[str, Any], field: str, default: str = "") -> str:
    lowered = {_key(k): v for k, v in row.items()}
    for alias in FIELD_ALIASES.get(field, (field,)):
        val = lowered.get(_key(alias))
        if val is not None and str(val).strip():
            return str(val).strip()
    return default


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            return []
        return [dict(row) for row in reader]


def _parse_dt(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    candidates = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d-%m-%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    )
    for fmt in candidates:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None, microsecond=0)
    except ValueError:
        return None


def _normalize_log(row: dict[str, Any], row_index: int) -> tuple[dict[str, Any] | None, str | None]:
    source_ip = _value(row, "source_ip")
    timestamp_raw = _value(row, "timestamp")
    parsed = _parse_dt(timestamp_raw) if timestamp_raw else None
    if not source_ip:
        return None, "Missing required source_ip value."
    if timestamp_raw and parsed is None:
        return None, f"Invalid timestamp format: {timestamp_raw}"
    timestamp = parsed
    return {
        "row_number": row_index,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else timestamp_raw or "Unknown",
        "timestamp_display": timestamp.strftime("%H:%M:%S") if timestamp else "—",
        "timestamp_hour": timestamp.strftime("%Y-%m-%d %H:00") if timestamp else "Unknown time",
        "username": _value(row, "username", "Unknown"),
        "source_ip": source_ip,
        "destination_ip": _value(row, "destination_ip", "—"),
        "event_type": _value(row, "event_type", "Unspecified event"),
        "status": _value(row, "status", "Unknown"),
        "raw": dict(row),
    }, None


def _normalize_alert(row: dict[str, Any], index: int) -> dict[str, Any]:
    raw_timestamp = _value(row, "timestamp")
    parsed = _parse_dt(raw_timestamp)
    severity = _value(row, "severity", "Unknown").title()
    if severity not in {"Critical", "High", "Medium", "Low", "Informational", "Unknown"}:
        severity = "Unknown"
    event_count = _value(row, "event_count", "1")
    try:
        event_count = max(1, int(float(event_count)))
    except (ValueError, TypeError):
        event_count = 1
    return {
        "alert_id": _value(row, "alert_id", f"ALERT-{index:03d}"),
        "timestamp": parsed.strftime("%Y-%m-%d %H:%M:%S") if parsed else raw_timestamp or "—",
        "timestamp_display": parsed.strftime("%H:%M:%S") if parsed else raw_timestamp or "—",
        "alert_name": _value(row, "alert_name", "Alert record"),
        "severity": severity,
        "source_ip": _value(row, "source_ip", "—"),
        "destination_ip": _value(row, "destination_ip", "—"),
        "username": _value(row, "username", "—"),
        "rule_id": _value(row, "rule_id", "Not provided"),
        "status": _value(row, "alert_status", "Unassigned"),
        "event_count": event_count,
        "reason": _value(row, "reason", "No reason/evidence column was provided."),
        "incident_id": _value(row, "incident_id", ""),
        "raw": dict(row),
    }


def _normalize_rejected(row: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "row_number": _value(row, "row_number", str(index + 2)),
        "timestamp": _value(row, "timestamp", "—"),
        "username": _value(row, "username", "—"),
        "source_ip": _value(row, "source_ip", "—") or "(missing)",
        "event_type": _value(row, "event_type", "—"),
        "reject_reason": _value(row, "reject_reason", "No reject_reason supplied."),
        "raw": dict(row),
    }


def _group_incidents(alerts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, alert in enumerate(alerts, start=1):
        incident_id = alert.get("incident_id")
        if incident_id:
            key = f"ID:{incident_id}"
        elif alert.get("source_ip") and alert["source_ip"] != "—":
            key = f"SOURCE:{alert['source_ip']}"
        else:
            key = f"SINGLE:{index}"
        buckets[key].append(alert)

    incidents: list[dict[str, Any]] = []
    correlated: list[dict[str, Any]] = []
    for key, items in buckets.items():
        if key.startswith("ID:"):
            display_id = key[3:]
            correlation_method = "incident_id supplied in security_alerts.csv"
        elif key.startswith("SOURCE:"):
            display_id = f"SRC-{items[0]['source_ip']}"
            correlation_method = "shared source IP; review correlation manually"
        else:
            display_id = "Not linked"
            correlation_method = "no shared incident identifier or source IP"
        severities = [a["severity"] for a in items]
        severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "Unknown": 5}
        highest = min(severities, key=lambda s: severity_rank.get(s, 5)) if severities else "Unknown"
        entry = {
            "incident_id": display_id,
            "alert_count": len(items),
            "highest_severity": highest,
            "source_ip": items[0].get("source_ip", "—"),
            "alerts": ", ".join(item["alert_id"] for item in items),
            "title": items[0].get("alert_name", "Related alerts"),
            "correlation_method": correlation_method,
        }
        if key.startswith("ID:") or (key.startswith("SOURCE:") and len(items) > 1):
            correlated.append(entry)
        if key.startswith("ID:"):
            incidents.append(entry)
    return incidents, correlated


def _payload(
    log_rows: list[dict[str, Any]],
    rejected_rows: list[dict[str, Any]],
    alert_rows: list[dict[str, Any]],
    *,
    data_mode: str,
    source_files: dict[str, int] | None = None,
) -> dict[str, Any]:
    alerts = [_normalize_alert(row, i + 1) for i, row in enumerate(alert_rows)]
    rejected = [_normalize_rejected(row, i) for i, row in enumerate(rejected_rows)]
    source_ips = sorted({str(_value(row, "source_ip")).strip() for row in log_rows if _value(row, "source_ip").strip()})
    severity_order = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
    severity_counter = Counter(alert["severity"] for alert in alerts)
    severity_counts = [{"label": label, "value": severity_counter.get(label, 0)} for label in severity_order if severity_counter.get(label, 0) or label != "Unknown"]

    hourly: Counter[str] = Counter()
    event_types: Counter[str] = Counter()
    suspicious_keywords = ("fail", "denied", "phishing", "suspicious", "unusual", "exploit", "blocked", "anomalous", "brute force", "powershell", "port scan")
    suspicious_events = 0
    normalized_logs: list[dict[str, Any]] = []
    for i, row in enumerate(log_rows, start=2):
        normalized, _ = _normalize_log(row, i)
        if normalized:
            normalized_logs.append(normalized)
            if normalized["timestamp_hour"] != "Unknown time":
                hourly[normalized["timestamp_hour"]] += 1
            event_types[normalized["event_type"]] += 1
            text = f"{normalized['event_type']} {normalized['status']}".lower()
            if any(term in text for term in suspicious_keywords):
                suspicious_events += 1

    if hourly:
        hours = sorted(hourly.keys())[-12:]
        trend_labels = [h[5:] for h in hours]
        trend_values = [hourly[h] for h in hours]
    else:
        trend_labels, trend_values = [], []

    incidents, correlated_groups = _group_incidents(alerts)
    alert_count = len(alert_rows)
    total_records = len(log_rows) + len(rejected_rows)
    return {
        "summary": {
            "total_records": total_records,
            "valid_records": len(log_rows),
            "rejected_records": len(rejected_rows),
            "unique_source_ips": len(source_ips),
            "alerts": alert_count,
            "suspicious_events": suspicious_events,
            "incident_groups": len(incidents),
            "correlated_groups": len(correlated_groups),
        },
        "source_ips": source_ips,
        "severity": {
            "labels": [item["label"] for item in severity_counts],
            "values": [item["value"] for item in severity_counts],
            "items": severity_counts,
        },
        "trend": {"labels": trend_labels, "values": trend_values},
        "event_types": [{"label": name, "value": count} for name, count in event_types.most_common(8)],
        "alerts": alerts,
        "rejected_records": rejected,
        "incidents": incidents,
        "correlated_groups": correlated_groups,
        "rules": RULE_CATALOG,
        "data_mode": data_mode,
        "source_files": source_files or {},
        "data_note": (
            "Dashboard values are read from local CSV files. No live network, endpoint, firewall, DNS, or external threat-intelligence feed is connected."
        ),
    }


def load_demo_data() -> dict[str, Any]:
    missing = [path.name for path in (PROCESSED_CSV, INVALID_CSV, ALERTS_CSV) if not path.exists()]
    if missing:
        raise RuntimeError("Required CSV file(s) are missing: " + ", ".join(missing))
    processed = _read_csv(PROCESSED_CSV)
    invalid = _read_csv(INVALID_CSV)
    alerts = _read_csv(ALERTS_CSV)
    return _payload(
        processed,
        invalid,
        alerts,
        data_mode="project-csv",
        source_files={
            "processed_logs.csv": len(processed),
            "invalid_logs.csv": len(invalid),
            "security_alerts.csv": len(alerts),
        },
    )


def _severity_for_text(event_type: str, status: str) -> tuple[str, str] | None:
    text = f"{event_type} {status}".lower()
    if any(word in text for word in ("credential stuffing", "exploit", "privilege escalation", "command injection")):
        return "Critical", "Matched a configured high-risk event indicator; analyst review is required."
    if any(word in text for word in ("phishing", "powershell", "suspicious transfer", "data exfiltration", "port scan", "brute force", "failed login")):
        return "High", "Matched a configured suspicious-event indicator; validate the surrounding activity."
    if any(word in text for word in ("blocked", "denied", "policy violation", "unusual", "anomalous")):
        return "Medium", "A blocked, denied or unusual event was recorded; review the context."
    return None


def _generate_alerts_for_uploaded_logs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=2):
        normalized, error = _normalize_log(row, index)
        if not error and normalized:
            events.append(normalized)

    generated: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(event: dict[str, Any], severity: str, name: str, rule_id: str, count: int, reason: str) -> None:
        dedupe = (name.lower(), event["source_ip"], event["username"])
        if dedupe in seen:
            return
        seen.add(dedupe)
        generated.append({
            "alert_id": f"UPLOAD-{len(generated) + 1:03d}",
            "timestamp": event["timestamp"],
            "alert_name": name,
            "severity": severity,
            "source_ip": event["source_ip"],
            "destination_ip": event["destination_ip"],
            "username": event["username"],
            "rule_id": rule_id,
            "status": "New",
            "event_count": str(count),
            "reason": reason,
            "incident_id": "",
        })

    # AUTH-001: five or more failed login attempts for a single user/source within five minutes.
    failed_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        event_text = f"{event['event_type']} {event['status']}".lower()
        is_login = any(token in event_text for token in ("login", "logon", "authentication"))
        is_failed = any(token in event_text for token in ("fail", "denied", "invalid password", "unsuccessful"))
        if is_login and is_failed and _parse_dt(event["timestamp"]):
            failed_by_pair[(event["username"], event["source_ip"])].append(event)

    for (username, source_ip), failures in failed_by_pair.items():
        failures.sort(key=lambda item: _parse_dt(item["timestamp"]) or datetime.min)
        for start_index, first in enumerate(failures):
            first_dt = _parse_dt(first["timestamp"])
            if not first_dt:
                continue
            burst = [item for item in failures[start_index:] if (_parse_dt(item["timestamp"]) or datetime.min) <= first_dt + timedelta(minutes=5)]
            if len(burst) >= 5:
                successful_after = any(
                    item["username"] == username and item["source_ip"] == source_ip
                    and (item_dt := _parse_dt(item["timestamp"])) is not None
                    and first_dt < item_dt <= first_dt + timedelta(minutes=10)
                    and any(token in f"{item['event_type']} {item['status']}".lower() for token in ("success", "successful", "authenticated"))
                    for item in events
                )
                severity = "Critical" if successful_after else "High"
                reason = f"{len(burst)} failed login attempts for {username} from {source_ip} within five minutes."
                if successful_after:
                    reason += " A successful login followed the burst; investigate, but this alone does not prove compromise."
                add(first, severity, "Repeated Failed Login Attempts", "AUTH-001", len(burst), reason)
                break

    # AUTH-002: five or more different accounts showing failed/denied activity from one source in ten minutes.
    failed_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        text = f"{event['event_type']} {event['status']}".lower()
        is_failed = any(token in text for token in ("fail", "denied", "invalid", "unsuccessful"))
        if is_failed and _parse_dt(event["timestamp"]):
            failed_by_ip[event["source_ip"]].append(event)
    for source_ip, source_events in failed_by_ip.items():
        source_events.sort(key=lambda item: _parse_dt(item["timestamp"]) or datetime.min)
        for start_index, first in enumerate(source_events):
            first_dt = _parse_dt(first["timestamp"])
            if not first_dt:
                continue
            burst = [item for item in source_events[start_index:] if (_parse_dt(item["timestamp"]) or datetime.min) <= first_dt + timedelta(minutes=10)]
            users = {item["username"] for item in burst}
            if len(users) >= 5:
                add(first, "High", "Multiple Usernames Targeted", "AUTH-002", len(burst), f"Failed or denied activity affected {len(users)} distinct usernames from {source_ip} within ten minutes.")
                break

    # BEHAVIOR-003 and POLICY-004: event-level indicators, excluding failed logins already handled above.
    for event in events:
        event_text = f"{event['event_type']} {event['status']}".lower()
        is_login = any(token in event_text for token in ("login", "logon", "authentication"))
        is_failed = any(token in event_text for token in ("fail", "denied", "invalid password", "unsuccessful"))
        if is_login and is_failed:
            continue
        if any(token in event_text for token in ("credential stuffing", "exploit", "privilege escalation", "command injection")):
            add(event, "Critical", event["event_type"].title(), "BEHAVIOR-003", 1, "A high-risk event indicator was present; investigate the event context.")
        elif any(token in event_text for token in ("phishing", "powershell", "suspicious transfer", "data exfiltration", "port scan", "brute force")):
            add(event, "High", event["event_type"].title(), "BEHAVIOR-003", 1, "A suspicious-event indicator was present; validate the surrounding activity.")
        elif any(token in event_text for token in ("blocked", "denied", "policy violation", "unusual", "anomalous")):
            add(event, "Medium", event["event_type"].title(), "POLICY-004", 1, "A blocked, denied or unusual event was recorded; review the context.")

    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    generated.sort(key=lambda alert: (severity_rank.get(alert["severity"], 9), alert["timestamp"]))
    return generated


def analyze_uploaded_content(content: str) -> dict[str, Any]:
    reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")))
    if not reader.fieldnames:
        raise ValueError("The uploaded CSV must include a header row.")
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for index, row in enumerate(reader, start=2):
        if not row or not any(str(value or "").strip() for value in row.values()):
            continue
        normalized, error = _normalize_log(row, index)
        if error:
            rejected.append({
                "row_number": str(index),
                **row,
                "reject_reason": error,
            })
        else:
            accepted.append(dict(row))
    if not accepted and not rejected:
        raise ValueError("The uploaded CSV has no event rows.")

    generated_alerts = _generate_alerts_for_uploaded_logs(accepted)
    return _payload(
        accepted,
        rejected,
        generated_alerts,
        data_mode="uploaded-csv",
        source_files={"uploaded CSV": len(accepted) + len(rejected)},
    )


@app.get("/")
def index():
    try:
        dashboard = load_demo_data()
        load_error = None
    except Exception as exc:
        dashboard = None
        load_error = str(exc)
    return render_template("index.html", dashboard=dashboard, load_error=load_error)


@app.post("/api/analyze")
def analyze_upload():
    upload = request.files.get("log_file")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose a CSV file before clicking Analyze CSV."}), 400
    if not upload.filename.lower().endswith(".csv"):
        return jsonify({"error": "Please upload a .csv file."}), 400
    try:
        content = upload.stream.read().decode("utf-8-sig")
        result = analyze_uploaded_content(content)
    except UnicodeDecodeError:
        return jsonify({"error": "The CSV must be saved as UTF-8 text."}), 400
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Could not analyze uploaded CSV")
        return jsonify({"error": "Could not analyze this file. Check the CSV headers and try again."}), 400
    return jsonify(result)


@app.get("/api/demo")
def demo_data():
    try:
        return jsonify(load_demo_data())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.get("/health")
def health():
    return jsonify({"status": "ok", "mode": "local CSV prototype"})




# ---------------- Incident reporting integration ----------------
import ast
from io import BytesIO, StringIO
from collections import Counter
from flask import abort, make_response, send_file, url_for
from incident_report import build_incident_report

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _reporting_alerts():
    """Adapt both dashboard CSV alerts and correlated detection-rule alerts."""
    rows = _read_csv(ALERTS_CSV)
    adapted = []
    for i, row in enumerate(rows, start=1):
        # Dashboard schema: alert_id, alert_name, rule_id, reason, incident_id.
        # Rule-engine schema: username, source_ip, severity, rules, reasons, event_count.
        raw_severity = _value(row, "severity", "MEDIUM").strip().upper()
        severity_map = {"INFORMATIONAL": "LOW", "INFO": "LOW", "WARNING": "MEDIUM"}
        severity = severity_map.get(raw_severity, raw_severity)
        if severity.title() in {"Critical", "High", "Medium", "Low"}:
            severity = severity.title().upper()
        if severity not in SEVERITY_LEVELS:
            severity = "MEDIUM"
        rules_raw = row.get("rules", "")
        reasons_raw = row.get("reasons", "")
        try:
            rules = ast.literal_eval(rules_raw) if isinstance(rules_raw, str) and rules_raw.startswith(("[", "(")) else rules_raw
        except (ValueError, SyntaxError):
            rules = rules_raw
        try:
            reasons = ast.literal_eval(reasons_raw) if isinstance(reasons_raw, str) and reasons_raw.startswith(("[", "(")) else reasons_raw
        except (ValueError, SyntaxError):
            reasons = reasons_raw
        if isinstance(rules, (list, tuple)):
            rule = "; ".join(str(x) for x in rules if str(x).strip())
        else:
            rule = str(rules or "").strip()
        if not rule:
            rule = _value(row, "rule_id", _value(row, "alert_name", "Security detection"))
        if isinstance(reasons, (list, tuple)):
            evidence = "; ".join(str(x) for x in reasons if str(x).strip())
        else:
            evidence = str(reasons or "").strip()
        if not evidence:
            evidence = _value(row, "reason", "No evidence details supplied in the alert CSV.")
        timestamp = _value(row, "timestamp", "Unknown")
        source_ip = _value(row, "source_ip", "Unknown")
        username = _value(row, "username", "Unknown")
        incident_id = _value(row, "incident_id", "") or _value(row, "alert_id", f"INC-{i:03d}")
        adapted.append({
            "incident_id": incident_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "username": username,
            "rule_triggered": rule,
            "severity": severity,
            "evidence": evidence,
            "destination_ip": _value(row, "destination_ip", "—"),
            "event_count": _value(row, "event_count", "1"),
            "status": _value(row, "alert_status", "Unassigned"),
            "alert_name": _value(row, "alert_name", rule),
        })
    return adapted


def _get_report(incident_id):
    for alert in _reporting_alerts():
        if alert["incident_id"] == incident_id:
            try:
                return build_incident_report(alert)
            except ValueError as exc:
                abort(400, description=f"Invalid incident data: {exc}")
    abort(404, description="Incident not found.")


@app.get("/incidents")
def incident_list():
    alerts = _reporting_alerts()
    severity_counts = Counter(a["severity"] for a in alerts)
    query = request.args.get("q", "").strip().lower()
    severity = request.args.get("severity", "").strip().upper()
    if query:
        alerts = [a for a in alerts if query in " ".join(str(v) for v in a.values()).lower()]
    if severity in SEVERITY_LEVELS:
        alerts = [a for a in alerts if a["severity"] == severity]
    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    page_size = 25
    try: page = max(1, int(request.args.get("page", "1")))
    except ValueError: page = 1
    pages = max(1, (len(alerts) + page_size - 1) // page_size)
    page = min(page, pages)
    shown = alerts[(page-1)*page_size:page*page_size]
    return render_template("incident_list.html", alerts=shown, query=query, severity=severity,
                           page=page, pages=pages, total=len(alerts), severity_counts=severity_counts,
                           total_all=sum(severity_counts.values()))


@app.get("/incident/<path:incident_id>")
def incident_detail(incident_id):
    return render_template("incident_detail.html", report=_get_report(incident_id))


@app.get("/download-csv/<path:incident_id>")
def download_incident_csv(incident_id):
    report = _get_report(incident_id)
    output = StringIO()
    fields = ["incident_id", "timestamp", "source_ip", "username", "rule_triggered", "severity", "evidence", "summary", "recommended_actions", "report_generated_at"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    row = dict(report); row["recommended_actions"] = " | ".join(report["recommended_actions"])
    writer.writerow(row)
    return send_file(BytesIO(output.getvalue().encode("utf-8-sig")), mimetype="text/csv", as_attachment=True, download_name=f"incident_{incident_id}.csv")


def _prepare_aggregate(alerts, title):
    counts = Counter(a["severity"] for a in alerts)
    total = len(alerts)
    rules = Counter(a["rule_triggered"] for a in alerts if a.get("rule_triggered"))
    return {"title": title, "alerts": alerts, "total": total,
            "severity_counts": {s: counts.get(s, 0) for s in SEVERITY_LEVELS},
            "severity_percentages": {s: round(counts.get(s, 0)*100/total, 1) if total else 0 for s in SEVERITY_LEVELS},
            "rule_counts": rules.most_common(5),
            "export_url": url_for("export_overall_report") if title == "Overall Incident Report" else url_for("export_severity_report", severity=title.split()[0].upper())}

@app.get("/reports/overall")
def overall_report():
    alerts = sorted(_reporting_alerts(), key=lambda a: a.get("timestamp", ""), reverse=True)
    return render_template("aggregate_report.html", report=_prepare_aggregate(alerts, "Overall Incident Report"))

@app.get("/reports/severity/<severity>")
def severity_report(severity):
    severity = severity.strip().upper()
    if severity not in SEVERITY_LEVELS: abort(404, description="Unknown severity level.")
    alerts = [a for a in _reporting_alerts() if a["severity"] == severity]
    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return render_template("aggregate_report.html", report=_prepare_aggregate(alerts, f"{severity.title()} Severity Incident Report"))

def _export_report_csv(alerts, filename):
    output = StringIO(); fields = ["incident_id", "timestamp", "source_ip", "username", "rule_triggered", "severity", "evidence"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore"); writer.writeheader(); writer.writerows(alerts)
    response = make_response("\ufeff" + output.getvalue()); response.headers["Content-Type"] = "text/csv; charset=utf-8"; response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'; return response

@app.get("/reports/export/overall")
def export_overall_report():
    alerts = sorted(_reporting_alerts(), key=lambda a: a.get("timestamp", ""), reverse=True)
    return _export_report_csv(alerts, "overall_incident_report.csv")

@app.get("/reports/export/severity/<severity>")
def export_severity_report(severity):
    severity = severity.strip().upper()
    if severity not in SEVERITY_LEVELS: abort(404, description="Unknown severity level.")
    alerts = [a for a in _reporting_alerts() if a["severity"] == severity]
    return _export_report_csv(alerts, f"{severity.lower()}_incident_report.csv")

# Reuse the reporter's detailed ReportLab PDF generator (one formatted incident per page).
def create_incident_pdf(alerts, title):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from xml.sax.saxutils import escape
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=17*mm, leftMargin=17*mm, topMargin=17*mm, bottomMargin=17*mm, title=title)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Brand", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=colors.HexColor("#173c70"), spaceAfter=12))
    styles.add(ParagraphStyle(name="ReportTitleCustom", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=23, leading=28, alignment=TA_LEFT, textColor=colors.HexColor("#071a36"), spaceAfter=6))
    styles.add(ParagraphStyle(name="SubtitleCustom", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#64748b"), spaceAfter=18))
    styles.add(ParagraphStyle(name="FieldLabel", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=7, leading=10, textColor=colors.HexColor("#173c70"), spaceAfter=5))
    styles.add(ParagraphStyle(name="FieldValue", parent=styles["Normal"], fontSize=10, leading=14, textColor=colors.HexColor("#10213f"), wordWrap="CJK"))
    styles.add(ParagraphStyle(name="IncidentID", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=colors.HexColor("#071a36")))
    styles.add(ParagraphStyle(name="SeverityLabel", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=11))
    story=[]
    def safe(v): return escape(str(v if v is not None else ""))
    def field_card(label, value, accent=None):
        card=Table([[[Paragraph(label.upper(),styles["FieldLabel"]),Paragraph(safe(value),styles["FieldValue"])] ]],colWidths=[doc.width])
        cmds=[("BOX",(0,0),(-1,-1),0.7,colors.HexColor("#cbd5e1")),("BACKGROUND",(0,0),(-1,-1),colors.white),("LEFTPADDING",(0,0),(-1,-1),12),("RIGHTPADDING",(0,0),(-1,-1),12),("TOPPADDING",(0,0),(-1,-1),12),("BOTTOMPADDING",(0,0),(-1,-1),12),("VALIGN",(0,0),(-1,-1),"TOP")]
        if accent: cmds.append(("LINEBEFORE",(0,0),(0,0),3,colors.HexColor(accent)))
        card.setStyle(TableStyle(cmds)); return [card,Spacer(1,8)]
    def color_for(s): return {"LOW":"#16805d","MEDIUM":"#b77900","HIGH":"#d35400","CRITICAL":"#dc2626"}.get(s,"#64748b")
    if not alerts: story=[Paragraph(title,styles["ReportTitleCustom"]),Paragraph("No incidents were found for this report.",styles["FieldValue"])]
    for i,a in enumerate(alerts):
        report=build_incident_report(a)
        if i: story.append(PageBreak())
        story += [Paragraph("AI-ASSISTED SIEM / SECURITY OPERATIONS",styles["Brand"]),Paragraph("Incident Report",styles["ReportTitleCustom"]),Paragraph("Incident documentation and investigation details",styles["SubtitleCustom"])]
        ref=Table([[[Paragraph("INCIDENT REFERENCE",styles["FieldLabel"]),Table([[Paragraph(safe(report["incident_id"]),styles["IncidentID"]),Paragraph(safe(report["severity"]),ParagraphStyle(name=f"Severity_{i}",parent=styles["SeverityLabel"],textColor=colors.HexColor(color_for(report["severity"]))))]],colWidths=[doc.width*.76,doc.width*.24],style=TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(1,0),(1,0),"RIGHT"),("LEFTPADDING",(0,0),(-1,-1),0),("RIGHTPADDING",(0,0),(-1,-1),0)])),Spacer(1,8),Paragraph("Event time: "+safe(report["timestamp"]),styles["FieldValue"])] ]],colWidths=[doc.width])
        ref.setStyle(TableStyle([("BOX",(0,0),(-1,-1),.7,colors.HexColor("#cbd5e1")),("LEFTPADDING",(0,0),(-1,-1),12),("RIGHTPADDING",(0,0),(-1,-1),12),("TOPPADDING",(0,0),(-1,-1),12),("BOTTOMPADDING",(0,0),(-1,-1),12),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story += [ref,Spacer(1,8)]
        details=Table([[[Paragraph("SOURCE IP ADDRESS",styles["FieldLabel"]),Paragraph(safe(report["source_ip"]),styles["FieldValue"])],[Paragraph("AFFECTED USER",styles["FieldLabel"]),Paragraph(safe(report["username"]),styles["FieldValue"])]]],colWidths=[doc.width/2-4,doc.width/2-4])
        details.setStyle(TableStyle([("BOX",(0,0),(0,0),.7,colors.HexColor("#cbd5e1")),("BOX",(1,0),(1,0),.7,colors.HexColor("#cbd5e1")),("LEFTPADDING",(0,0),(-1,-1),10),("RIGHTPADDING",(0,0),(-1,-1),10),("TOPPADDING",(0,0),(-1,-1),12),("BOTTOMPADDING",(0,0),(-1,-1),12),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story += [details,Spacer(1,8)]
        story += field_card("Rule Triggered",report["rule_triggered"])+field_card("Evidence",report["evidence"])+field_card("Incident Summary",report["summary"])
        actions="<br/>".join(f"{j}. {safe(x)}" for j,x in enumerate(report["recommended_actions"],1))
        story += field_card("Recommended Defensive Actions",actions)
    def footer(canvas,document):
        canvas.saveState(); canvas.setFont("Helvetica",8); canvas.setFillColor(colors.HexColor("#64748b")); canvas.drawCentredString(A4[0]/2,9*mm,f"Page {document.page}"); canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer); buffer.seek(0); return buffer

@app.get("/reports/download/overall")
def download_overall_pdf():
    alerts=sorted(_reporting_alerts(),key=lambda a:a.get("timestamp",""),reverse=True)
    return send_file(create_incident_pdf(alerts,"Overall Incident Report"),mimetype="application/pdf",as_attachment=True,download_name="overall_incident_report.pdf")

@app.get("/reports/download/severity/<severity>")
def download_severity_pdf(severity):
    severity=severity.strip().upper()
    if severity not in SEVERITY_LEVELS: abort(404,description="Unknown severity level.")
    alerts=sorted([a for a in _reporting_alerts() if a["severity"]==severity],key=lambda a:a.get("timestamp",""),reverse=True)
    return send_file(create_incident_pdf(alerts,f"{severity.title()} Incident Report"),mimetype="application/pdf",as_attachment=True,download_name=f"{severity.lower()}_incident_report.pdf")


if __name__ == "__main__":
    print("\nAI-Assisted SIEM dashboard is starting.")
    print("Open http://127.0.0.1:5000 in your browser.")
    print("Default records are read from processed_logs.csv, invalid_logs.csv and security_alerts.csv.\n")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
