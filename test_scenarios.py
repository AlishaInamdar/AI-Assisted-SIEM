from rules import (
    detect_failed_login_burst,
    detect_multiple_users_from_ip,
    detect_success_after_failed_burst,
    correlate_alerts
)


# ---------------------------------------------------------
# TEST 1: NORMAL LOGIN
# ---------------------------------------------------------

normal_logs = [
    {
        "timestamp": "2026-10-18 13:00:00",
        "source_ip": "192.168.1.100",
        "username": "normal_user",
        "event_type": "LOGIN",
        "status": "SUCCESS"
    }
]

print("\n--- TEST 1: NORMAL LOGIN ---")

alerts = detect_failed_login_burst(normal_logs)
alerts += detect_multiple_users_from_ip(normal_logs)
alerts += detect_success_after_failed_burst(normal_logs)

print("Alerts:", alerts)


# ---------------------------------------------------------
# TEST 2: DUPLICATE ALERTS
# ---------------------------------------------------------

duplicate_alerts = [
    {
        "rule": "Repeated Failed Logins",
        "username": "admin",
        "source_ip": "192.168.1.10",
        "event_count": 5,
        "severity": "HIGH",
        "timestamp": "2026-10-18 10:00:00",
        "reason": "5 failed login attempts detected within 5 minutes"
    },
    {
        "rule": "Repeated Failed Logins",
        "username": "admin",
        "source_ip": "192.168.1.10",
        "event_count": 5,
        "severity": "HIGH",
        "timestamp": "2026-10-18 10:00:00",
        "reason": "5 failed login attempts detected within 5 minutes"
    }
]

print("\n--- TEST 2: DUPLICATE ALERTS ---")

correlated = correlate_alerts(duplicate_alerts)

print("Correlated alerts:", len(correlated))

for alert in correlated:
    print(alert)


# ---------------------------------------------------------
# TEST 3: DIFFERENT USERS / SAME IP
# ---------------------------------------------------------

multi_user_logs = [
    {
        "timestamp": "2026-10-18 14:00:00",
        "source_ip": "192.168.1.50",
        "username": "user1",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-18 14:01:00",
        "source_ip": "192.168.1.50",
        "username": "user2",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-18 14:02:00",
        "source_ip": "192.168.1.50",
        "username": "user3",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-18 14:03:00",
        "source_ip": "192.168.1.50",
        "username": "user4",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-18 14:04:00",
        "source_ip": "192.168.1.50",
        "username": "user5",
        "event_type": "LOGIN",
        "status": "FAILED"
    }
]

print("\n--- TEST 3: MULTIPLE USERS FROM SAME IP ---")

alerts = detect_multiple_users_from_ip(multi_user_logs)

print("Alerts:", alerts)
