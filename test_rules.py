# AI-Assisted SIEM
# Payal - Testing Detection Rules

from rules import (
    detect_failed_login_burst,
    detect_multiple_users_from_ip,
    detect_success_after_failed_burst,
    run_detection_rules
)


# ---------------------------------------------------------
# TEST DATA
# ---------------------------------------------------------

sample_logs = [
    # Rule 1: 5 failed logins from same user + IP within 5 minutes
    {
        "timestamp": "2026-10-17 10:01:00",
        "source_ip": "192.168.1.10",
        "username": "user1",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-17 10:02:00",
        "source_ip": "192.168.1.10",
        "username": "user1",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-17 10:03:00",
        "source_ip": "192.168.1.10",
        "username": "user1",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-17 10:04:00",
        "source_ip": "192.168.1.10",
        "username": "user1",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-17 10:05:00",
        "source_ip": "192.168.1.10",
        "username": "user1",
        "event_type": "LOGIN",
        "status": "FAILED"
    },

    # Successful login after failed-login burst
    {
        "timestamp": "2026-10-17 10:06:00",
        "source_ip": "192.168.1.10",
        "username": "user1",
        "event_type": "LOGIN",
        "status": "SUCCESS"
    },

    # Rule 2: same IP attacking multiple users
    {
        "timestamp": "2026-10-17 11:01:00",
        "source_ip": "192.168.1.50",
        "username": "user2",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-17 11:02:00",
        "source_ip": "192.168.1.50",
        "username": "user3",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-17 11:03:00",
        "source_ip": "192.168.1.50",
        "username": "user4",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-17 11:04:00",
        "source_ip": "192.168.1.50",
        "username": "user5",
        "event_type": "LOGIN",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-10-17 11:05:00",
        "source_ip": "192.168.1.50",
        "username": "user6",
        "event_type": "LOGIN",
        "status": "FAILED"
    },

    # Normal login - should not create an alert
    {
        "timestamp": "2026-10-17 12:00:00",
        "source_ip": "192.168.1.100",
        "username": "normal_user",
        "event_type": "LOGIN",
        "status": "SUCCESS"
    }
]


# ---------------------------------------------------------
# TEST 1 - FAILED LOGIN BURST
# ---------------------------------------------------------

print("\n--- TEST 1: Failed Login Burst ---")

alerts = detect_failed_login_burst(sample_logs)

print("Number of alerts:", len(alerts))

for alert in alerts:
    print(alert)


# ---------------------------------------------------------
# TEST 2 - MULTIPLE USERS FROM ONE IP
# ---------------------------------------------------------

print("\n--- TEST 2: Multiple Users From One IP ---")

alerts = detect_multiple_users_from_ip(sample_logs)

print("Number of alerts:", len(alerts))

for alert in alerts:
    print(alert)


# ---------------------------------------------------------
# TEST 3 - SUCCESS AFTER FAILED BURST
# ---------------------------------------------------------

print("\n--- TEST 3: Successful Login After Failed Burst ---")

alerts = detect_success_after_failed_burst(sample_logs)

print("Number of alerts:", len(alerts))

for alert in alerts:
    print(alert)


# ---------------------------------------------------------
# TEST 4 - RUN ALL RULES + CORRELATION
# ---------------------------------------------------------

print("\n--- TEST 4: All Rules + Alert Correlation ---")

final_alerts = run_detection_rules(sample_logs)

print("Number of correlated alerts:", len(final_alerts))

for alert in final_alerts:
    print(alert)
