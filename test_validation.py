from rules import validate_log


tests = [
    (
        "Valid log",
        {
            "timestamp": "2026-10-18 10:00:00",
            "source_ip": "192.168.1.10",
            "username": "admin",
            "event_type": "LOGIN",
            "status": "FAILED"
        }
    ),
    (
        "Missing username",
        {
            "timestamp": "2026-10-18 10:00:00",
            "source_ip": "192.168.1.10",
            "username": "",
            "event_type": "LOGIN",
            "status": "FAILED"
        }
    ),
    (
        "Invalid timestamp",
        {
            "timestamp": "invalid-date",
            "source_ip": "192.168.1.10",
            "username": "admin",
            "event_type": "LOGIN",
            "status": "FAILED"
        }
    ),
    (
        "Invalid status",
        {
            "timestamp": "2026-10-18 10:00:00",
            "source_ip": "192.168.1.10",
            "username": "admin",
            "event_type": "LOGIN",
            "status": "UNKNOWN"
        }
    ),
    (
        "Invalid event type",
        {
            "timestamp": "2026-10-18 10:00:00",
            "source_ip": "192.168.1.10",
            "username": "admin",
            "event_type": "UNKNOWN",
            "status": "FAILED"
        }
    ),
]


for name, log in tests:
    result = validate_log(log)
    print(f"{name}: {result}")
