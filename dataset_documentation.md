
# SIEM Log Dataset and Preprocessing Documentation

## 1. Dataset Overview

The dataset used in this SIEM project is a synthetic CSV dataset created for testing and demonstrating security log analysis.

**Input file:** `logs.csv`

**Output files:**
- `processed_logs.csv` — contains valid and cleaned log records.
- `invalid_logs.csv` — contains rejected log records.
- `security_alerts.csv` — contains detected and correlated security alerts.

The dataset contains timestamps, source IP addresses, usernames, event types, and login statuses.

## 2. Log Sources

In real-world environments, security logs may come from operating systems, application servers, authentication services, firewalls, and network devices.

For this project, we use artificially created login events instead of collecting real organizational logs. These records represent normal and suspicious login activities.

## 3. Dataset Fields

| Field | Description |
|---|---|
| timestamp | Date and time when the event occurred |
| source_ip | IP address associated with the login attempt |
| username | Account involved in the event |
| event_type | Type of event, such as LOGIN |
| status | Result of the login attempt: SUCCESS or FAILED |

## 4. Event Normalization

Event normalization converts log data into a consistent format so that it can be processed and analyzed easily.

The preprocessing function:
- Removes extra spaces from column names and values.
- Converts column names to lowercase.
- Converts event types and login statuses to uppercase.
- Retains the required columns.
- Converts valid timestamps into a standard format.

## 5. Timestamp Validation

Timestamps are validated using the format `YYYY-MM-DD HH:MM:SS`.

Invalid or missing timestamps are rejected. Consistent timestamps allow the detection rules to identify suspicious activities occurring within specific time windows, such as five or ten minutes.

## 6. Missing and Invalid Records

The preprocessing function checks required fields, timestamps, IP addresses, event types, and login statuses.

Missing or invalid values cause a record to be rejected. Valid records are saved to `processed_logs.csv`, while rejected records are saved to `invalid_logs.csv` for inspection.

In the current test run:
- Total records: 14
- Valid records: 13
- Invalid records: 1

## 7. Why Synthetic Data Is Safer

Synthetic data is artificially generated and does not need to contain real user accounts or actual security incidents. It reduces the risk of exposing personal information or confidential organizational data during development and demonstrations.

Synthetic data also allows us to create controlled scenarios, repeat tests, and check whether detection rules behave as expected. However, it may not represent every condition found in real-world environments.

## 8. Current Limitations

The current preprocessing function is designed for login-event analysis. It accepts LOGIN events with SUCCESS or FAILED statuses and uses a specified timestamp format.

The dataset is intended for educational testing and does not represent a complete production SIEM environment.
