import pandas as pd
from preprocessing import preprocess_logs
from rules import run_detection_rules


def main():
    print("===== SIEM LOG PROCESSING =====")

    # Step 1: Preprocess the dataset
    logs = preprocess_logs("logs.csv")

    # Step 2: Run Payal's detection rules
    alerts = run_detection_rules(logs)
    # Save security alerts to a CSV file
    if alerts:
        alerts_df = pd.DataFrame(alerts)
        alerts_df.to_csv("security_alerts.csv", index=False)
        print("Security alerts saved to security_alerts.csv")
    else:
        print("No alerts to save.")

    # Step 3: Display correlated alerts
    print("\n===== SIEM SECURITY ALERTS =====")

    if not alerts:
        print("No suspicious activity detected.")
    else:
        for alert in alerts:
            print("\nUsername:", alert["username"])
            print("Source IP:", alert["source_ip"])
            print("Severity:", alert["severity"])
            print("Triggered Rules:", ", ".join(alert["rules"]))
            print("Event Count:", alert["event_count"])
            print("Reasons:", "; ".join(alert["reasons"]))


if __name__ == "__main__":
    main()
