# AI-Assisted SIEM
# Payal - CSV Loader, Validation and Detection Runner

import csv

from rules import run_detection_rules, validate_log


def load_logs_from_csv(filename):
    """
    Load and validate SIEM logs from a CSV file.
    """

    logs = []
    invalid_rows = 0

    with open(filename, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            if validate_log(row):
                logs.append(row)
            else:
                invalid_rows += 1

    return logs, invalid_rows


def main():
    """
    Load CSV data, validate logs and run detection rules.
    """

    logs, invalid_rows = load_logs_from_csv("sample_logs.csv")

    print("Total valid logs loaded:", len(logs))
    print("Total invalid logs skipped:", invalid_rows)

    alerts = run_detection_rules(logs)

    print("\n--- DETECTION RESULTS ---")

    if not alerts:
        print("No suspicious activity detected.")
        return

    print("Total correlated alerts:", len(alerts))

    for alert in alerts:
        print("\nAlert:")
        print(alert)


if __name__ == "__main__":
    main()
