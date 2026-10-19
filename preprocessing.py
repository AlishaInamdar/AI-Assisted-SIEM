
import pandas as pd
import ipaddress

REQUIRED_COLUMNS = [
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "status"
]


def preprocess_logs(file_path):
    # 1. Read the CSV file
    df = pd.read_csv(file_path, dtype=str)

    # 2. Clean column names
    df.columns = df.columns.str.strip().str.lower()

    # 3. Check required columns
    missing = set(REQUIRED_COLUMNS) - set(df.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    # 4. Keep the required columns only
    df = df[REQUIRED_COLUMNS].copy()

    # 5. Clean empty and extra-space values
    for column in REQUIRED_COLUMNS:
        df[column] = df[column].fillna("").str.strip()

    # 6. Standardize event values
    df["event_type"] = df["event_type"].str.upper()
    df["status"] = df["status"].str.upper()

    # 7. Validate timestamps
    parsed_time = pd.to_datetime(
        df["timestamp"],
        format="%Y-%m-%d %H:%M:%S",
        errors="coerce"
    )

    # 8. Validate IP addresses
    def is_valid_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    valid_ip = df["source_ip"].apply(is_valid_ip)

    # 9. Identify valid records
    valid_row = (
        parsed_time.notna()
        & df["source_ip"].ne("")
        & valid_ip
        & df["username"].ne("")
        & df["event_type"].eq("LOGIN")
        & df["status"].isin(["FAILED", "SUCCESS"])
    )

    # 10. Separate valid and invalid records
    valid_df = df.loc[valid_row].copy()
    invalid_df = df.loc[~valid_row].copy()

    # 11. Standardize timestamp format
    valid_df["timestamp"] = (
        parsed_time.loc[valid_row]
        .dt.strftime("%Y-%m-%d %H:%M:%S")
    )

    # 12. Convert records into a list of dictionaries
    logs = valid_df.to_dict(orient="records")
    # Save cleaned logs for inspection
    valid_df.to_csv("processed_logs.csv", index=False)

    print("Processed logs saved to processed_logs.csv")

    # 13. Save rejected records for inspection
    invalid_df.to_csv("invalid_logs.csv", index=False)

    print("Total records:", len(df))
    print("Valid records:", len(logs))
    print("Invalid records:", len(invalid_df))

    return logs


if __name__ == "__main__":
    logs = preprocess_logs("logs.csv")

    print("\nFirst two processed records:")

    for log in logs[:2]:
        print(log)
