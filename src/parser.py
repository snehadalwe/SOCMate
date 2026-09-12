import pandas as pd


def load_logs(file_path):
    """Load security logs from a CSV file."""
    try:
        logs = pd.read_csv(file_path)
        return logs
    except FileNotFoundError:
        print(f"Log file not found: {file_path}")
        return None


def display_logs(logs):
    """Display loaded security logs."""
    if logs is not None:
        print("\nSOCMate Security Logs")
        print("-" * 60)
        print(logs.to_string(index=False))


if __name__ == "__main__":
    logs = load_logs("data/sample_logs.csv")
    display_logs(logs)