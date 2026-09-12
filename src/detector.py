import pandas as pd


FAILED_LOGIN_THRESHOLD = 5
SUSPICIOUS_LOGIN_THRESHOLD = 3
MULTI_USER_THRESHOLD = 2


def detect_brute_force(logs):
    """Detect repeated failed login attempts."""

    failed_logins = logs[
        (logs["event_type"] == "LOGIN") &
        (logs["status"] == "FAILED")
    ]

    grouped = (
        failed_logins
        .groupby(["username", "ip_address"])
        .agg(
            failed_attempts=("username", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max")
        )
        .reset_index()
    )

    incidents = grouped[
        grouped["failed_attempts"] >= FAILED_LOGIN_THRESHOLD
    ]

    results = []

    for _, incident in incidents.iterrows():

        results.append({
            "threat_type": "Brute Force",
            "username": incident["username"],
            "ip_address": incident["ip_address"],
            "severity": "HIGH",
            "timestamp": incident["last_seen"],
            "description":
                f"{incident['failed_attempts']} failed login attempts detected"
        })

    return results


def detect_privilege_changes(logs):
    """Detect privilege change events."""

    privilege_events = logs[
        logs["event_type"] == "PRIVILEGE_CHANGE"
    ]

    results = []

    for _, event in privilege_events.iterrows():

        results.append({
            "threat_type": "Privilege Change",
            "username": event["username"],
            "ip_address": event["ip_address"],
            "severity": "MEDIUM",
            "timestamp": event["timestamp"],
            "description":
                "User privilege was changed"
        })

    return results


def detect_suspicious_logins(logs):
    """Detect repeated suspicious login attempts."""

    failed_logins = logs[
        (logs["event_type"] == "LOGIN") &
        (logs["status"] == "FAILED")
    ]

    grouped = (
        failed_logins
        .groupby(["username", "ip_address"])
        .agg(
            failed_attempts=("username", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max")
        )
        .reset_index()
    )

    suspicious = grouped[
        (grouped["failed_attempts"] >= SUSPICIOUS_LOGIN_THRESHOLD) &
        (grouped["failed_attempts"] < FAILED_LOGIN_THRESHOLD)
    ]

    results = []

    for _, incident in suspicious.iterrows():

        results.append({
            "threat_type": "Suspicious Login",
            "username": incident["username"],
            "ip_address": incident["ip_address"],
            "severity": "MEDIUM",
            "timestamp": incident["last_seen"],
            "description":
                f"{incident['failed_attempts']} suspicious failed login attempts"
        })

    return results


def detect_multi_user_attack(logs):
    """Detect one IP attempting to access multiple usernames."""

    failed_logins = logs[
        (logs["event_type"] == "LOGIN") &
        (logs["status"] == "FAILED")
    ]

    grouped = (
        failed_logins
        .groupby("ip_address")
        .agg(
            usernames=("username", "nunique"),
            attempts=("username", "count"),
            last_seen=("timestamp", "max")
        )
        .reset_index()
    )

    suspicious = grouped[
        grouped["usernames"] >= MULTI_USER_THRESHOLD
    ]

    results = []

    for _, incident in suspicious.iterrows():

        results.append({
            "threat_type": "Multi-User Attack",
            "username": "Multiple",
            "ip_address": incident["ip_address"],
            "severity": "HIGH",
            "timestamp": incident["last_seen"],
            "description":
                f"IP attempted login against "
                f"{incident['usernames']} different usernames "
                f"with {incident['attempts']} failed attempts"
        })

    return results


def detect_success_after_failures(logs):
    """Detect successful login after multiple failed attempts."""

    login_logs = logs[
        logs["event_type"] == "LOGIN"
    ].copy()

    login_logs["timestamp"] = pd.to_datetime(
        login_logs["timestamp"]
    )

    results = []

    for (username, ip_address), group in login_logs.groupby(
        ["username", "ip_address"]
    ):

        group = group.sort_values("timestamp")

        failed_count = 0

        for _, event in group.iterrows():

            if event["status"] == "FAILED":

                failed_count += 1

            elif (
                event["status"] == "SUCCESS" and
                failed_count >= SUSPICIOUS_LOGIN_THRESHOLD
            ):

                results.append({
                    "threat_type": "Successful Login After Failures",
                    "username": username,
                    "ip_address": ip_address,
                    "severity": "HIGH",
                    "timestamp": event["timestamp"],
                    "description":
                        f"Successful login after "
                        f"{failed_count} failed attempts"
                })

                failed_count = 0

    return results


def detect_all_threats(logs):
    """Run all SOCMate detection rules."""

    incidents = []

    incidents.extend(
        detect_brute_force(logs)
    )

    incidents.extend(
        detect_privilege_changes(logs)
    )

    incidents.extend(
        detect_suspicious_logins(logs)
    )

    incidents.extend(
        detect_multi_user_attack(logs)
    )

    incidents.extend(
        detect_success_after_failures(logs)
    )

    return incidents


def display_incidents(incidents):
    """Display detected incidents."""

    if not incidents:

        print("\nNo security incidents detected.")

        return

    print("\n🚨 SOCMate SECURITY INCIDENTS")
    print("=" * 75)

    for incident in incidents:

        print(f"Threat      : {incident['threat_type']}")
        print(f"Username    : {incident['username']}")
        print(f"IP Address  : {incident['ip_address']}")
        print(f"Timestamp   : {incident['timestamp']}")
        print(f"Severity    : {incident['severity']}")
        print(f"Description : {incident['description']}")
        print("-" * 75)


if __name__ == "__main__":

    logs = pd.read_csv(
        "data/sample_logs.csv"
    )

    incidents = detect_all_threats(logs)

    display_incidents(incidents)