import pandas as pd

from detector import detect_all_threats

from scoring import (
    add_risk_information,
    generate_alert
)

from database import (
    create_database,
    save_incident,
    save_alert
)


def main():

    print("🧠 SOCMate Security Operations Center")
    print("=" * 60)

    # Create database
    create_database()

    # Load security logs
    logs = pd.read_csv(
        "data/sample_logs.csv"
    )

    print(
        f"\n📄 Loaded {len(logs)} security log entries."
    )

    # Detect threats
    incidents = detect_all_threats(
        logs
    )

    # Calculate risk
    incidents = add_risk_information(
        incidents
    )

    print(
        f"\n🚨 Detected {len(incidents)} security incidents."
    )

    print("\n" + "=" * 70)
    print("SOCMate SECURITY INCIDENTS")
    print("=" * 70)

    # Process incidents
    for incident in incidents:

        alert = generate_alert(
            incident
        )

        print(
            f"\nThreat      : "
            f"{incident['threat_type']}"
        )

        print(
            f"Username    : "
            f"{incident['username']}"
        )

        print(
            f"IP Address  : "
            f"{incident['ip_address']}"
        )

        print(
            f"Risk Score  : "
            f"{incident['risk_score']}/10"
        )

        print(
            f"Risk Level  : "
            f"{incident['risk_level']}"
        )

        print(
            f"Description : "
            f"{incident['description']}"
        )

        print(
            f"Alert       : "
            f"{alert}"
        )

        print("-" * 70)

        # Save incident and get its database ID
        incident_id = save_incident(
            incident
        )

        # Save alert using the correct incident ID
        save_alert(
            incident_id,
            incident
        )

    print(
        "\n✅ Incidents processed successfully."
    )

    print(
        "✅ Security alerts saved successfully."
    )

    print(
        "🗄️ Database: data/socmate.db"
    )


if __name__ == "__main__":

    main()