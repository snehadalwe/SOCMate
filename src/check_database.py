from database import get_incidents


incidents = get_incidents()

print("\n📋 STORED SOCMATE INCIDENTS")
print("=" * 60)

for incident in incidents:
    print(
        f"#{incident['id']} | "
        f"{incident['threat_type']} | "
        f"{incident['ip_address']} | "
        f"{incident['risk_level']}"
    )