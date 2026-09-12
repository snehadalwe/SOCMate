THREAT_SCORES = {
    "Brute Force": 7,
    "Privilege Change": 5,
    "Suspicious Login": 4,
    "Multi-User Attack": 8,
    "Successful Login After Failures": 8
}


def calculate_risk_score(incident):
    """Calculate numerical risk score."""

    threat_type = incident["threat_type"]

    return THREAT_SCORES.get(
        threat_type,
        1
    )


def get_risk_level(score):
    """Convert risk score into risk level."""

    if score <= 2:
        return "LOW"

    elif score <= 5:
        return "MEDIUM"

    elif score <= 8:
        return "HIGH"

    else:
        return "CRITICAL"


def add_risk_information(incidents):
    """Add risk score and risk level."""

    for incident in incidents:

        score = calculate_risk_score(
            incident
        )

        incident["risk_score"] = score

        incident["risk_level"] = get_risk_level(
            score
        )

    return incidents


def generate_alert(incident):
    """Generate SOC alert based on risk level."""

    risk_level = incident["risk_level"]

    if risk_level == "CRITICAL":

        return "🚨 CRITICAL ALERT: Immediate investigation required!"

    elif risk_level == "HIGH":

        return "⚠️ HIGH ALERT: Suspicious activity detected!"

    elif risk_level == "MEDIUM":

        return "🟡 MEDIUM ALERT: Investigation recommended."

    else:

        return "🟢 LOW: No immediate action required."