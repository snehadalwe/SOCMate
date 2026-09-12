import pandas as pd

from src.detector import (
    detect_brute_force,
    detect_privilege_changes,
    detect_suspicious_logins
)

from src.scoring import (
    calculate_risk_score,
    get_risk_level,
    generate_alert
)


# --------------------------------------------------
# TEST BRUTE FORCE DETECTION
# --------------------------------------------------

def test_brute_force_detection():

    logs = pd.DataFrame([
        {
            "timestamp": "2026-09-06 10:00:01",
            "event_type": "LOGIN",
            "username": "admin",
            "ip_address": "192.168.1.50",
            "status": "FAILED",
            "details": "Invalid password"
        },
        {
            "timestamp": "2026-09-06 10:00:02",
            "event_type": "LOGIN",
            "username": "admin",
            "ip_address": "192.168.1.50",
            "status": "FAILED",
            "details": "Invalid password"
        },
        {
            "timestamp": "2026-09-06 10:00:03",
            "event_type": "LOGIN",
            "username": "admin",
            "ip_address": "192.168.1.50",
            "status": "FAILED",
            "details": "Invalid password"
        },
        {
            "timestamp": "2026-09-06 10:00:04",
            "event_type": "LOGIN",
            "username": "admin",
            "ip_address": "192.168.1.50",
            "status": "FAILED",
            "details": "Invalid password"
        },
        {
            "timestamp": "2026-09-06 10:00:05",
            "event_type": "LOGIN",
            "username": "admin",
            "ip_address": "192.168.1.50",
            "status": "FAILED",
            "details": "Invalid password"
        }
    ])

    incidents = detect_brute_force(logs)

    assert len(incidents) == 1
    assert incidents[0]["threat_type"] == "Brute Force"
    assert incidents[0]["username"] == "admin"


# --------------------------------------------------
# TEST PRIVILEGE CHANGE DETECTION
# --------------------------------------------------

def test_privilege_change_detection():

    logs = pd.DataFrame([
        {
            "timestamp": "2026-09-06 11:00:00",
            "event_type": "PRIVILEGE_CHANGE",
            "username": "admin",
            "ip_address": "192.168.1.25",
            "status": "SUCCESS",
            "details": "User privilege changed"
        }
    ])

    incidents = detect_privilege_changes(logs)

    assert len(incidents) == 1
    assert incidents[0]["threat_type"] == "Privilege Change"
    assert incidents[0]["severity"] == "MEDIUM"


# --------------------------------------------------
# TEST SUSPICIOUS LOGIN
# --------------------------------------------------

def test_suspicious_login_detection():

    logs = pd.DataFrame([
        {
            "timestamp": "2026-09-06 12:00:01",
            "event_type": "LOGIN",
            "username": "user1",
            "ip_address": "192.168.1.60",
            "status": "FAILED",
            "details": "Invalid password"
        },
        {
            "timestamp": "2026-09-06 12:00:02",
            "event_type": "LOGIN",
            "username": "user1",
            "ip_address": "192.168.1.60",
            "status": "FAILED",
            "details": "Invalid password"
        },
        {
            "timestamp": "2026-09-06 12:00:03",
            "event_type": "LOGIN",
            "username": "user1",
            "ip_address": "192.168.1.60",
            "status": "FAILED",
            "details": "Invalid password"
        }
    ])

    incidents = detect_suspicious_logins(logs)

    assert len(incidents) == 1
    assert incidents[0]["threat_type"] == "Suspicious Login"
    assert incidents[0]["severity"] == "MEDIUM"


# --------------------------------------------------
# TEST RISK SCORE
# --------------------------------------------------

def test_risk_score():

    incident = {
        "threat_type": "Brute Force"
    }

    score = calculate_risk_score(incident)

    assert score == 7


# --------------------------------------------------
# TEST RISK LEVEL
# --------------------------------------------------

def test_risk_level():

    assert get_risk_level(1) == "LOW"
    assert get_risk_level(4) == "MEDIUM"
    assert get_risk_level(7) == "HIGH"
    assert get_risk_level(10) == "CRITICAL"


# --------------------------------------------------
# TEST ALERT GENERATION
# --------------------------------------------------

def test_alert_generation():

    incident = {
        "risk_level": "HIGH"
    }

    alert = generate_alert(incident)

    assert "HIGH ALERT" in alert