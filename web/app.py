from flask import Flask, render_template, request, redirect, url_for
import sys
from pathlib import Path


# Project root
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT))


from src.database import (
    get_incidents,
    update_incident_status,
    get_alerts
)


app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)


@app.route("/")
def dashboard():

    selected_risk = request.args.get(
        "risk",
        "ALL"
    )

    selected_status = request.args.get(
        "status",
        "ALL"
    )

    incidents = get_incidents()

    # Risk filter

    if selected_risk != "ALL":

        incidents = [
            incident
            for incident in incidents
            if incident["risk_level"] == selected_risk
        ]


    # Status filter

    if selected_status != "ALL":

        incidents = [
            incident
            for incident in incidents
            if incident["status"] == selected_status
        ]


    # Risk statistics

    total_incidents = len(incidents)

    high_risk = sum(
        1
        for incident in incidents
        if incident["risk_level"] == "HIGH"
    )

    medium_risk = sum(
        1
        for incident in incidents
        if incident["risk_level"] == "MEDIUM"
    )

    low_risk = sum(
        1
        for incident in incidents
        if incident["risk_level"] == "LOW"
    )

    critical_risk = sum(
        1
        for incident in incidents
        if incident["risk_level"] == "CRITICAL"
    )


    # Threat statistics

    threat_counts = {}

    for incident in incidents:

        threat = incident["threat_type"]

        threat_counts[threat] = (
            threat_counts.get(threat, 0) + 1
        )


    # IP statistics

    ip_counts = {}

    for incident in incidents:

        ip = incident["ip_address"]

        ip_counts[ip] = (
            ip_counts.get(ip, 0) + 1
        )


    # Status statistics

    new_count = sum(
        1
        for incident in incidents
        if incident["status"] == "NEW"
    )

    investigating_count = sum(
        1
        for incident in incidents
        if incident["status"] == "INVESTIGATING"
    )

    resolved_count = sum(
        1
        for incident in incidents
        if incident["status"] == "RESOLVED"
    )


    # Alerts

    alerts = get_alerts()


    return render_template(
        "index.html",

        incidents=incidents,

        total_incidents=total_incidents,

        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        critical_risk=critical_risk,

        threat_counts=threat_counts,
        ip_counts=ip_counts,

        new_count=new_count,
        investigating_count=investigating_count,
        resolved_count=resolved_count,

        alerts=alerts,

        selected_risk=selected_risk,
        selected_status=selected_status
    )


@app.route(
    "/incident/<int:incident_id>"
)
def incident_details(incident_id):

    incidents = get_incidents()

    incident = None

    for item in incidents:

        if item["id"] == incident_id:

            incident = item

            break


    if incident is None:

        return "Incident not found", 404


    return render_template(
        "incident.html",
        incident=incident
    )


@app.route(
    "/update_status/<int:incident_id>",
    methods=["POST"]
)
def update_status(incident_id):

    status = request.form.get(
        "status"
    )

    allowed_statuses = [
        "NEW",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if status in allowed_statuses:

        update_incident_status(
            incident_id,
            status
        )


    return redirect(
        url_for(
            "incident_details",
            incident_id=incident_id
        )
    )


if __name__ == "__main__":

    app.run(debug=True)