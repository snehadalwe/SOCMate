import sqlite3
from pathlib import Path


DATABASE_PATH = (
    Path(__file__).parent.parent
    / "data"
    / "socmate.db"
)


def get_connection():
    """Create a database connection."""

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def create_database():
    """Create SOCMate database and tables."""

    connection = get_connection()

    cursor = connection.cursor()

    # INCIDENTS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            threat_type TEXT NOT NULL,

            username TEXT,

            ip_address TEXT,

            severity TEXT,

            risk_score INTEGER,

            risk_level TEXT,

            timestamp TEXT,

            description TEXT,

            status TEXT DEFAULT 'NEW',

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(
                threat_type,
                username,
                ip_address,
                timestamp
            )
        )
    """)

    # ALERTS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id INTEGER,

            threat_type TEXT,

            risk_level TEXT,

            message TEXT,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (incident_id)
                REFERENCES incidents(id)
        )
    """)

    # Remove old alerts that have no incident ID
    cursor.execute("""
        DELETE FROM alerts
        WHERE incident_id IS NULL
    """)

    # Remove duplicate alerts
    cursor.execute("""
        DELETE FROM alerts
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM alerts
            WHERE incident_id IS NOT NULL
            GROUP BY incident_id
        )
        AND incident_id IS NOT NULL
    """)

    # Make sure one incident gets only one alert
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_alerts_incident_id
        ON alerts(incident_id)
    """)

    connection.commit()

    connection.close()


def save_incident(incident):
    """Save incident and return its database ID."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO incidents (
            threat_type,
            username,
            ip_address,
            severity,
            risk_score,
            risk_level,
            timestamp,
            description,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident["threat_type"],
        incident["username"],
        incident["ip_address"],
        incident["severity"],
        incident["risk_score"],
        incident["risk_level"],
        str(incident["timestamp"]),
        incident["description"],
        "NEW"
    ))

    cursor.execute("""
        SELECT id
        FROM incidents
        WHERE threat_type = ?
        AND username = ?
        AND ip_address = ?
        AND timestamp = ?
    """, (
        incident["threat_type"],
        incident["username"],
        incident["ip_address"],
        str(incident["timestamp"])
    ))

    row = cursor.fetchone()

    connection.commit()

    connection.close()

    if row:
        return row["id"]

    return None


def save_alert(incident_id, incident):
    """Save one alert for a HIGH or CRITICAL incident."""

    if incident["risk_level"] not in [
        "HIGH",
        "CRITICAL"
    ]:
        return

    if incident_id is None:
        return

    connection = get_connection()

    cursor = connection.cursor()

    message = (
        f"{incident['risk_level']} risk detected: "
        f"{incident['threat_type']} from "
        f"{incident['ip_address']}"
    )

    cursor.execute("""
        INSERT OR IGNORE INTO alerts (
            incident_id,
            threat_type,
            risk_level,
            message
        )
        VALUES (?, ?, ?, ?)
    """, (
        incident_id,
        incident["threat_type"],
        incident["risk_level"],
        message
    ))

    connection.commit()

    connection.close()


def get_incidents():
    """Retrieve all stored incidents."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY timestamp DESC
    """)

    incidents = cursor.fetchall()

    connection.close()

    return incidents


def update_incident_status(
    incident_id,
    status
):
    """Update incident status."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        UPDATE incidents
        SET status = ?
        WHERE id = ?
    """, (
        status,
        incident_id
    ))

    connection.commit()

    connection.close()


def get_alerts():
    """Retrieve recent security alerts."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY created_at DESC
        LIMIT 10
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


def get_incident_by_id(incident_id):
    """Retrieve one incident by ID."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE id = ?
    """, (
        incident_id,
    ))

    incident = cursor.fetchone()

    connection.close()

    return incident