import sqlite3

DATABASE = "database/soc.db"


# Detection type -> MITRE ATT&CK technique
MITRE_MAP = {

    "Possible Brute Force":
        "T1110 - Brute Force",

    "Network Port Scan":
        "T1046 - Network Service Scanning",

    "SQL Injection Attempt":
        "T1190 - Exploit Public-Facing Application",

    "Privilege Escalation":
        "T1068 - Exploitation for Privilege Escalation"
}


def update_mitre():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, alert_type
        FROM alerts
        WHERE mitre_technique IS NULL
           OR mitre_technique = 'Unknown - Requires Investigation'
    """)

    alerts = cursor.fetchall()

    for alert_id, alert_type in alerts:

        technique = MITRE_MAP.get(
            alert_type,
            "Unknown - Requires Investigation"
        )

        cursor.execute("""
            UPDATE alerts
            SET mitre_technique = ?
            WHERE id = ?
        """, (technique, alert_id))

        print(f"Alert {alert_id}: {alert_type}")
        print(f"MITRE ATT&CK: {technique}")
        print()

    connection.commit()
    connection.close()


if __name__ == "__main__":
    update_mitre()
