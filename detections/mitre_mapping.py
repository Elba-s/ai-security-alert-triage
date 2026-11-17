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


def compare_mitre(rule_technique, ai_technique):
    """Compare rule and AI MITRE suggestions by technique ID."""

    if not rule_technique or not ai_technique:
        return "NOT_COMPARABLE"

    rule_technique = rule_technique.strip()
    ai_technique = ai_technique.strip()

    if rule_technique.lower() == "unknown - requires investigation":
        return "NOT_COMPARABLE"

    if ai_technique.lower() == "insufficient evidence":
        return "NOT_COMPARABLE"

    import re

    rule_match = re.match(r"^(T\d{4}(?:\.\d{3})?)\b", rule_technique, re.IGNORECASE)
    ai_match = re.match(r"^(T\d{4}(?:\.\d{3})?)\b", ai_technique, re.IGNORECASE)

    if not rule_match or not ai_match:
        return "NOT_COMPARABLE"

    if rule_match.group(1).upper() == ai_match.group(1).upper():
        return "AGREEMENT"

    return "DISAGREEMENT"


def save_mitre_comparison(alert_id, ai_technique):
    """Save the comparison status without changing the rule mapping."""

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    try:
        cursor.execute("""
            SELECT mitre_technique
            FROM alerts
            WHERE id = ?
        """, (alert_id,))

        row = cursor.fetchone()

        if row is None:
            raise ValueError(f"Alert {alert_id} not found")

        rule_technique = row[0]
        status = compare_mitre(rule_technique, ai_technique)

        cursor.execute("""
            UPDATE alerts
            SET ai_mitre_suggestion = ?,
                mitre_comparison_status = ?
            WHERE id = ?
        """, (ai_technique, status, alert_id))

        connection.commit()
        return status

    finally:
        connection.close()

if __name__ == "__main__":
    update_mitre()
