import sys

sys.path.append(".")

from database.db import insert_alert


LOG_FILE = "logs/security.log"


with open(LOG_FILE, "r") as file:

    for line in file:

        parts = [part.strip() for part in line.split("|")]

        if len(parts) != 5:
            continue

        timestamp, event_type, source_ip, username, action = parts

        if action == "PORT_SCAN":

            severity = "MEDIUM"

            description = (
                "Possible network reconnaissance detected."
            )

            insert_alert(
                timestamp,
                "Network Port Scan",
                source_ip,
                username,
                severity,
                description
            )

            print("\n🚨 SECURITY ALERT")
            print("-------------------------")
            print("Alert Type : Network Port Scan")
            print("Source IP  :", source_ip)
            print("Timestamp  :", timestamp)
            print("Severity   :", severity)
            print("Stored in  : SQLite database")
