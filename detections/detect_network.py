
import sys

sys.path.append(".")

from database.db import (
    insert_alert,
    is_event_processed,
    mark_event_processed
)

LOG_FILE = "logs/security.log"

new_events = []

# Read only new events
with open(LOG_FILE, "r") as file:
    for line in file:
        line = line.strip()

        if not line or is_event_processed(line):
            continue

        parts = [part.strip() for part in line.split("|")]

        if len(parts) != 5:
            continue

        timestamp, event_type, source_ip, username, action = parts

        if action != "PORT_SCAN":
           continue

        new_events.append(
            (line, timestamp, source_ip, username, action)
        )

# Detect network port scans
for line, timestamp, source_ip, username, action in new_events:

    if action == "PORT_SCAN":

        severity = "MEDIUM"
        description = "Possible network reconnaissance detected."

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
        print("Alert Type :", "Network Port Scan")
        print("Source IP  :", source_ip)
        print("Timestamp  :", timestamp)
        print("Severity   :", severity)
        print("Stored in  : SQLite database")

# Mark all valid new events as processed
for line, timestamp, source_ip, username, action in new_events:
    mark_event_processed(line)

print(f"\nProcessed {len(new_events)} new security event(s).")
