from collections import defaultdict
from datetime import datetime, timedelta
import sys
sys.path.append(".")

from database.db import (
    insert_alert,
    is_event_processed,
    mark_event_processed
)


LOG_FILE = "logs/security.log"


failed_logins = defaultdict(list)
successful_logins = defaultdict(list)
sudo_events = defaultdict(list)
users = {}

CORRELATION_WINDOW = timedelta(minutes=5)

# ========================================================
# READ ONLY NEW EVENTS
# ========================================================

new_events = []

with open(LOG_FILE, "r") as file:

    for line in file:

        line = line.strip()

        if not line:
            continue

        # Ignore events already processed
        if is_event_processed(line):
            continue

        parts = [part.strip() for part in line.split("|")]

        if len(parts) != 5:
            continue
 
        timestamp, event_type, source_ip, username, action = parts

        event_time = datetime.strptime(
        timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

        new_events.append(
             (line, event_time, source_ip, username, action)
        )

# ========================================================
# PROCESS NEW EVENTS
# ========================================================

for line, timestamp, source_ip, username, action in new_events:

    users[source_ip] = username

    if action == "LOGIN_FAILED":

        failed_logins[source_ip].append(timestamp)

    elif action == "LOGIN_SUCCESS":

        successful_logins[source_ip].append(timestamp)

    elif action == "SUDO_EXECUTED":

        sudo_events[source_ip].append(timestamp)

# ========================================================
# DETECT BRUTE FORCE
# ========================================================

for ip, failed_times in failed_logins.items():

    if not failed_times:
        continue

    # Sort failed-login timestamps
    failed_times.sort()

    # Check each possible 5-minute window
    for start_time in failed_times:

        window_end = start_time + CORRELATION_WINDOW

        window_failures = [
            event_time
            for event_time in failed_times
            if start_time <= event_time <= window_end
        ]

        if len(window_failures) < 5:
            continue

        username = users.get(ip, "unknown")

        successful_in_window = [
            event_time
            for event_time in successful_logins[ip]
            if start_time <= event_time <= window_end
        ]
        sudo_in_window = [
            event_time
            for event_time in sudo_events[ip]
            if start_time <= event_time <= window_end
        ]

        if successful_in_window and sudo_in_window:

            severity = "HIGH"

            description = (
                "Multiple failed logins within a 5-minute window "
                "followed by successful login and sudo activity."
            )

        elif successful_in_window:

            severity = "HIGH" 
            description = (
                "Multiple failed logins within a 5-minute window "
                "followed by a successful login."
            )

        else:

            severity = "MEDIUM"

            description = (
                "Multiple failed login attempts detected "
                "within a 5-minute window."
            )

        latest_timestamp = max(
            window_failures
            + successful_in_window
            + sudo_in_window
        )

        alert_created = insert_alert(
            latest_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "Possible Brute Force",
            ip, username,
            severity,
            description
        )

        if alert_created:

            print("\n🚨 SECURITY ALERT")
            print("-------------------------")
            print("Alert Type      : Possible Brute Force")
            print("Source IP       :", ip)
            print("Username        :", username)
            print("Failed Logins   :", len(window_failures))

            print(
                "Successful Login:",
                "YES" if successful_in_window else "NO"
            )

            print(
                "Sudo Activity   :",
                "YES" if sudo_in_window else "NO"
            )

            print("Risk Assessment :", severity)
            print("Correlation     : 5-minute window")
            print("Stored in       : SQLite database")

        # One alert per source IP per run
        break

# ========================================================
# MARK EVENTS AS PROCESSED
# ========================================================

for line, timestamp, source_ip, username, action in new_events:

    mark_event_processed(line)


print(
    f"\nProcessed {len(new_events)} new security event(s)."
)
