from collections import defaultdict
from datetime import datetime, timedelta
import sqlite3
import sys

sys.path.append(".")

from database.db import (
    DATABASE,
    mark_event_processed
)

LOG_FILE = "logs/security.log"
CORRELATION_WINDOW = timedelta(minutes=5)
MIN_FAILED_LOGINS = 5


def insert_auth_alert_once(timestamp, source_ip, username,
                           severity, description,
                           window_start, window_end):

    with sqlite3.connect(DATABASE) as connection:

        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute("""
            SELECT id, severity
            FROM alerts
            WHERE alert_type = 'Possible Brute Force'
              AND source_ip = ?
              AND timestamp BETWEEN ? AND ?
            ORDER BY id DESC
            LIMIT 1
        """, (
            source_ip,
            window_start.strftime("%Y-%m-%d %H:%M:%S"),
            window_end.strftime("%Y-%m-%d %H:%M:%S")
        )).fetchone()

        if existing:
            alert_id, old_severity = existing
            if old_severity != severity:
                connection.execute("""
                    UPDATE alerts
                    SET timestamp = ?,
                        username = ?,
                        severity = ?,
                        description = ?
                    WHERE id = ?
                """, (
                    timestamp,
                    username,
                    severity,
                    description,
                    alert_id
                ))

                return "updated"

            return False

        connection.execute("""
            INSERT INTO alerts
            (timestamp, alert_type, source_ip, username,
             severity, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            "Possible Brute Force",
            source_ip,
            username,
            severity,
            description
        ))

        return "created"

def main():

    auth_events = defaultdict(
        lambda: {
            "failed": [],
            "successful": [],
            "sudo": []
        }
    )

    # Read ALL authentication events, not just unprocessed ones.
    with open(LOG_FILE, "r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            parts = [part.strip() for part in line.split("|")]

            if len(parts) != 5:
                continue

            timestamp, event_type, source_ip, username, action = parts

            if action not in (
                "LOGIN_FAILED",
                "LOGIN_SUCCESS",
                "SUDO_EXECUTED"
            ):
                continue

            try:
                event_time = datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                continue

            auth_events[source_ip][
                {
                    "LOGIN_FAILED": "failed",
                    "LOGIN_SUCCESS": "successful",
                    "SUDO_EXECUTED": "sudo"
                }[action]
            ].append((event_time, username))

            mark_event_processed(line)

    # Correlate events for each source IP.
    for ip, events in auth_events.items():

        failed = sorted(events["failed"], key=lambda x: x[0])
        successful = events["successful"]
        sudo = events["sudo"]

        index = 0

        while index < len(failed):

            start_time = failed[index][0]
            window_end = start_time + CORRELATION_WINDOW

            window_failures = [
                event for event in failed
                if start_time <= event[0] <= window_end
            ]

            if len(window_failures) < MIN_FAILED_LOGINS:
                index += 1
                continue

            successful_in_window = [
                event for event in successful
                if start_time <= event[0] <= window_end
            ]

            sudo_in_window = [
                event for event in sudo
                if start_time <= event[0] <= window_end
            ]

            username = window_failures[-1][1]

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
                [event[0] for event in window_failures]
                + [event[0] for event in successful_in_window]
                + [event[0] for event in sudo_in_window]
            )

            result = insert_auth_alert_once(
                latest_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                username,
                severity,
                description,
                start_time,
                window_end
            )
            if result:
                print("\n🚨 SECURITY ALERT")
                print("-------------------------")
                print("Alert Type       : Possible Brute Force")
                print("Source IP        :", ip)
                print("Username         :", username)
                print("Failed Logins    :", len(window_failures))
                print("Successful Login :",
                      "YES" if successful_in_window else "NO")
                print("Sudo Activity    :",
                      "YES" if sudo_in_window else "NO")

            # Move beyond this incident window.
            index = next(
                (
                    i for i, event in enumerate(failed)
                    if event[0] > window_end
                ),
                len(failed)
            )


if __name__ == "__main__":
    main()
