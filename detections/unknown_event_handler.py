import sys
sys.path.append(".")

import sqlite3

from database.db import (
    DATABASE,
    is_event_processed,
    mark_event_processed,
    get_event_hash
)

LOG_FILE = "logs/security.log"

KNOWN_ACTIONS = {
    "LOGIN_FAILED",
    "LOGIN_SUCCESS",
    "SUDO_EXECUTED",
    "PORT_SCAN",
    "SQL_INJECTION_ATTEMPT"
}


def setup_table():
    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS unclassified_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                source_ip TEXT,
                username TEXT,
                action TEXT,
                raw_event TEXT NOT NULL,
                classification TEXT NOT NULL,
                event_hash TEXT UNIQUE
            )
        """)


def store_event(raw_event, parts, classification):
    values = (parts + ["Unknown"] * 5)[:5]
    timestamp, event_type, source_ip, username, action = values

    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            INSERT OR IGNORE INTO unclassified_events
            (timestamp, event_type, source_ip, username,
             action, raw_event, classification, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            event_type,
            source_ip,
            username,
            action,
            raw_event,
            classification,
            get_event_hash(raw_event)
        ))


def main():
    setup_table()
    processed = 0

    with open(LOG_FILE, "r") as file:
        for line in file:
            raw_event = line.strip()

            if not raw_event:
                continue

            event_hash = get_event_hash(raw_event)

            with sqlite3.connect(DATABASE) as connection:
                exists = connection.execute("""
                    SELECT 1 FROM unclassified_events
                    WHERE event_hash = ?
                """, (event_hash,)).fetchone()

            if exists:
                continue

            parts = [part.strip() for part in raw_event.split("|")]

            if len(parts) != 5:
                classification = "INVALID"
            elif parts[4] not in KNOWN_ACTIONS:
                classification = "UNCLASSIFIED"
            else:
                continue

            store_event(raw_event, parts, classification)

            mark_event_processed(raw_event)
            processed += 1

    print(f"[+] Unknown event handler stored {processed} event(s).")

if __name__ == "__main__":
    main()
