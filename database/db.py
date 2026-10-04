import sqlite3
import hashlib

DATABASE = "database/soc.db"


def get_event_hash(event_line):
    """
    Create a unique hash for one security-log line.
    """
    return hashlib.sha256(
        event_line.strip().encode()
    ).hexdigest()


def is_event_processed(event_line):

    event_hash = get_event_hash(event_line)

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM processed_events
        WHERE event_hash = ?
    """, (event_hash,))

    result = cursor.fetchone()

    connection.close()

    return result is not None


def mark_event_processed(event_line):

    event_hash = get_event_hash(event_line)

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO processed_events
        (event_hash)
        VALUES (?)
    """, (event_hash,))

    connection.commit()
    connection.close()


def insert_alert(timestamp, alert_type, source_ip, username,
                 severity, description):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts
        (timestamp, alert_type, source_ip, username, severity, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        alert_type,
        source_ip,
        username,
        severity,
        description
    ))

    connection.commit()
    connection.close()

    return True
