from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DATABASE = "database/soc.db"


def get_database():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


@app.route("/")
def dashboard():

    db = get_database()

    # ========================================================
    # BASIC STATISTICS
    # ========================================================

    total_alerts = db.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    high_alerts = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'"
    ).fetchone()[0]

    medium_alerts = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'MEDIUM'"
    ).fetchone()[0]

    low_alerts = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'LOW'"
    ).fetchone()[0]


    # ========================================================
    # AI INVESTIGATION STATISTICS
    # ========================================================

    analyzed_alerts = db.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE ai_analysis IS NOT NULL
        """
    ).fetchone()[0]

    pending_ai = db.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE ai_analysis IS NULL
        """
    ).fetchone()[0]


    # ========================================================
    # ALERT TYPE SUMMARY
    # ========================================================

    alert_types = db.execute(
        """
        SELECT alert_type, COUNT(*) AS count
        FROM alerts
        GROUP BY alert_type
        ORDER BY count DESC
        """
    ).fetchall()


    # ========================================================
    # RECENT ALERTS
    # ========================================================

    alerts = db.execute("""
        SELECT
            id,
            timestamp,
            alert_type,
            source_ip,
            username,
            severity,
            mitre_technique,
            ai_analysis,
            status
        FROM alerts
        ORDER BY id DESC
    """).fetchall()


    db.close()


    return render_template(
        "dashboard.html",

        total_alerts=total_alerts,

        high_alerts=high_alerts,

        medium_alerts=medium_alerts,

        low_alerts=low_alerts,

        analyzed_alerts=analyzed_alerts,

        pending_ai=pending_ai,

        alert_types=alert_types,

        alerts=alerts
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
