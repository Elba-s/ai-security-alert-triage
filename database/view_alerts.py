import sqlite3

DATABASE = "database/soc.db"

connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()

cursor.execute("""
    SELECT id, timestamp, alert_type, source_ip,
           username, severity, description, status
    FROM alerts
    ORDER BY id
""")

alerts = cursor.fetchall()

if not alerts:
    print("No alerts found.")

else:
    print("\n========== SOC ALERT DATABASE ==========\n")

    for alert in alerts:
        print(f"Alert ID     : {alert[0]}")
        print(f"Timestamp    : {alert[1]}")
        print(f"Alert Type   : {alert[2]}")
        print(f"Source IP    : {alert[3]}")
        print(f"Username     : {alert[4]}")
        print(f"Severity     : {alert[5]}")
        print(f"Description  : {alert[6]}")
        print(f"Status       : {alert[7]}")
        print("----------------------------------------")

connection.close()
