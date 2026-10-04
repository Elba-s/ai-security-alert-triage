import sqlite3

DATABASE = "database/soc.db"

connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    alert_type TEXT,
    source_ip TEXT,
    username TEXT,
    severity TEXT,
    description TEXT,
    status TEXT DEFAULT 'NEW'
)
""")

connection.commit()
connection.close()

print("SOC database created successfully.")
