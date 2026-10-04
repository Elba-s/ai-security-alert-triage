import sqlite3
import subprocess
import time

DATABASE = "database/soc.db"


def get_pending_alerts():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE ai_analysis IS NULL
           OR mitre_technique IS NULL
        ORDER BY id ASC
    """)

    alerts = cursor.fetchall()
    connection.close()

    return alerts


def run_mitre_mapping():
    subprocess.run(
        ["python3", "detections/mitre_mapping.py"],
        timeout=30
    )


def run_ai_investigator():
    subprocess.run(
        ["python3", "ai/investigator.py"],
        timeout=180
    )


def main():

    print("======================================")
    print("       AI SOC ALERT MONITOR")
    print("======================================")
    print("Monitoring for new alerts...")
    print("Press Ctrl+C to stop.\n")

    processed_count = 0

    while True:

        try:

            alerts = get_pending_alerts()

            if alerts:

                print(f"[+] {len(alerts)} alert(s) require processing.")

                # Add MITRE enrichment
                run_mitre_mapping()

                # Run AI investigation
                run_ai_investigator()

                processed_count += len(alerts)

                print(
                    f"[+] Processing complete. "
                    f"Total processed this session: {processed_count}\n"
                )

            time.sleep(10)

        except KeyboardInterrupt:

            print("\n[*] SOC monitor stopped.")
            break

        except Exception as error:

            print(f"[!] Monitor error: {error}")
            print("[*] Retrying in 10 seconds...\n")

            time.sleep(10)


if __name__ == "__main__":
    main()
