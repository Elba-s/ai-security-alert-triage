
import sqlite3
import subprocess
import time
import sys

DATABASE = "database/soc.db"

DETECTORS = [
    "detections/detect_auth.py",
    "detections/detect_network.py",
    "detections/detect_web.py"
]


def run_detectors():
    for detector in DETECTORS:
        print(f"[*] Running {detector}")

        subprocess.run(
            ["python3", detector],
            timeout=60,
            check=True
        )

def run_unknown_event_handler():
    print("[*] Checking for unknown events")

    subprocess.run(
        ["python3", "detections/unknown_event_handler.py"],
        timeout=60,
        check=True
    )

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
        timeout=30,
        check=True
    )


def run_ai_investigator():
    subprocess.run(
        ["python3", "-m", "ai.investigator"],
        timeout=180,
        check=True
    )


def main():

    print("======================================")
    print("       AI SOC ALERT MONITOR")
    print("======================================")
    print("Monitoring for new security events...")
    print("Press Ctrl+C to stop.\n")

    processed_count = 0

    while True:
        try:
            # Detect new events from the security log
            run_detectors()
            run_unknown_event_handler()

            # Process alerts that need enrichment
            alerts = get_pending_alerts()

            if alerts:
                print(f"\n[+] {len(alerts)} alert(s) require processing.")

                run_mitre_mapping()
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
