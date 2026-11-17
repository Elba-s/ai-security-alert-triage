import sqlite3
import subprocess
import re

DATABASE = "database/soc.db"


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

MITRE_MAP = {
    "Possible Brute Force":
        "T1110 - Brute Force",

    "Network Port Scan":
        "T1046 - Network Service Scanning",

    "SQL Injection Attempt":
        "T1190 - Exploit Public-Facing Application",

    "Suspicious Login":
        "T1078 - Valid Accounts",

    "Unauthorized Access":
        "T1078 - Valid Accounts",

    "Privilege Escalation":
        "T1068 - Exploitation for Privilege Escalation",

    "Command Injection":
        "T1059 - Command and Scripting Interpreter",

    "Malware Detection":
        "T1204.002 - User Execution: Malicious File",

    "Directory Traversal":
        "T1190 - Exploit Public-Facing Application",

    "XSS Attempt":
        "T1189 - Drive-by Compromise"
}


# ============================================================
# GET UNANALYZED ALERTS
# ============================================================

def get_unanalyzed_alerts():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id,
               timestamp,
               alert_type,
               source_ip,
               username,
               severity,
               description
        FROM alerts
        WHERE ai_analysis IS NULL
        ORDER BY id ASC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


# ============================================================
# CLEAN AI OUTPUT
# ============================================================

def clean_output(output):

    # Remove ANSI terminal escape sequences
    output = re.sub(
        r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])',
        '',
        output
    )

    # Remove Qwen thinking section
    if "...done thinking..." in output:

        output = output.split(
            "...done thinking...",
            1
        )[1].strip()

    # Remove <think>...</think>
    output = re.sub(
        r'<think>.*?</think>',
        '',
        output,
        flags=re.IGNORECASE | re.DOTALL
    )

    # Remove accidental Rules section
    output = re.split(
        r'(?i)\bRules\s*:',
        output,
        maxsplit=1
    )[0].strip()

    return output.strip()


# ============================================================
# EXTRACT ONE AI SECTION
# ============================================================

def get_section(text, section_name, next_sections):

    next_pattern = "|".join(
        re.escape(section)
        for section in next_sections
    )

    pattern = (
        rf'(?im)^\s*{re.escape(section_name)}\s*:\s*'
        rf'(.*?)'
        rf'(?=^\s*(?:{next_pattern})\s*:|\Z)'
    )

    match = re.search(
        pattern,
        text,
        re.DOTALL
    )

    if not match:
        return ""

    value = match.group(1).strip()

    # Remove accidental repeated labels
    value = re.sub(
        r'^\s*(Finding|Risk|Evidence|Recommended Action|Rules)\s*:\s*',
        '',
        value,
        flags=re.IGNORECASE
    )

    return value.strip()


# ============================================================
# AI ANALYSIS
# ============================================================

def analyze_alert(alert):

    (
        alert_id,
        timestamp,
        alert_type,
        source_ip,
        username,
        severity,
        description
    ) = alert


    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    mitre_technique = MITRE_MAP.get(
        alert_type,
        "Insufficient evidence"
    )


    # --------------------------------------------------------
    # AI PROMPT
    # --------------------------------------------------------

    prompt = f"""
Analyze this security alert.

Alert Type: {alert_type}
Source IP: {source_ip}
Username: {username}
Severity: {severity}
Evidence: {description}

Return exactly four short sections:

Finding:
Risk:
Evidence:
Recommended Action:

Do not provide reasoning.
Do not provide MITRE ATT&CK.
Do not add any extra sections.
Use only the supplied evidence.
Recommend investigation before containment.
Keep each section to one short sentence.
"""


    # --------------------------------------------------------
    # RUN OLLAMA
    # --------------------------------------------------------

    try:

        result = subprocess.run(
            [
                "ollama",
                "run",
                "qwen3:0.6b",
                "--think=false",
                prompt
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

    except subprocess.TimeoutExpired:

        result = None


    # --------------------------------------------------------
    # GET AI OUTPUT
    # --------------------------------------------------------

    if result is not None and result.returncode == 0:

        output = clean_output(
            result.stdout
        )

    else:

        output = ""


    # Extra protection against Rules being displayed
    output = re.split(
        r'(?i)\bRules\s*:',
        output,
        maxsplit=1
    )[0].strip()


    # ========================================================
    # EXTRACT AI SECTIONS
    # ========================================================

    finding = get_section(
        output,
        "Finding",
        [
            "Risk",
            "Evidence",
            "Recommended Action"
        ]
    )

    risk = get_section(
        output,
        "Risk",
        [
            "Finding",
            "Evidence",
            "Recommended Action"
        ]
    )

    evidence = get_section(
        output,
        "Evidence",
        [
            "Finding",
            "Risk",
            "Recommended Action"
        ]
    )

    action = get_section(
        output,
        "Recommended Action",
        [
            "Finding",
            "Risk",
            "Evidence"
        ]
    )


    # ========================================================
    # FINDING FALLBACKS
    # ========================================================

    finding_map = {

        "Possible Brute Force":
            "Multiple failed login attempts detected.",

        "Network Port Scan":
            "Multiple network ports detected during scanning activity.",

        "SQL Injection Attempt":
            "Possible SQL injection attempt detected against a web application.",

        "Privilege Escalation":
            "Possible privilege escalation activity detected.",

        "Suspicious Process Execution":
            "Unexpected process execution detected."

    }

    if not finding:
        finding = finding_map.get(
            alert_type,
            "Investigate the alert and collect additional evidence before containment."
        )

    # ========================================================
    # RISK FALLBACKS
    # ========================================================

    if not risk:

        risk_map = {

            "Possible Brute Force":
                "Potential unauthorized access or account compromise.",

            "Network Port Scan":
                "Potential network reconnaissance activity.",

            "SQL Injection Attempt":
                "Potential unauthorized database access or data exposure.",

            "Suspicious Login":
                "Potential unauthorized account access.",

            "Unauthorized Access":
                "Potential compromise of a user or system account.",

            "Privilege Escalation":
                "Potential unauthorized access to higher privileges.",

            "Command Injection":
                "Potential unauthorized command execution.",

            "Malware Detection":
                "Potential system compromise or malicious activity.",

            "Directory Traversal":
                "Potential unauthorized access to application files.",

            "XSS Attempt":
                "Potential client-side code execution or user-session compromise."
        }

        risk = risk_map.get(
            alert_type,
            f"{severity} severity security alert requiring investigation."
        )


    # ========================================================
    # EVIDENCE FALLBACK
    # ========================================================
    # Always use the original detection evidence.
    # Do not allow the small AI model to invent or
    # replace the actual evidence.

    evidence = description

    # ========================================================
    # RECOMMENDED ACTION FALLBACKS
    # ========================================================

    if not action:

        action_map = {

            "Possible Brute Force":
                "Investigate the login activity before taking containment actions.",

            "Network Port Scan":
                "Investigate the source activity and determine whether the scanning is authorized.",

            "SQL Injection Attempt":
                "Investigate the request and review the affected application's input validation.",

            "Suspicious Login":
                "Investigate the login activity and verify whether the account activity is legitimate.",

            "Unauthorized Access":
                "Investigate the access activity and verify the legitimacy of the account.",

            "Privilege Escalation":
                "Investigate the activity and review recent privilege changes.",

            "Command Injection":
                "Investigate the request and review command execution logs.",

            "Malware Detection":
                "Investigate the affected system and verify the detected activity.",

            "Directory Traversal":
                "Investigate the request and review application access controls.",

            "XSS Attempt":
                "Investigate the request and review the application's input handling."
        }

        action = action_map.get(
            alert_type,
            "Investigate the activity before taking containment actions."
        )


    # ========================================================
    # CLEAN FINAL VALUES
    # ========================================================

    finding = " ".join(
        finding.split()
    )

    risk = " ".join(
        risk.split()
    )

    evidence = " ".join(
        evidence.split()
    )

    action = " ".join(
        action.split()
    )


    # ========================================================
    # FINAL STANDARD FORMAT
    # ========================================================

    final_output = f"""Finding:
{finding}

Risk:
{risk}

Evidence:
{evidence}

MITRE ATT&CK:
{mitre_technique}

Recommended Action:
{action}"""


    return final_output

# ============================================================
# GROUNDING VERIFIER
# ============================================================

def verify_grounding(analysis, description):
       # Deterministic check: detect invented usernames.
    usernames = re.findall(
        r"\b(?:user|username)\s+([A-Za-z][A-Za-z0-9_.-]*)",
        analysis,
        re.IGNORECASE
    )

    for username in usernames:
        if username.lower() not in description.lower():
            print(f"Unsupported username detected: {username}")
            return "UNGROUNDED"
        # Deterministic check: detect unsupported confirmed attack claims.
    confirmed_attack_patterns = [
        r"\bbrute force attack in progress\b",
        r"\bconfirmed brute force attack\b",
        r"\bsuccessful account compromise\b",
        r"\battacker successfully accessed\b",
        r"\bdata exfiltration confirmed\b"
    ]

    evidence_lower = description.lower()
    analysis_lower = analysis.lower()

    for pattern in confirmed_attack_patterns:
        if re.search(pattern, analysis_lower):
            if not re.search(pattern, evidence_lower):
                print("Unsupported confirmed attack claim detected.")
                return "UNGROUNDED"
    prompt = f"""
You are a cybersecurity evidence-grounding auditor.

Compare the AI investigation with the original alert evidence.

ORIGINAL EVIDENCE:
{description}

AI INVESTIGATION:
{analysis}

CLASSIFICATION RULES:

1. GROUNDED:
   - Factual claims are supported by the original evidence.
   - Reasonable security interpretations are allowed when
     expressed cautiously using words like possible or potential.
   - Recommendations do not need to be directly present in the evidence.
   - The investigation does not contradict the original evidence.

2. UNGROUNDED:
   - The investigation invents usernames, IP addresses,
     timestamps, event counts, commands or other specific details.
   - It claims an event occurred when the evidence does not support it.
   - It presents an unconfirmed attack or consequence as a confirmed fact.
   - It contradicts the original evidence.

3. NO CHECKABLE CLAIMS:
   - The investigation contains no meaningful factual claims
     that can be compared with the evidence.
   - It contains only generic recommendations or vague statements.

IMPORTANT DISTINCTIONS:

- "Potential account compromise" is a qualified risk,
  not a claim that compromise definitely happened.
- "Account compromise confirmed" requires supporting evidence.
- "Possible privilege escalation" can be a reasonable
  interpretation of unexpected privileged command execution.
- A username or IP address must never be invented.
- A recommendation such as "investigate the login activity"
  is not an unsupported factual claim.
- Missing details alone do not make an investigation ungrounded.
- If at least one important factual claim is unsupported,
  classify the investigation as UNGROUNDED.

EXAMPLES:

Evidence: Four failed SSH login attempts.
Investigation: Four failed SSH login attempts were detected.
Answer: GROUNDED

Evidence: Four failed SSH login attempts.
Investigation: The attacker successfully accessed root.
Answer: UNGROUNDED

Evidence: Multiple failed login attempts detected.
Investigation: Multiple failed login attempts detected for user admin.
Answer: UNGROUNDED

Evidence: Unexpected privileged command execution detected.
Investigation: Possible privilege escalation activity detected.
Answer: GROUNDED

Evidence: Multiple failed logins followed by successful login.
Investigation: Potential account compromise.
Answer: GROUNDED

Evidence: Security event recorded.
Investigation: Further investigation is recommended.
Answer: NO CHECKABLE CLAIMS

Return exactly ONE of these verdicts:

GROUNDED
UNGROUNDED
NO CHECKABLE CLAIMS

Do not provide explanations.
"""

    try:
        result = subprocess.run(
            [
                "ollama",
                "run",
                "qwen3:0.6b",
                "--think=false",
                prompt
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

    except (subprocess.TimeoutExpired, OSError):
        return "NO CHECKABLE CLAIMS"

    if result.returncode != 0:
        return "NO CHECKABLE CLAIMS"

    verdict = clean_output(result.stdout).strip().upper()

    allowed_verdicts = {
        "GROUNDED",
        "UNGROUNDED",
        "NO CHECKABLE CLAIMS"
    }

    if verdict not in allowed_verdicts:
        return "NO CHECKABLE CLAIMS"

    return verdict


# ============================================================
# SAVE ANALYSIS
# ============================================================

def save_analysis(alert_id, analysis, alert_type, description):

    connection = sqlite3.connect(DATABASE)

    try:
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE alerts
            SET ai_analysis = ?
            WHERE id = ?
        """, (
            analysis,
            alert_id
        ))

        connection.commit()

    finally:
        connection.close()



# ============================================================
# MAIN
# ============================================================

def main():

    alerts = get_unanalyzed_alerts()


    if not alerts:

        print(
            "No unanalyzed alerts found."
        )

        return


    print(
        f"\nFound {len(alerts)} "
        f"unanalyzed alert(s).\n"
    )


    processed = 0


    for alert in alerts:

        (
            alert_id,
            timestamp,
            alert_type,
            source_ip,
            username,
            severity,
            description
        ) = alert


        print("=" * 60)

        print(
            "AI SOC INVESTIGATION"
        )

        print("=" * 60)

        print(
            f"Alert ID    : {alert_id}"
        )

        print(
            f"Alert Type  : {alert_type}"
        )

        print(
            f"Severity    : {severity}"
        )

        print(
            f"Source IP   : {source_ip}"
        )

        print(
            "\n---------- AI ANALYSIS ----------\n"
        )


        try:

            analysis = analyze_alert(
                alert
            )

            print(
                analysis
            )


            save_analysis(
                alert_id,
                analysis,
		alert_type,
		description
            )


            print(
                "\n✓ Analysis saved to database.\n"
            )


            processed += 1


        except Exception as error:

            print(
                f"\nError processing "
                f"alert {alert_id}: {error}"
            )

            print(
                "Alert was not marked as analyzed.\n"
            )


    print("=" * 60)

    print(
        f"Processing complete. "
        f"Total processed this session: "
        f"{processed}"
    )

    print("=" * 60)


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    main()
