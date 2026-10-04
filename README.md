#  🛡️ AI Security Alert Triage

An AI-assisted Security Operations Center (SOC) project that detects suspicious security activity, correlates authentication events, stores and enriches alerts, maps detections to MITRE ATT&CK techniques, and uses a local LLM to assist analysts during initial alert triage.

The project is designed as a lightweight, locally deployable SOC environment using Python, SQLite, Flask, and Ollama.

  **Important:** The AI is an analyst-assistance component. It does not autonomously make containment or remediation decisions. Final decisions remain with the human analyst.

---

## 📌 Project Overview

Security Operations Centers receive large numbers of alerts that need to be investigated and prioritized.

This project demonstrates a simplified SOC alert-triage workflow:


Security Event
      ↓
Detection
      ↓
Alert Generation
      ↓
SQLite Storage
      ↓
MITRE ATT&CK Mapping
      ↓
AI-Assisted Investigation
      ↓
SOC Dashboard
      ↓
Human Analyst Review




## The main objectives of the project are to:

- Detect suspicious security activity using rule-based detection.
- Correlate related authentication events within a time window.
- Assign alert severity.
- Store alerts in a SQLite database.
- Prevent repeated processing of the same security events.
- Map supported alerts to MITRE ATT&CK techniques.
- Use a local LLM to assist with alert investigation.
- Generate structured findings, risk descriptions, evidence, and recommended actions.
- Provide a web-based SOC dashboard.
- Demonstrate how AI can assist rather than replace a security analyst.


## 🏗️ System Architecture
                  

                     Synthetic Security Logs
                              │
                              ▼
                    ┌────────────────────┐
                    │  Detection Engine  │
                    └─────────┬──────────┘
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
      Authentication      Network            Web
         Detection        Detection        Detection
             │                │                │
             └────────────────┼────────────────┘
                              │
                              ▼
                       SQLite Database
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
          MITRE ATT&CK              AI Investigation
             Mapping                       │
                 │                         │
                 └────────────┬────────────┘
                              ▼
                    Flask SOC Dashboard
                              │
                              ▼
                       Human Analyst




## Architecture notes

The current implementation uses synthetic security logs.

The detection components generate alerts that are stored in SQLite.

MITRE ATT&CK mapping and AI investigation are currently separate enrichment stages operating on the stored alert.

The AI is not treated as the authoritative source for MITRE ATT&CK assignment.

The final alert is presented through the dashboard for human review


## 📥 Data Source

The current implementation uses synthetic security logs generated to simulate security events.

The logs are designed to represent activities such as:

- Authentication failures
- Successful authentication
- Privileged command execution
- Network reconnaissance
- Web application attacks
- Suspicious process execution
- Privilege escalation

Synthetic logs allow the detection pipeline to be tested in a controlled environment without using sensitive production data.

**Future data sources**

Future versions may evaluate the system using public cybersecurity datasets such as:

- CICIDS2017
- UNSW-NB15
- Public Sysmon datasets
- Wazuh-generated security events

These datasets are not currently part of the implemented pipeline.


## 🔍 Detection Capabilities

The project currently supports several security alert types.

Detection Type  	        Description	                               Severity Examples	MITRE ATT&CK
Possible Brute Force	        Detects repeated authentication failures       MEDIUM / HIGH	        T1110
Network Port Scan	        Detects possible network reconnaissance	       MEDIUM	                T1046
SQL Injection Attempt	        Detects possible SQL injection activity	       HIGH			T1190
Suspicious Process Execution	Detects unexpected process execution	       MEDIUM			Unknown - Requires Investigation 
Privilege Escalation	        Detects possible privilege escalation	       HIGH			T1068

- The system currently uses rule-based detection rather than machine-learning-based detection.



## 🔐 Authentication Event Correlation

One of the main detection improvements in the project is time-based authentication event correlation.

The authentication detector uses a five-minute correlation window.

Instead of simply counting failed login attempts throughout the entire log, the detector checks whether related events occur within the same five-minute window.


LOGIN_FAILED
LOGIN_FAILED
LOGIN_FAILED
LOGIN_FAILED
LOGIN_FAILED
       │
       ▼
Within 5 minutes
       │
       ▼
Possible Brute Force
       │
       ├──────────────────┐
       │                  │
       ▼                  ▼
No successful login    Successful login
       │                  │
       ▼                  ▼
    MEDIUM              HIGH
                          │
                          ▼
                    SUDO activity
                          │
                          ▼
                         HIGH



## The current system does not perform cross-source correlation such as:
Port Scan
    ↓
SQL Injection
    ↓
Same Source IP

- Cross-source correlation is a future enhancement.


## 🧠 MITRE ATT&CK Mapping
Possible Brute Force
        ↓
T1110 - Brute Force



Network Port Scan
        ↓
T1046 - Network Service Scanning



SQL Injection Attempt
        ↓
T1190 - Exploit Public-Facing Application



Privilege Escalation
        ↓
T1068 - Exploitation for Privilege Escalation


**If an alert type does not have a defined mapping, the system can return:**
   **Unknown - Requires Investigation**



## 🤖 AI-Assisted Alert Investigation

The project uses a local LLM through Ollama to assist with security alert investigation.

The AI produces structured investigation information including:

- Finding

Explains what the alert may represent.

- Risk

Describes the potential security impact.

- Evidence

Presents the evidence associated with the detection.

- MITRE ATT&CK

Provides a technique when sufficient information or an existing mapping is available.

- Recommended Action

Suggests an investigation or response step for the analyst

**The exact wording generated by the local model may vary.**

**The AI output should be treated as advisory information, not as an authoritative security decision.**




## 🗄️ Database

SQLite is used for local alert storage.

The database stores information including:

- Alert ID
- Timestamp
- Alert type
- Source IP
- Username
- Severity
- Description
- Status
- MITRE ATT&CK technique
- AI analysis

The system also maintains information about processed security events to reduce duplicate event processing.


## 📊 SOC Dashboard

The project includes a Flask-based SOC dashboard.

The dashboard provides visibility into:

- Total alerts
- Alert distribution
- Severity distribution
- Alert ID
- Timestamp
- Alert type
- Source IP
- Username
- Severity
- MITRE ATT&CK technique
- AI analysis
- Alert status

The dashboard allows the analyst to view the results of the detection and enrichment pipeline from a single interface.



## 🔎 Evidence

The system was tested using synthetic security events representing different attack and suspicious-activity scenarios.

Sample Raw Security Events

Example authentication activity:

2026-09-23 09:02:31 | AUTH | 192.168.1.25 | admin | LOGIN_FAILED
2026-09-23 09:02:35 | AUTH | 192.168.1.25 | admin | LOGIN_FAILED
2026-09-23 09:02:39 | AUTH | 192.168.1.25 | admin | LOGIN_FAILED
2026-09-23 09:02:43 | AUTH | 192.168.1.25 | admin | LOGIN_FAILED
2026-09-23 09:02:47 | AUTH | 192.168.1.25 | admin | LOGIN_FAILED
2026-09-23 09:03:02 | AUTH | 192.168.1.25 | admin | LOGIN_SUCCESS
2026-09-23 09:03:15 | SYSTEM | 192.168.1.25 | admin | SUDO_EXECUTED

The detector identifies the related authentication events within the five-minute correlation window

   Detection result:

SECURITY ALERT
-------------------------
Alert Type      : Possible Brute Force
Source IP       : 192.168.1.25
Username        : admin
Failed Logins   : 5
Successful Login: YES
Sudo Activity   : YES
Risk Assessment : HIGH
Correlation     : 5-minute window
Stored in       : SQLite database

---------- AI ANALYSIS ----------
Finding:
Multiple failed login attempts detected.

Risk:
Potential unauthorized access or account compromise.

Evidence:
Multiple failed logins within a 5-minute window followed by successful login and sudo activity.

MITRE ATT&CK:
T1110 - Brute Force

Recommended Action:
Investigate the login activity before taking containment actions.

**The detection engine supplies the underlying alert and evidence, while the AI assists with interpretation and investigation.**



## 📈 Evaluation

The current project has been tested using synthetic security events.

An initial evaluation produced:

- Total alerts: 16
- AI analyzed: 16
- MITRE mapped: 16

Alert Distribution:

- Possible Brute Force          8
- SQL Injection Attempt         3
- Network Port Scan             3
- Suspicious Process Execution  1
- Privilege Escalation          1

Severity Distribution:

- HIGH       10
- MEDIUM      6
- LOW         0


## AI accuracy

A formal AI accuracy evaluation has not yet been performed.

The project therefore does not claim a specific AI accuracy percentage or hallucination rate.

A future evaluation should use a larger labeled dataset, such as 30–50 or more alerts, and manually compare the AI output against expected analyst conclusions.

Possible evaluation metrics include:

- Correct alert interpretation
- Correct evidence usage
- Correct MITRE technique
- Appropriate recommended action
- Unsupported evidence / hallucination rate
- False-positive rate
- False-negative rate
- Analyst triage time


## 🛠️ Technology Stack

Component		Technology
Programming Language	Python
Database		SQLite
Web Framework		Flask
AI Runtime		Ollama
Threat Framework	MITRE ATT&CK
Operating Environment	Linux / Kali Linux
Version Control		Git
Dashboard		Flask + HTML/CSS


## 📁 Project Structure

ai-security-alert-triage/
│
├── ai/
│   └── investigator.py
│
├── dashboard/
│   ├── app.py
│   └── templates/
│       └── dashboard.html
│
├── database/
│   ├── db.py
│   ├── setup_db.py
│   └── view_alerts.py
│
├── detections/
│   ├── detect_auth.py
│   ├── detect_network.py
│   ├── detect_web.py
│   └── mitre_mapping.py
│
├── logs/
│
├── monitor.py
│
├── requirements.txt
│
├── .gitignore
│
└── README.md


## 🔒 Security Considerations

This project is intended for educational, portfolio, and laboratory use.

It should not be considered production-ready without additional security controls.

- Dashboard Authentication

The current Flask dashboard does not implement complete production-grade authentication and authorization.

- Log Injection

An attacker who can control log fields may be able to insert malicious or misleading content into the logs.

- AI Prompt Injection

Security logs can contain attacker-controlled text.

For example, a malicious User-Agent, username, URL parameter, or other field could contain instructions intended to manipulate the AI model.

Therefore, AI output must be treated as untrusted advisory information.

- Sensitive Information

Production security logs may contain:

Usernames
IP addresses
Hostnames
Authentication information
Tokens
Other sensitive information

Real production data should be handled according to appropriate security and privacy requirements.


## ⚠️ Limitations

The current implementation has several limitations:

- Security events are synthetic rather than production-generated.
- Detection rules are primarily rule-based.
- Authentication correlation currently focuses on a five-minute time window.
- Cross-source correlation is not currently implemented.
- MITRE ATT&CK mapping is primarily rule/detection-based.
- AI-generated analysis can be incorrect.
- The local LLM can potentially hallucinate unsupported conclusions.
- Malicious log content could potentially cause AI prompt injection.
- AI-generated recommendations require human verification.
- The Flask dashboard does not currently provide full authentication and authorization.
- SQLite is suitable for this local project but does not provide the scalability of a production SOC database.
- The project has not been evaluated against a large production dataset.
- Formal false-positive and false-negative measurements have not yet been performed.
- Formal AI accuracy and hallucination-rate measurements have not yet been performed.
- The project does not perform autonomous incident containment.


## 🔮 Future Improvements

Possible future improvements include:

Detection:

- Additional authentication detections
- Malware detection
- Suspicious PowerShell activity
- Command injection detection
- Directory traversal detection
- Cross-source event correlation
- More MITRE ATT&CK techniques

Data ingestion:

- Wazuh integration
- Sysmon integration
- Real-time log ingestion
- Public cybersecurity datasets
- Network telemetry integration

AI:

- Rule-based MITRE mapping supplied directly to the AI as context
- Structured AI output validation
- Prompt-injection protection
- Evidence grounding
- Analyst feedback loop
- AI performance evaluation
- Model comparison

Dashboard:

- User authentication
- Role-based access control
- Alert filtering
- Search
- Alert details
- Interactive charts
- Analyst comments
- Alert status updates
- Incident tracking

SOC functionality:

- Threat intelligence integration
- Alert deduplication improvements
- Risk scoring
- Automated notifications
- Incident timelines
- Case management
