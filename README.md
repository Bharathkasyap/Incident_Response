# 📘 Incident Handler Reference Guide

> **Purpose:** This GitHub page is designed to be a comprehensive and beginner-friendly reference for anyone involved in **Incident Response (IR)**. It follows best practices, frameworks like **NIST SP 800-61**, real-world attack types, and hands-on detection methods.

---

## 📚 Table of Contents

1. [What is Incident Response (IR)?](#what-is-incident-response-ir)
2. [Why Incident Response Matters](#why-incident-response-matters)
3. [Incident Response Lifecycle (NIST SP 800-61)](#incident-response-lifecycle-nist-sp-800-61)
4. [Detailed Explanation of Each IR Phase](#detailed-explanation-of-each-ir-phase)
5. [Roles and Responsibilities in IR](#roles-and-responsibilities-in-ir)
6. [Common Attacks and Response Playbooks](#common-attacks-and-response-playbooks)
7. [KQL Queries Used in IR (Microsoft Sentinel)](#kql-queries-used-in-ir)
8. [Incident Report Writing Guide](#incident-report-writing-guide)
9. [MITRE ATT&CK Mappings](#mitre-attck-mappings)
10. [Authority & Escalation Flow](#authority--escalation-flow)
11. [External References & Public Docs](#external-references--public-docs)

---

## 🧠 What is Incident Response (IR)?

**Incident Response** is a structured methodology for handling security incidents, breaches, and cyber threats. It helps minimize damage, reduce recovery time and cost, and prevent future incidents.

---

## 🎯 Why Incident Response Matters

- Prevents loss of sensitive data.
- Ensures business continuity.
- Helps in legal and regulatory compliance.
- Builds trust with customers and stakeholders.

---

## 🔄 Incident Response Lifecycle (NIST SP 800-61)

NIST SP 800-61 defines the **four key phases**:

| Phase             | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| Preparation       | Planning, team setup, training, tool selection.                            |
| Detection & Analysis | Identifying suspicious activity and analyzing severity.                     |
| Containment, Eradication & Recovery | Stopping the threat, cleaning infected systems, and restoring systems. |
| Post-Incident Activity | Learning, documenting, and improving processes.                        |

---

## 🔍 Detailed Explanation of Each IR Phase

### 📌 1. Preparation
- Define policies & roles
- Establish communication plans
- Set up detection systems (SIEM, IDS/IPS)

### 📌 2. Detection and Analysis
- Use logs, EDR tools, firewall alerts, and SIEM to detect anomalies
- Classify severity (Low, Medium, High, Critical)
- Validate incident legitimacy

### 📌 3. Containment, Eradication, Recovery
- Short-term containment (isolate infected machine)
- Eradicate malware or threat actor’s access
- Restore from clean backups

### 📌 4. Post-Incident Activity
- Conduct lessons learned meeting
- Update playbooks and controls
- Create final incident report

---

## 👥 Roles and Responsibilities in IR

| Role                  | Duties                                                                 |
|-----------------------|------------------------------------------------------------------------|
| Incident Handler      | Coordinates the response process.                                     |
| SOC Analyst           | Monitors alerts, performs triage.                                     |
| Threat Hunter         | Proactively searches for hidden threats.                              |
| Forensic Analyst      | Extracts evidence from systems and logs.                              |
| Management/CIO        | Makes high-level decisions, approves actions.                         |
| Legal/Compliance Team| Ensures response complies with law.                                   |

---

## 🛡️ Common Attacks and Response Playbooks

<details>
  <summary><strong>Brute Force Attack</strong></summary>

  - **Detection:** Multiple failed login attempts in short time
  - **KQL Query:**

    ```kusto
    DeviceLogonEvents
    | where ActionType == "LogonFailed"
    | summarize count() by AccountName, RemoteIP
    | order by count_ desc
    ```

  - **Action List:**
    - Lock affected accounts
    - Notify user
    - Check for successful logins from same IP
    - Apply rate limits or MFA

</details>

<details>
  <summary><strong>Phishing Email</strong></summary>

  - **Detection:** Email contains suspicious links or file attachments
  - **Action List:**
    - Block sender domain
    - Extract IOCs and check logs
    - Check for user click activity
    - Notify affected users

</details>

<details>
  <summary><strong>Ransomware</strong></summary>

  - **Detection:** Files renamed/encrypted, ransom note drops
  - **Action List:**
    - Isolate affected systems
    - Check for lateral movement
    - Backup analysis
    - Engage legal/compliance immediately

</details>

---

## 📊 KQL Queries Used in IR

| Purpose              | KQL Snippet                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| Failed Logons        | `DeviceLogonEvents | where ActionType == "LogonFailed"`                   |
| Suspicious File Drop | `DeviceFileEvents | where FileName endswith ".exe" and FolderPath has "Temp"` |
| Remote Access Use    | `DeviceNetworkEvents | where RemoteIP != "" and Protocol == "RDP"`         |

---

## 📝 Incident Report Writing Guide

- **Executive Summary:** What happened, when, and who is affected.
- **Technical Details:** Timeline, affected systems, attack vector.
- **IOC Summary:** IPs, Hashes, Domains.
- **Actions Taken:** Containment steps, recovery procedures.
- **Lessons Learned:** Gaps identified, improvements needed.

---

## 🎯 MITRE ATT&CK Mappings

| Phase               | Example Technique        | Tactic              | MITRE ID   |
|---------------------|--------------------------|---------------------|------------|
| Initial Access       | Spearphishing Attachment | Initial Access      | T1566.001  |
| Execution            | PowerShell               | Execution           | T1059.001  |
| Persistence          | Registry Run Keys        | Persistence         | T1547.001  |
| Defense Evasion      | Obfuscated Files/Scripts | Defense Evasion     | T1027      |
| Exfiltration         | Exfiltration Over HTTPS  | Exfiltration        | T1041      |

---

## 🧾 Authority & Escalation Flow

| Action Needed                  | Role to Approve             |
|-------------------------------|------------------------------|
| System Isolation              | IR Lead / SOC Manager        |
| Data Wipe / Restoration       | CISO / IT Manager            |
| Legal Disclosure              | Legal / Compliance Officer   |
| Communication to Customers    | PR / Legal / Management      |

---

## 🔗 External References & Public Docs

| Source               | Link                                                              |
|----------------------|-------------------------------------------------------------------|
| NIST SP 800-61       | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf |
| CISA IR Guidance     | https://www.cisa.gov/sites/default/files/publications/incident_handling_guidelines.pdf |
| MITRE ATT&CK         | https://attack.mitre.org/                                          |
| SANS IR Cheat Sheet  | https://www.sans.org/posters/incident-response-cheat-sheet/        |

---

> 📌 **Feel free to contribute**: Pull requests are welcome to add more attack types, queries, or frameworks.

> 🛠️ Maintained by: Bharath Kasyap | Cybersecurity Analyst
