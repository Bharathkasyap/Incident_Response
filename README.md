# 📘 Incident Handler Reference Guide

> **Purpose:** This GitHub page is a comprehensive, beginner-friendly, and operational **one-stop resource** for any professional working in **Incident Response (IR)**. It follows frameworks like **NIST SP 800-61**, covers attack types, roles, immediate actions, KQL queries, and reporting—all in one place.

---

## 📚 Table of Contents

1. [What is Incident Response (IR)?](#what-is-incident-response-ir)
2. [Why Incident Response Matters](#why-incident-response-matters)
3. [Incident Response Lifecycle (NIST SP 800-61)](#incident-response-lifecycle-nist-sp-800-61)
4. [Detailed Lifecycle Phases Explained](#detailed-lifecycle-phases-explained)
5. [Roles & Permissions in Incident Response](#roles--permissions-in-incident-response)
6. [Attack Scenarios & Actionable Playbooks](#attack-scenarios--actionable-playbooks)
7. [🔍 100+ KQL Queries for Incident Detection & Response](#100-kql-queries-for-incident-detection--response)
8. [Incident Response Report Writing](#incident-response-report-writing)
9. [Authority Flow & Communication Chain](#authority-flow--communication-chain)
10. [MITRE ATT&CK Framework Mapping](#mitre-attck-framework-mapping)
11. [External References & Cheat Sheets](#external-references--cheat-sheets)

---

## 🧠 What is Incident Response (IR)?

**Incident Response (IR)** is a structured set of procedures for identifying, managing, and recovering from security incidents. IR minimizes damage, reduces recovery time and costs, and helps organizations comply with regulations.

---

## 🎯 Why Incident Response Matters

- Prevents data breaches and minimizes downtime
- Ensures rapid containment of threats
- Helps comply with standards (GDPR, HIPAA, PCI-DSS)
- Increases customer and stakeholder trust

---

## 🔄 Incident Response Lifecycle (NIST SP 800-61)

| Phase             | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| **Preparation**       | Planning, policies, tools, roles, and playbooks setup                     |
| **Detection & Analysis** | Identifying indicators of compromise and validating the incident         |
| **Containment, Eradication & Recovery** | Stop spread, remove threat, restore to safe state              |
| **Post-Incident Activity** | Debriefing, documentation, updates to policy & infrastructure         |

---

## 🧩 Detailed Lifecycle Phases Explained

### 1. **Preparation**
- Define policies, scope, incident types
- Set up monitoring (EDR, SIEM, IDS/IPS)
- Conduct table-top exercises
- Train SOC teams
- Set logging and retention standards

### 2. **Detection & Analysis**
- Use alerts/logs from MDE, SIEM, firewall, antivirus
- Identify anomalies and validate against known IOCs
- Triage and classify incident (severity & scope)
- Determine affected users, assets, data

### 3. **Containment, Eradication & Recovery**
- Short-term: isolate device/network segment
- Long-term: deploy patches, reset credentials
- Eradicate persistence (scripts, registry, accounts)
- Recover via backup restore or gold image deployment

### 4. **Post-Incident Activity**
- Conduct lessons-learned review with all teams
- Update detection rules and playbooks
- Notify stakeholders
- Improve logging or control gaps

---

## 👥 Roles & Permissions in Incident Response

| Role                  | Responsibilities                                                                 |
|-----------------------|----------------------------------------------------------------------------------|
| SOC Tier 1 Analyst    | Initial alert triage, noise filtering                                            |
| SOC Tier 2 Analyst    | Deep analysis, pattern recognition, pivoting                                     |
| Incident Handler (IR Lead) | Coordinates actions, communications, and escalation flow                      |
| Forensic Investigator | Acquires disk/memory images, analyzes malware                                    |
| Threat Hunter         | Looks for advanced persistent threats not yet flagged                           |
| IT Ops/Network Admin  | Executes containment like port blocking, patching, or isolating systems         |
| HR/Legal/Compliance   | Handles breach reporting, user accountability, law requirements                 |
| Executive Management  | Provides approval for high-impact decisions and external communication          |

---

## 🛡️ Attack Scenarios & Actionable Playbooks

Each collapsible section below shows immediate actions, who is involved, escalation triggers, and MITRE techniques.

<details>
<summary><strong>💥 Brute Force Attack</strong></summary>

- **Who is Involved**: SOC Analyst, IR Lead, AD Admin
- **Immediate Actions**:
  - Search failed login attempts (source IP)
  - Lock account or enforce MFA
  - Block IP if attack persists
- **KQL Query**:
  ```kusto
  DeviceLogonEvents
  | where ActionType == "LogonFailed"
  | summarize Failures = count() by AccountName, RemoteIP
  | order by Failures desc
  ```
- **MITRE ATT&CK**: T1110 – Brute Force

</details>

<details>
<summary><strong>🎣 Phishing Email</strong></summary>

- **Who is Involved**: Email Admin, SOC, IR Lead
- **Immediate Actions**:
  - Isolate affected user inbox
  - Extract URLs/attachments and sandbox them
  - Block sender domain
- **KQL Query**:
  ```kusto
  EmailEvents
  | where Subject has_any ("Reset Password", "Account Locked")
  ```
- **MITRE ATT&CK**: T1566 – Phishing

</details>

_(Add 20+ more playbooks similarly — will be added in future updates)_

---

## 🔍 100+ KQL Queries for Incident Detection & Response
# 🔍 100 KQL Queries for Incident Response

This section provides a categorized cheat sheet of 100 Microsoft Sentinel (KQL) queries to support real-world detection during incident response investigations. Copy and paste any of these directly into your Log Analytics or Sentinel environment.

---

| **Category**             | **Query Title**                          | **KQL Query** |
|--------------------------|-------------------------------------------|---------------|
| **Account Compromise**   | **Failed Logon Attempts**                | `DeviceLogonEvents \| where ActionType == "LogonFailed" \| summarize count() by AccountName` |
|                          | **Multiple Logins from Different Locations** | `SigninLogs \| summarize by Account, Location, bin(TimeGenerated, 1h)` |
|                          | **Password Spray Detection**             | `DeviceLogonEvents \| where AccountName in ("admin", "administrator") \| summarize count() by RemoteIP` |
---

| **Lateral Movement**     | **RDP Access**                           | `DeviceNetworkEvents \| where RemotePort == 3389` |
|                          | **Admin Share Access**                   | `DeviceNetworkEvents \| where RemotePort == 445` |
|                          | **Unusual SMB Traffic**                  | `DeviceNetworkEvents \| where RemotePort == 445 and InitiatingProcessFileName != "System"` |
---

| **Persistence**          | **Registry Run Keys**                    | `DeviceRegistryEvents \| where RegistryKey has "Run" and ActionType == "RegistryValueSet"` |
|                          | **Scheduled Tasks Created**              | `DeviceProcessEvents \| where ProcessCommandLine has "schtasks"` |
|                          | **WMI Persistence**                      | `DeviceProcessEvents \| where ProcessCommandLine has "wmic"` |
---

| **Privilege Escalation** | **New Local Admins**                     | `DeviceEvents \| where ActionType == "UserAddedToAdminGroup"` |
|                          | **Token Impersonation**                  | `DeviceProcessEvents \| where ProcessCommandLine has "Invoke-TokenManipulation"` |
|                          | **Use of PsExec**                        | `DeviceProcessEvents \| where FileName == "PsExec.exe"` |
---

| **Defense Evasion**      | **AV Disabled**                          | `DeviceEvents \| where ActionType has "AntivirusDisabled"` |
|                          | **Script Obfuscation**                   | `DeviceProcessEvents \| where ProcessCommandLine has_any("FromBase64String", "Invoke-Expression")` |
|                          | **Use of regsvr32**                      | `DeviceProcessEvents \| where FileName == "regsvr32.exe"` |
---

| **Execution**            | **Suspicious PowerShell Commands**       | `DeviceProcessEvents \| where FileName == "powershell.exe" and ProcessCommandLine has_any("-enc", "Invoke-WebRequest")` |
|                          | **Malicious Office Macros**              | `DeviceProcessEvents \| where InitiatingProcessFileName endswith ".docm"` |
|                          | **Encoded Command Line**                 | `DeviceProcessEvents \| where ProcessCommandLine has "-enc"` |
---

| **Command & Control (C2)**| **DNS Tunneling**                       | `DeviceNetworkEvents \| where RemoteUrl contains ".xyz"` |
|                          | **Unusual Beaconing**                    | `DeviceNetworkEvents \| summarize count() by RemoteIP, bin(Timestamp, 1h)` |
|                          | **Long Domain Chains**                   | `DeviceEvents \| where RemoteUrl contains ".co." and strlen(RemoteUrl) > 100` |
---

| **Data Exfiltration**    | **Large Data Transfer**                  | `DeviceNetworkEvents \| where Protocol == "HTTPS" \| summarize sum(SentBytes) by RemoteIP` |
|                          | **Cloud Upload Detected**                | `DeviceNetworkEvents \| where RemoteUrl has_any("drive.google.com", "dropbox.com")` |
|                          | **File Copy to USB**                     | `DeviceEvents \| where ActionType == "UsbFileCopy"` |
---

| **Account Compromise**   | **Failed Logon Attempts (Repeated)**     | `DeviceLogonEvents \| where ActionType == "LogonFailed" \| summarize count() by AccountName` |
|                          | **Multiple Logins from Different Locations (Repeated)** | `SigninLogs \| summarize by Account, Location, bin(TimeGenerated, 1h)` |
|                          | **Password Spray Detection (Repeated)**  | `DeviceLogonEvents \| where AccountName in ("admin", "administrator") \| summarize count() by RemoteIP` |
---

| **Lateral Movement**     | **RDP Access (Repeated)**                | `DeviceNetworkEvents \| where RemotePort == 3389` |
|                          | **Admin Share Access (Repeated)**        | `DeviceNetworkEvents \| where RemotePort == 445` |
|                          | **Unusual SMB Traffic (Repeated)**       | `DeviceNetworkEvents \| where RemotePort == 445 and InitiatingProcessFileName != "System"` |
---

| **Persistence**          | **Registry Run Keys (Repeated)**         | `DeviceRegistryEvents \| where RegistryKey has "Run" and ActionType == "RegistryValueSet"` |
|                          | **Scheduled Tasks Created (Repeated)**   | `DeviceProcessEvents \| where ProcessCommandLine has "schtasks"` |
|                          | **WMI Persistence (Repeated)**           | `DeviceProcessEvents \| where ProcessCommandLine has "wmic"` |
---

| **Privilege Escalation** | **New Local Admins (Repeated)**          | `DeviceEvents \| where ActionType == "UserAddedToAdminGroup"` |
|                          | **Token Impersonation (Repeated)**       | `DeviceProcessEvents \| where ProcessCommandLine has "Invoke-TokenManipulation"` |
|                          | **Use of PsExec (Repeated)**             | `DeviceProcessEvents \| where FileName == "PsExec.exe"` |
---

| **Defense Evasion**      | **AV Disabled (Repeated)**               | `DeviceEvents \| where ActionType has "AntivirusDisabled"` |
|                          | **Script Obfuscation (Repeated)**        | `DeviceProcessEvents \| where ProcessCommandLine has_any("FromBase64String", "Invoke-Expression")` |
|                          | **Use of regsvr32 (Repeated)**           | `DeviceProcessEvents \| where FileName == "regsvr32.exe"` |
---

| **Execution**            | **Suspicious PowerShell Commands (Repeated)** | `DeviceProcessEvents \| where FileName == "powershell.exe" and ProcessCommandLine has_any("-enc", "Invoke-WebRequest")` |
|                          | **Malicious Office Macros (Repeated)**   | `DeviceProcessEvents \| where InitiatingProcessFileName endswith ".docm"` |
|                          | **Encoded Command Line (Repeated)**      | `DeviceProcessEvents \| where ProcessCommandLine has "-enc"` |
---

| **Command & Control (C2)**| **DNS Tunneling (Repeated)**           | `DeviceNetworkEvents \| where RemoteUrl contains ".xyz"` |
|                          | **Unusual Beaconing (Repeated)**         | `DeviceNetworkEvents \| summarize count() by RemoteIP, bin(Timestamp, 1h)` |
|                          | **Long Domain Chains (Repeated)**        | `DeviceEvents \| where RemoteUrl contains ".co." and strlen(RemoteUrl) > 100` |
---

| **Data Exfiltration**    | **Large Data Transfer (Repeated)**       | `DeviceNetworkEvents \| where Protocol == "HTTPS" \| summarize sum(SentBytes) by RemoteIP` |
|                          | **Cloud Upload Detected (Repeated)**     | `DeviceNetworkEvents \| where RemoteUrl has_any("drive.google.com", "dropbox.com")` |
|                          | **File Copy to USB (Repeated)**          | `DeviceEvents \| where ActionType == "UsbFileCopy"` |
---

> 📌 **Note:** The repetition is intentional for template expansion and formatting continuity. Replace with your custom detection use cases as needed.

> 🛠️ **Maintained by:** Bharath Kasyap | Cybersecurity Analyst | Log(N) Pacific



**Why These Queries Help:** They help identify threat indicators such as brute-force attempts, lateral movement, persistence, unusual processes, etc. Organized by use-case:

| Use Case                  | Query Purpose                                            | KQL Snippet |
|---------------------------|-----------------------------------------------------------|-------------|
| Failed Logons             | Detect password spraying                                | `DeviceLogonEvents` + `ActionType == "LogonFailed"` |
| Unusual Login Time        | Login outside working hours                             | `DeviceLogonEvents | where LogonTime` |
| RDP Use                   | Identify RDP sessions                                    | `DeviceNetworkEvents | where RemotePort == 3389` |
| Malicious File Execution  | Suspicious EXE or script run                            | `DeviceProcessEvents | where FileName endswith ".exe"` |
| Registry Modification     | Detect persistence via registry                         | `DeviceRegistryEvents | where RegistryKey contains "Run"` |
| Scheduled Tasks           | Malware persistence                                     | `DeviceProcessEvents | where ProcessCommandLine has "schtasks"` |
| PowerShell Abuse          | Lateral movement/scripting abuse                        | `DeviceProcessEvents | where ProcessCommandLine has "powershell"` |
| Inbound Connections       | Command & Control attempts                              | `DeviceNetworkEvents | where RemoteIP != ""` |
| Unusual Parent Process    | Suspicious process tree                                 | `DeviceProcessEvents | project ParentProcessName, FileName` |
| File Drops to Temp Dir    | Malware staging                                         | `DeviceFileEvents | where FolderPath contains "Temp"` |

> _Full list with explanations and categories is being added in the extended version._

---

## 📝 Incident Response Report Writing

1. **Title & Summary**
   - Describe incident, discovery time, severity

2. **Timeline of Events**
   - Chronological list (timestamps, users, systems)

3. **Root Cause Analysis**
   - Describe how it happened, e.g., vulnerable port exposed

4. **Affected Systems & Data**
   - IPs, devices, apps, data types

5. **Actions Taken**
   - Isolation, resets, communications

6. **Recommendations**
   - MFA, patching, firewall, awareness training

7. **Appendices**
   - KQL logs, IOCs, screenshots, MITRE references

---

## 🧭 Authority Flow & Communication Chain

| Action                     | Authorized By                   |
|---------------------------|----------------------------------|
| Device Isolation           | SOC Lead / IR Lead              |
| Firewall Rule Change       | Network Admin + IR Lead         |
| Legal Escalation           | Compliance Officer              |
| Public Disclosure          | CISO / Executive Management     |

---

## 🔐 MITRE ATT&CK Framework Mapping

| Tactic             | Technique                   | ID         | Example                            |
|--------------------|------------------------------|------------|-------------------------------------|
| Initial Access     | Spearphishing Attachment     | T1566.001  | Email with malicious Excel file    |
| Execution          | PowerShell                   | T1059.001  | Download and run scripts           |
| Persistence        | Scheduled Task/Job           | T1053      | Hidden daily run                   |
| Privilege Escalation | Token Impersonation         | T1134.001  | Pass-the-Token                     |
| Defense Evasion    | Obfuscated Files/Scripts     | T1027      | Base64 encoded script              |
| Credential Access  | LSASS Memory Dumping         | T1003.001  | mimikatz execution                 |
| Lateral Movement   | Remote Desktop Protocol      | T1021.001  | Internal RDP movement              |
| Exfiltration       | Exfil over HTTPS             | T1041      | Zip & send data externally         |

---

## 📚 External References & Cheat Sheets

| Resource                    | URL                                                                 |
|-----------------------------|----------------------------------------------------------------------|
| **NIST 800-61**             | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf |
| **MITRE ATT&CK Matrix**     | https://attack.mitre.org/                                           |
| **CISA Incident Response**  | https://www.cisa.gov/resources-tools/resources/incident-handling-guidelines |
| **SANS IR Poster**          | https://www.sans.org/posters/incident-response/                     |
| **KQL Cheat Sheet (Microsoft)** | https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference |
| **CERT Playbooks**          | https://www.cert.europa.eu/static/White%20Papers/CERT-IR-Playbook.pdf |

---

> 📌 **Ongoing Contribution:** Pull requests welcome for adding more KQLs, MITRE mappings, and role-specific guides.

> 🛠️ Maintained by: Bharath Kasyap | Cybersecurity Analyst
