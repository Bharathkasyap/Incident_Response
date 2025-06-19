
# 🔐 Incident Response Playbooks with KQL Queries

This repository contains a comprehensive set of **incident response scenarios**, each mapped to **MITRE ATT&CK techniques**, along with actionable **KQL queries**, involved parties, and remediation steps.

---

## 📘 How to Use

Click on each scenario to expand and view details such as:

- **Who is involved**
- **Immediate Response Actions**
- **KQL Query**
- **MITRE ATT&CK Mapping**

---

<details>
<summary><strong>11. 🛡️ Ransomware Activity Detected</strong></summary>

**Sample Scenario**: An employee in the finance department opens an email attachment named 'Invoice_Q2_2025.pdf.exe'. Within minutes, files across the shared network drive start getting encrypted with the '.locky' extension. The SOC team detects unusual process behavior from 'encrypt.exe' and initiates isolation.

**Who is Involved**: SOC Tier 2, IR Lead, Legal, Communications  
**Immediate Actions**:

  - Isolate affected systems immediately.
  - Disable network access for compromised devices.
  - Identify the strain of ransomware if possible.
  - Engage backup and recovery teams.
  - Notify legal and leadership.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("encrypt.exe", "ryuk.exe", "wannacry.exe", "badrabbit.exe", "locky.exe") or ProcessCommandLine has_any (".lock", ".encrypted", ".crypt")
| where InitiatingProcessFileName !in~ ("explorer.exe", "svchost.exe")
```

**MITRE ATT\&CK**: T1486 – Data Encrypted for Impact

</details>

<details>
<summary><strong>12. 🚫 Brute Force Attack on Authentication</strong></summary>

**Sample Scenario**: Multiple failed login attempts are detected against a single user account from the same external IP over a short time period. The user reports no login activity, prompting the SOC to block the IP and review login patterns for other accounts.

**Who is Involved**: SOC Analyst, Identity & Access Management (IAM)  
**Immediate Actions**:

  - Block IP addresses showing excessive failed login attempts.
  - Temporarily lock affected user accounts.
  - Investigate successful logins from those IPs or accounts.
  - Review MFA logs if applicable.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by AccountUpn, IpAddress
| where FailedAttempts > 10 // Threshold for failed attempts
| extend Reason = "Brute Force"
```

**MITRE ATT\&CK**: T1110 – Brute Force

</details>

<details>
<summary><strong>13. 🌐 Data Exfiltration via Cloud Storage</strong></summary>

**Sample Scenario**: A marketing employee uploads large .zip and .sql files to their personal Google Drive using the corporate laptop. The DLP system flags the activity, and SOC validates it was not business-approved data transfer.

**Who is Involved**: SOC Tier 2, Cloud Security Team, Data Governance  
**Immediate Actions**:

  - Identify the data being exfiltrated and its sensitivity.
  - Block access to the cloud storage service or specific bucket/folder.
  - Investigate the source (user/system) of the exfiltration.
  - Review DLP alerts.

**KQL Query**:

```kusto
CloudAppEvents
| where ActivityType in~ ("Share", "Download", "Upload")
| where isnotempty(TargetResources[0].DisplayName) // Ensure a target resource exists
| where TargetResources[0].DisplayName has_any (".zip", ".rar", ".7z", ".tar.gz", ".bak", ".sql") or isnotempty(TargetResources[0].AccessType) // Looking for common exfiltration methods
```

**MITRE ATT\&CK**: T1537 – Transfer Data to Cloud Account

</details>

<details>
<summary><strong>14. 🕵️ Process Hollowing/Injection</strong></summary>

**Sample Scenario**: A seemingly benign executable launches 'svchost.exe', but memory inspection shows shellcode being injected. The child process starts behaving unusually, triggering alerts based on process injection behavior.

**Who is Involved**: Forensics, SOC Tier 2  
**Immediate Actions**:

  - Isolate the affected system.
  - Capture memory dump for analysis.
  - Identify the injected process and the injecting process.
  - Determine the payload and its capabilities.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "VirtualAllocEx" or ProcessCommandLine has "WriteProcessMemory" or ProcessCommandLine has "CreateRemoteThread" // Common indicators of injection
| where InitiatingProcessFileName != FileName // Process injecting into another
```

**MITRE ATT\&CK**: T1055 – Process Injection

</details>

<details>
<summary><strong>15. 📧 Email Spoofing/Phishing Attempt</strong></summary>

**Sample Scenario**: A phishing email appears to come from 'ceo@company.com', asking the finance team to process an urgent payment. Email headers reveal the real sender is from a spoofed external domain, leading to domain block and user awareness alerts.

**Who is Involved**: Email Security Team, SOC Analyst, IT Help Desk  
**Immediate Actions**:

  - Block the sender's email address and domain.
  - Recall malicious emails from user inboxes.
  - Alert users to the phishing campaign.
  - Analyze email headers for origin and legitimacy.

**KQL Query**:

```kusto
EmailEvents
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| where SenderFromDomain has "example.com" and SenderFromDomain != "legitimate-example.com" // Replace with domain being spoofed
```

**MITRE ATT\&CK**: T1566.001 – Phishing: Spearphishing Attachment, T1566.002 – Phishing: Spearphishing Link

</details>

<details>
<summary><strong>16. 🔄 Lateral Movement via PsExec/SMB</strong></summary>

**Sample Scenario**: After compromising one endpoint, an attacker uses 'PsExec.exe' to access other machines within the subnet using hardcoded credentials. SOC detects the tool usage and initiates containment of the lateral spread.

**Who is Involved**: SOC Tier 2, Network Security  
**Immediate Actions**:

  - Identify source and destination of lateral movement.
  - Block SMB/PsExec traffic from suspicious sources.
  - Review authentication logs for newly accessed systems.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName =~ "PsExec.exe" or ProcessCommandLine has "net use"
| where InitiatingProcessCommandLine has "\\\\" // Indicative of remote execution
```

**MITRE ATT\&CK**: T1021.002 – Remote Services: SMB/Windows Admin Shares, T1563.002 – Remote Services: Lateral Tool Transfer

</details>

<details>
<summary><strong>17. 📦 Supply Chain Compromise Alert</strong></summary>

**Sample Scenario**: A third-party HR software vendor announces a breach. Internal systems show recent communication with the compromised vendor's infrastructure, prompting an investigation of all related endpoints for C2 or backdoor artifacts.

**Who is Involved**: IR Lead, Vendor Management, Legal, SOC Tier 3  
**Immediate Actions**:

  - Isolate systems running software from the compromised vendor.
  - Review network traffic for suspicious connections to vendor infrastructure.
  - Assess impact and potential for backdoors.
  - Communicate with the affected vendor.

**KQL Query**:

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName has "compromised_vendor_app.exe" // Replace with actual compromised application
| where RemoteIPType == "Public"
```

**MITRE ATT\&CK**: T1195 – Supply Chain Compromise

</details>

<details>
<summary><strong>18. 🗑️ Data Destruction Attempt</strong></summary>

**Sample Scenario**: A disgruntled employee uses 'sdelete.exe' on their last working day to erase project files. Endpoint monitoring flags the action and allows partial recovery from backups.

**Who is Involved**: SOC Tier 2, IR Lead, Forensics  
**Immediate Actions**:

  - Identify the method of destruction (e.g., sdelete, format).
  - Isolate affected systems.
  - Attempt data recovery if possible.
  - Preserve logs and artifacts.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("sdelete.exe", "format.com", "cipher.exe") or ProcessCommandLine has_any ("/wipe", "/s")
| where InitiatingProcessFileName !in~ ("explorer.exe", "cmd.exe") // Exclude benign usage
```

**MITRE ATT\&CK**: T1485 – Data Destruction

</details>

<details>
<summary><strong>19. 🔑 Credential Dumping via LSASS</strong></summary>

**Sample Scenario**: The SOC detects the use of 'procdump.exe' targeting 'lsass.exe' on a developer’s machine. Further inspection confirms Mimikatz was used to dump credentials, and SOC forces password resets for affected accounts.

**Who is Involved**: SOC Tier 2, Forensics  
**Immediate Actions**:

  - Isolate the system where credential dumping occurred.
  - Force password reset for affected accounts.
  - Identify the tool used (e.g., Mimikatz, procdump).
  - Scan for persistence mechanisms.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "procdump.exe") or ProcessCommandLine has "lsass.exe"
| where InitiatingProcessFileName !in~ ("taskmgr.exe") // Exclude benign process analysis
```

**MITRE ATT\&CK**: T1003.001 – OS Credential Dumping: LSASS Memory

</details>

<details>
<summary><strong>20. 📈 Unusual Network Traffic Spike</strong></summary>

**Sample Scenario**: A user’s device uploads over 5GB in under 5 minutes during off-hours. Network logs show data being sent to an unrecognized IP, indicating possible data exfiltration or a C2 beaconing attempt.

**Who is Involved**: Network Security, SOC Analyst  
**Immediate Actions**:

  - Identify source and destination of the traffic.
  - Determine the protocol and ports used.
  - Check for signs of DDoS, exfiltration, or C2 communication.
  - Block suspicious traffic flows.

**KQL Query**:

```kusto
DeviceNetworkEvents
| summarize TotalBytes = sum(SentBytes + ReceivedBytes) by DeviceName, bin(5m) // Aggregate traffic in 5-minute bins
| where TotalBytes > 1000000000 // Example: 1GB in 5 minutes, adjust threshold
| extend Reason = "Unusual Traffic Spike"
```

**MITRE ATT\&CK**: T1071 – Application Layer Protocol, T1041 – Exfiltration Over C2 Channel

</details>

<details>
<summary><strong>21. 🦠 Malware Communication to C2 Server</strong></summary>

**Sample Scenario**: After an alert from threat intel about a new C2 domain, internal logs reveal one endpoint attempting to reach that domain. The process responsible is a disguised dropper malware embedded in a recent download.

**Who is Involved**: SOC Tier 2, Network Security, Threat Intelligence  
**Immediate Actions**:

  - Block outbound connections to identified C2 IPs/domains.
  - Isolate affected hosts.
  - Analyze network traffic for indicators of compromise (IOCs).
  - Update threat intelligence feeds.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemoteIP in (ThreatIntelligenceIndicator | where Active == true and NetworkIP != "" | project NetworkIP) or RemoteUrl in (ThreatIntelligenceIndicator | where Active == true and Url != "" | project Url)
| where ActionType == "ConnectionAttempt" and RemotePort in (80, 443, 53) // Common C2 ports
```

**MITRE ATT\&CK**: T1071 – Application Layer Protocol, T1041 – Exfiltration Over C2 Channel

</details>

<details>
<summary><strong>22. 🛑 Unauthorized System Shutdown/Reboot</strong></summary>

**Sample Scenario**: A user's machine triggers an unexpected shutdown during business hours. Investigation shows a remote execution tool was misused through 'shutdown.exe' by a compromised admin account.

**Who is Involved**: SOC Analyst, System Administrators  
**Immediate Actions**:
  - Investigate the source of the shutdown/reboot command.
  - Check for signs of system compromise or denial of service.
  - Restore system availability if malicious.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "shutdown" or ProcessCommandLine has "reboot"
| where InitiatingProcessFileName !in~ ("explorer.exe", "systeminit.exe") // Exclude normal shutdowns/reboots
```

**MITRE ATT\&CK**: T1490 – Inhibit System Recovery

</details>

<details>
<summary><strong>23. 🗃️ Registry Key Modification (Persistence)</strong></summary>

**Sample Scenario**: Malware creates a Run key in the Windows registry to maintain persistence. KQL logs identify the exact change, and analysts trace it back to a suspicious executable launched from AppData.

**Who is Involved**: SOC Tier 2, Forensics  
**Immediate Actions**:

  - Identify the modified registry key and its purpose.
  - Remove the malicious entry.
  - Scan for associated malware or processes.

**KQL Query**:

```kusto
DeviceRegistryEvents
| where RegistryKey has_any ("Run", "RunOnce", "CurrentVersion\\Windows\\", "Services\\") // Common persistence locations
| where InitiatingProcessFileName !in~ ("system", "svchost.exe", "explorer.exe") // Exclude common benign processes
| where ActionType == "RegistryKeySet"
```

**MITRE ATT\&CK**: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

</details>

<details>
<summary><strong>24. 🔒 Suspicious Account Lockout Spike</strong></summary>

**Sample Scenario**: Over 20 users report being locked out within a 2-minute window. Logs show all attempts originate from a specific IP, revealing a brute-force password spraying attempt.

**Who is Involved**: SOC Analyst, IAM Team  
**Immediate Actions**:

  - Identify the locked accounts and originating IPs.
  - Check for credential stuffing or password spraying.
  - Temporarily block problematic IPs.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "AccountLocked"
| summarize LockedAttempts = count() by AccountUpn, IpAddress, bin(1m)
| where LockedAttempts > 5 // Adjust threshold
```

**MITRE ATT\&CK**: T1110 – Brute Force

</details>

<details>
<summary><strong>25. 🕵️ Service Creation/Modification</strong></summary>

**Sample Scenario**: A malicious script deploys a rogue Windows service under the name 'WinUpdates'. Logs show 'sc create' was used from an unauthorized terminal session, leading to further compromise analysis.

**Who is Involved**: SOC Tier 2, System Administrators  
**Immediate Actions**:

  - Investigate newly created or modified services.
  - Determine if the service is legitimate or malicious.
  - Disable or remove unauthorized services.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "sc create" or ProcessCommandLine has "sc config"
| where InitiatingProcessFileName !in~ ("svchost.exe", "systeminit.exe") // Exclude benign system processes
```

**MITRE ATT\&CK**: T1543.003 – Create or Modify System Process: Windows Service

</details>

<details>
<summary><strong>26. 🌐 DNS Tunneling Activity</strong></summary>

**Sample Scenario**: A compromised device sends unusually long DNS queries with Base64-encoded data. DNS logs confirm the presence of data exfiltration using DNS as a covert channel.

**Who is Involved**: Network Security, SOC Tier 2  
**Immediate Actions**:

  - Monitor for unusually long or malformed DNS queries.
  - Block suspicious DNS requests.
  - Identify the source of the tunneling.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemotePort == 53 and Protocol == "UDP"
| where RemoteUrl has_any (".txt", ".exe", ".zip", "malicious_pattern") // Look for unusual data in DNS queries
| summarize QueryCount = count() by RemoteUrl, DeviceName
| where QueryCount > 50 // Adjust threshold for frequent unusual queries
```

**MITRE ATT\&CK**: T1071.004 – Application Layer Protocol: DNS

</details>

<details>
<summary><strong>27. 🔓 Unsecured Remote Desktop Protocol (RDP) Access</strong></summary>

**Sample Scenario**: External scanning reveals port 3389 open to the internet. KQL logs show public IPs attempting to connect, triggering an alert and enforced NLA requirement with IP whitelisting.

**Who is Involved**: SOC Analyst, Network Security  
**Immediate Actions**:

  - Block RDP access from external/untrusted IPs.
  - Investigate RDP login attempts from unusual sources.
  - Ensure RDP is configured for Network Level Authentication (NLA).

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemotePort == 3389 and InitiatingProcessFileName =~ "rdpclip.exe" // RDP activity
| where RemoteIPType == "Public"
```

**MITRE ATT\&CK**: T1021.001 – Remote Services: RDP

</details>

<details>
<summary><strong>28. 💾 WMI Persistence (Event Subscriptions)</strong></summary>

**Sample Scenario**: During threat hunting, WMI event filters and consumers linked to a rogue binary are discovered. The persistence was stealthily re-triggering the malware post-reboot.

**Who is Involved**: Forensics, SOC Tier 2  
**Immediate Actions**:

  - Identify malicious WMI event subscriptions.
  - Remove the unauthorized subscriptions.
  - Investigate the triggered actions.

**KQL Query**:

```kusto
DeviceWmiEvent
| where EventType has_any ("__EventFilter", "__EventConsumer", "__EventBinding") // WMI persistence artifacts
| where isnotempty(CommandLine) // Ensure command line is present for analysis
```

**MITRE ATT\&CK**: T1546.003 – Event Triggered Execution: Windows Management Instrumentation

</details>

<details>
<summary><strong>29. 🛡️ Tampering with Security Software</strong></summary>

**Sample Scenario**: Malware disables Microsoft Defender via 'net stop Sense'. DeviceProcessEvents catch the stop command and generate alerts for analyst review.

**Who is Involved**: SOC Tier 2, Endpoint Security  
**Immediate Actions**:

  - Re-enable/re-configure security software.
  - Investigate the process that attempted to tamper.
  - Scan the affected system for malware.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("sc stop Sense", "net stop Sense", "taskkill /f /im sense.exe") // Example for Microsoft Defender for Endpoint
| where InitiatingProcessFileName !in~ ("system", "msmpeng.exe") // Exclude benign processes
```

**MITRE ATT\&CK**: T1562.001 – Impair Defenses: Disable or Modify System Firewall, T1562.002 – Impair Defenses: Disable or Modify Tools

</details>

<details>
<summary><strong>30. 🔑 Golden Ticket/Silver Ticket Attack</strong></summary>

**Sample Scenario**: KQL shows TGT/TGS requests with odd SIDs and long ticket lifetimes. Analysts determine the krbtgt account was compromised, requiring dual password resets.

**Who is Involved**: IAM Team, SOC Tier 3, Forensics  
**Immediate Actions**:

  - Reset krbtgt account password twice (for Golden Ticket).
  - Identify and invalidate forged tickets.
  - Investigate the source of the compromise.
  - Review domain controller logs for unusual activity.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "TGTRequested" or ActionType == "TGSRequested"
| where isnotempty(TargetUserSid) and TargetUserSid contains "S-1-5-21" // Look for suspicious TGT/TGS requests
| where isnotempty(LogonType) and LogonType == "Service" // Often associated with service accounts
```

**MITRE ATT\&CK**: T1558.001 – Steal or Forge Kerberos Tickets: Golden Ticket, T1558.003 – Steal or Forge Kerberos Tickets: Silver Ticket

</details>

<details>
<summary><strong>31. 📈 Unusual Data Volume in Network Shares</strong></summary>

**Sample Scenario**: A device accesses 12GB of data from a shared drive within 30 minutes. Analysis shows it was not a backup but a possible staging phase for exfiltration.

**Who is Involved**: SOC Analyst, System Administrators  
**Immediate Actions**:

  - Investigate sudden increases in data read/write to network shares.
  - Determine if it's legitimate activity (e.g., backup) or exfiltration.
  - Restrict access if suspicious.

**KQL Query**:

```kusto
DeviceFileEvents
| where ActionType == "FileShareAccessed"
| summarize TotalBytes = sum(FileSize) by DeviceName, InitiatingProcessFileName, FolderPath, bin(1h) // Aggregate by hour
| where TotalBytes > 10000000000 // Example: 10GB in an hour, adjust threshold
```

**MITRE ATT\&CK**: T1020 – Automated Exfiltration

</details>

<details>
<summary><strong>32. ⚙️ Exploitation of Public-Facing Application</strong></summary>

**Sample Scenario**: A vulnerability in a web form allowed SQL injection. Web logs show use of 'union select' and attempted command execution, prompting emergency patching.

**Who is Involved**: Web Security, SOC Tier 2, Application Owners  
**Immediate Actions**:

  - Take the vulnerable application offline or restrict access.
  - Patch the vulnerability immediately.
  - Forensically analyze logs for exploit attempts and success.

**KQL Query**:

```kusto
// This query depends heavily on specific web server logs and application logs.
// Example for a generic web server log:
Syslog
| where ProcessName == "apache" or ProcessName == "nginx"
| where Message has_any ("union select", "waitfor delay", "etc/passwd") // Common SQLi/LFI patterns
| where Result == 200 // Successful exploitation
```

**MITRE ATT\&CK**: T1190 – Exploit Public-Facing Application

</details>

<details>
<summary><strong>33. 🔑 Use of Obfuscated Files or Information</strong></summary>

**Sample Scenario**: KQL flags PowerShell scripts containing Base64 strings and 'Invoke-Expression'. Review shows attempts to download and run payloads hidden in encoded commands.

**Who is Involved**: SOC Tier 2, Threat Hunter, Forensics  
**Immediate Actions**:

  - Isolate the system.
  - De-obfuscate the file/script to understand its purpose.
  - Identify the origin and delivery method.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("-encodedcommand", "iex (new-object net.webclient)", "FromBase64String") // PowerShell obfuscation
| where InitiatingProcessFileName !in~ ("powershell.exe", "pwsh.exe") // Exclude benign PowerShell scripts if possible
```

**MITRE ATT\&CK**: T1027 – Obfuscated Files or Information

</details>

<details>
<summary><strong>34. 💬 Unusual Slack/Teams Activity</strong></summary>

**Sample Scenario**: An intern's account sends files and invites to external users via Teams. Logs confirm account compromise through phishing, leading to access revocation.

**Who is Involved**: SOC Analyst, Collaboration Tools Administrator  
**Immediate Actions**:

  - Investigate unusual file sharing, external user invitations, or message content.
  - Restrict user access or revoke sharing permissions.
  - Check for compromised accounts.

**KQL Query**:

```kusto
// KQL for collaboration tools often requires specific connectors/APIs
// Example for Microsoft 365 Audit Logs (conceptually):
AuditLogs
| where OperationName in~ ("SharePointFileActivity", "TeamsMessage", "ExternalUserInvited")
| where InitiatedBy.UserPrincipalName in~ ("suspicioususer@domain.com") // Identify suspicious user
```

**MITRE ATT\&CK**: T1534 – Internal Spearphishing

</details>

<details>
<summary><strong>35. 🖥️ Suspicious Remote Code Execution (RCE)</strong></summary>

**Sample Scenario**: RCE commands executed via 'cmd.exe /c' triggered from 'w3wp.exe' (IIS). Webshell activity is suspected, and IR isolates the web server for inspection.

**Who is Involved**: SOC Tier 2, IR Lead, Application Owners  
**Immediate Actions**:

  - Isolate the affected server/application.
  - Identify the vulnerability exploited.
  - Patch the vulnerability and deploy mitigations.
  - Forensically analyze for persistence and lateral movement.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("cmd.exe /c", "powershell.exe -c", "bash -c") // Common RCE commands
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe") // Common web server processes
```

**MITRE ATT\&CK**: T1210 – Exploitation of Remote Services

</details>

<details>
<summary><strong>36. 🚮 Deletion of Logs/Security Artifacts</strong></summary>

**Sample Scenario**: A compromised system shows 'EventLog.evtx' being deleted via command line. The attacker tried to remove forensic evidence post-compromise, but alerting captured the action in time.

**Who is Involved**: SOC Tier 3, Forensics  
**Immediate Actions**:

  - Immediately preserve remaining logs and system images.
  - Restore logs from backups if available.
  - Identify the process/user attempting deletion.

**KQL Query**:

```kusto
DeviceFileEvents
| where FileName has_any ("syslog", "auth.log", "EventLog.evtx") and ActionType == "FileDeleted"
| where InitiatingProcessFileName !in~ ("logrotate.exe", "system") // Exclude legitimate log management
```

**MITRE ATT\&CK**: T1070.001 – Indicator Removal: Clear Windows Event Logs, T1070.004 – Indicator Removal: File Deletion

</details>

<details>
<summary><strong>37. 🎭 Impersonation via Token Manipulation</strong></summary>

**Sample Scenario**: An attacker leverages SeImpersonatePrivilege to launch a new process as SYSTEM. Logs reveal token manipulation attempts and command execution using 'CreateProcessWithToken'.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Identify the process performing token manipulation.
  - Revoke compromised tokens/sessions.
  - Investigate how the initial access was gained.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("SeDebugPrivilege", "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege") // Privileges related to token manipulation
| where InitiatingProcessFileName !in~ ("lsass.exe", "services.exe") // Exclude benign system processes
```

**MITRE ATT\&CK**: T1134.001 – Access Token Manipulation: Token Impersonation/Theft

</details>

<details>
<summary><strong>38. 🛡️ Firewall Rule Modification</strong></summary>

**Sample Scenario**: A malware modifies Windows Defender firewall rules using 'netsh' to allow outbound C2 traffic. Endpoint logs detect the change and flag it as suspicious.

**Who is Involved**: Network Security, SOC Tier 2  
**Immediate Actions**:

  - Revert unauthorized firewall rule changes.
  - Identify the source of the modification.
  - Block suspicious connections allowed by the new rules.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("netsh advfirewall firewall set rule", "New-NetFirewallRule") // Windows Firewall commands
| where InitiatingProcessFileName !in~ ("svchost.exe", "system") // Exclude benign system processes
```

**MITRE ATT\&CK**: T1562.004 – Impair Defenses: Disable or Modify System Firewall

</details>

<details>
<summary><strong>39. ☁️ Cloud Instance/Resource Creation</strong></summary>

**Sample Scenario**: An attacker uses a stolen cloud API token to spin up crypto-mining VMs in unused regions. Azure Activity logs show the creation requests coming from an unfamiliar IP address.

**Who is Involved**: Cloud Security Team, DevOps, SOC Tier 2  
**Immediate Actions**:

  - Investigate unauthorized cloud resource provisioning.
  - Terminate malicious instances or delete resources.
  - Review IAM roles and permissions.

**KQL Query**:

```kusto
// KQL for cloud provider logs (e.g., Azure Activity Logs, AWS CloudTrail)
// Example for Azure:
AzureActivity
| where OperationNameValue contains "Microsoft.Compute/virtualMachines/write" or OperationNameValue contains "Microsoft.Storage/storageAccounts/write"
| where ActivityStatus == "Accepted" and Caller != "LegitimateAutomationAccount" // Exclude known automation
```

**MITRE ATT\&CK**: T1578.002 – Cloud Infrastructure: Create Cloud Instance

</details>

<details>
<summary><strong>40. 🔗 Web Shell Deployment</strong></summary>

**Sample Scenario**: Security logs show a new '.aspx' file being created in 'wwwroot'. This webshell provides backdoor access to attackers, and the SOC removes it and restores the server from backup.

**Who is Involved**: Web Security, Forensics, SOC Tier 3  
**Immediate Actions**:

  - Take the compromised web server offline.
  - Identify and remove the web shell.
  - Conduct a forensic analysis to determine how it was deployed.
  - Patch the underlying vulnerability.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath contains "inetpub" or FolderPath contains "wwwroot" // Common web server directories
| where FileName has_any (".aspx", ".php", ".jsp") and FileSize < 10000 // Small files often indicate web shells
| where ActionType == "FileCreated"
```

**MITRE ATT\&CK**: T1505.003 – Server Software Component: Web Shell

</details>

<details>
<summary><strong>41. 📤 Excessive Outbound Traffic to Unusual Ports</strong></summary>

**Sample Scenario**: An internal host starts communicating with external IPs over port 6667 (IRC), commonly used in botnet C2. Network logs highlight over 500 connections in 10 minutes.

**Who is Involved**: Network Security, SOC Analyst  
**Immediate Actions**:

  - Identify the source and destination of the traffic.
  - Block the unusual port communication.
  - Investigate for data exfiltration or C2 channels.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where LocalIPType == "Private" and RemoteIPType == "Public"
| where RemotePort !in (80, 443, 21, 22, 25, 53, 110, 143, 3389, 445) // Exclude common ports
| summarize ConnectionCount = count() by DeviceName, RemoteIP, RemotePort
| where ConnectionCount > 100 // Adjust threshold for unusual volume
```

**MITRE ATT\&CK**: T1048 – Exfiltration Over Alternative Protocol

</details>

<details>
<summary><strong>42. 🕵️ Process Argument/Command Line Obfuscation</strong></summary>

**Sample Scenario**: Analysts detect PowerShell scripts running with 'JAB=' and 'FromBase64String' – indicators of obfuscated commands. The parent process is traced to a phishing document's macro.

**Who is Involved**: SOC Tier 2, Threat Hunter  
**Immediate Actions**:

  - Isolate the affected system.
  - Attempt to de-obfuscate the command line to understand intent.
  - Look for parent/child process relationships.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("JAB", "==") // Common patterns for Base64 or PowerShell obfuscation
| where InitiatingProcessFileName !in~ ("powershell.exe", "cmd.exe") // Exclude if running directly in a known shell
```

**MITRE ATT\&CK**: T1027 – Obfuscated Files or Information

</details>

<details>
<summary><strong>43. 🖥️ Unauthorized Software Installation</strong></summary>

**Sample Scenario**: A user installs a crypto wallet using 'setup.exe' outside approved software channels. Logs catch silent installation flags like '/s', triggering software compliance review.

**Who is Involved**: SOC Analyst, Desktop Support  
**Immediate Actions**:

  - Uninstall unauthorized software.
  - Investigate how it was installed (user, automated, malware).
  - Review software whitelisting/blacklisting policies.

**KQL Query**:

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "msiexec.exe" or InitiatingProcessFileName =~ "setup.exe"
| where FileName !in~ ("chromeinstaller.exe", "firefoxinstaller.exe") // Exclude common benign installers
| where isnotempty(ProcessCommandLine) and ProcessCommandLine has_any ("install", "silent", "/s")
```

**MITRE ATT\&CK**: T1072 – System Owner/Developer Mode

</details>

<details>
<summary><strong>44. 🎣 Spearphishing via Service</strong></summary>

**Sample Scenario**: An email claiming to be from 'noreply@microsoft-support.com' asks users to reset credentials. The sender domain was not whitelisted, and EmailEvents flagged this as impersonation.

**Who is Involved**: Email Security Team, SOC Analyst  
**Immediate Actions**:

  - Block sender and associated domains.
  - Recall malicious messages.
  - Alert users to the specific service being impersonated.

**KQL Query**:

```kusto
EmailEvents
| where ThreatTypes has "Phish"
| where SenderFromAddress has_any ("support@", "noreply@") and SenderFromDomain != "legitimate-company.com" // Look for common service impersonations
```

**MITRE ATT\&CK**: T1566.003 – Phishing: Spearphishing via Service

</details>

<details>
<summary><strong>45. 🔄 Scheduled Task Abuse for Persistence</strong></summary>

**Sample Scenario**: A scheduled task is created with 'schtasks /create' that runs a payload every 30 minutes. The task’s binary points to a file in 'AppData', confirming persistence via task scheduler.

**Who is Involved**: SOC Tier 2, Endpoint Security  
**Immediate Actions**:

  - Disable or delete the malicious scheduled task.
  - Investigate the executable or script triggered by the task.
  - Scan for associated malware.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "schtasks" and ProcessCommandLine has "create"
| where InitiatingProcessFileName !in~ ("system", "svchost.exe") // Exclude benign system processes
| where ProcessCommandLine has_any ("/tn", "/tr") // Task Name and Task Run
```

**MITRE ATT\&CK**: T1053.005 – Scheduled Task/Job: Scheduled Task

</details>

<details>
<summary><strong>46. 💾 Disk Wipe/Data Destruction Attempt</strong></summary>

**Sample Scenario**: A departing employee uses 'format c:' and 'sdelete' commands to wipe local drives. Process monitoring alerts on the commands and triggers containment actions.

**Who is Involved**: IR Lead, Forensics, SOC Tier 3  
**Immediate Actions**:

  - Isolate the system.
  - Power off if possible to preserve forensic data.
  - Attempt data recovery from backups.
  - Identify the destruction tool or method.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("cipher.exe", "diskpart.exe", "dd.exe", "shred.exe") or ProcessCommandLine has_any ("/wipe", "/s", "format c:", "del /s /q c:\\")
| where InitiatingProcessFileName !in~ ("explorer.exe", "cmd.exe") // Exclude common benign usage
```

**MITRE ATT\&CK**: T1488 – Data Destruction

</details>

<details>
<summary><strong>47. ⚙️ Exploitation for Privilege Escalation</strong></summary>

**Sample Scenario**: A user with low privileges executes 'exploit.exe' targeting a known Windows vulnerability. Post-exploit, they successfully spawn SYSTEM-level processes – a privilege escalation confirmed in logs.

**Who is Involved**: SOC Tier 2, Forensics  
**Immediate Actions**:

  - Isolate the affected system.
  - Identify the exploited vulnerability and patch it.
  - Determine the new escalated privileges and their use.
  - Scan for persistence mechanisms.

**KQL Query**:

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName has_any ("exploit.exe", "poc.exe") or InitiatingProcessCommandLine has "SeDebugPrivilege" // Look for common exploit tools or privilege requests
| where isnotempty(AccountDomain) and AccountDomain != "NT AUTHORITY" // Look for non-system accounts gaining privilege
```

**MITRE ATT\&CK**: T1068 – Exploitation for Privilege Escalation

</details>

<details>
<summary><strong>48. 👻 Kerberoasting Attack</strong></summary>

**Sample Scenario**: A pentester requests multiple SPNs using RC4 encryption and exports tickets. The request volume exceeds baseline, triggering alerts from the authentication monitoring system.

**Who is Involved**: IAM Team, SOC Tier 3  
**Immediate Actions**:

  - Identify service principal names (SPNs) with weak encryption types.
  - Reset passwords for affected service accounts with strong, random passwords.
  - Implement account monitoring for SPN requests.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "TGSRequested"
| where isnotempty(ServicePrincipalName)
| where isnotempty(RequestedTicketEncryptionType) and RequestedTicketEncryptionType == "RC4_HMAC_MD5" // Weak encryption type
| summarize RequestCount = count() by ServicePrincipalName, ClientIpAddress
| where RequestCount > 100 // Adjust threshold for unusual SPN requests
```

**MITRE ATT\&CK**: T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting

</details>

<details>
<summary><strong>49. 🛠️ Use of Living Off The Land Binaries (LOLBins)</strong></summary>

**Sample Scenario**: Attackers abuse 'certutil.exe' to download encoded payloads. Analysts detect it being used with 'urlcache' and 'decode' flags – a known tactic to avoid AV detection.

**Who is Involved**: SOC Tier 2, Threat Hunter  
**Immediate Actions**:

  - Investigate the use of legitimate binaries for malicious purposes.
  - Analyze the command line arguments and parent/child processes.
  - Determine the overall attack chain.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| where ProcessCommandLine has_any ("urlcache", "download", "decode", "exec") // Common malicious usage patterns
| where InitiatingProcessFileName !in~ ("explorer.exe", "system") // Exclude benign usage
```

**MITRE ATT\&CK**: T1218 – System Binary Proxy Execution

</details>

<details>
<summary><strong>50. 💾 Exfiltration Over C2 Channel (DNS)</strong></summary>

**Sample Scenario**: DNS logs show hundreds of outbound queries to suspicious subdomains like 'data.leak.example.com'. SOC suspects and confirms DNS tunneling used to exfiltrate compressed files.

**Who is Involved**: Network Security, SOC Tier 2  
**Immediate Actions**:

  - Block suspicious DNS queries to external domains.
  - Identify the data being exfiltrated within DNS requests.
  - Isolate affected systems.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemotePort == 53 and Protocol == "UDP"
| where RemoteUrl contains "maliciousdomain.com" and RemoteUrl has_any (".txt", ".zip", "base64encodeddata") // Specific indicators of DNS exfiltration
| summarize QueryCount = count() by DeviceName, RemoteUrl
| where QueryCount > 500 // High volume of unusual DNS queries
```

**MITRE ATT\&CK**: T1041 – Exfiltration Over C2 Channel, T1071.004 – Application Layer Protocol: DNS

</details>

<details>
<summary><strong>51. 🔌 Rogue Wireless Access Point</strong></summary>

**Sample Scenario**: A fake Wi-Fi network mimicking the corporate SSID is set up near the office. Devices auto-connect, leaking credentials. Blue team captures logs of the rogue AP using Wireshark.

**Who is Involved**: Network Security, IT Support, SOC Analyst  
**Immediate Actions**:

  - Locate and disable the rogue WAP.
  - Scan for devices connected to the rogue WAP.
  - Audit network access points.
  - Communicate with staff about Wi-Fi security.

**KQL Query**:

```kusto
// This typically requires network device logs or wireless sensor data.
// Conceptual query for network devices detecting unknown SSIDs
NetworkEvents
| where EventType == "RogueAPDetected"
| where WirelessSSID !in~ ("Your_Legitimate_SSID_1", "Your_Legitimate_SSID_2")
```

**MITRE ATT\&CK**: T1565.001 – Impair Process Control: Compromise Network Device

</details>

<details>
<summary><strong>52. 📞 Voice Phishing (Vishing) Report</strong></summary>

**Sample Scenario**: An employee receives a call from someone pretending to be IT, requesting login credentials to "fix a system issue." The caller ID appears spoofed. The employee reports it immediately.

**Who is Involved**: SOC Analyst, HR, IT Help Desk, Communications  
**Immediate Actions**:

  - Collect details from the victim (caller ID, request made, info given).
  - Alert all employees about the vishing campaign.
  - Block reported phone numbers if possible.
  - Review recent access logs for any compromise related to the call.

**KQL Query**:

```kusto
// This is primarily a human-reported incident. Log analysis would follow up.
// Example: Checking for logins after a reported vishing attempt
IdentityLogonEvents
| where TimeGenerated > ago(1h) // Check recent logins
| where AccountUpn =~ "victim@domain.com"
| where IpAddress !in (KnownOfficeIPs) // Look for logins from unusual locations
```

**MITRE ATT\&CK**: T1566.004 – Phishing: Spearphishing Voice

</details>

<details>
<summary><strong>53. ⚙️ Browser Extensions with Malicious Behavior</strong></summary>

**Sample Scenario**: A browser extension is flagged for capturing browsing history and sending it to an external domain. Logs indicate the extension had permissions to read all data on visited sites.

**Who is Involved**: SOC Analyst, Desktop Support  
**Immediate Actions**:

  - Identify and disable/remove the malicious browser extension.
  - Scan the affected system for additional malware.
  - Educate users on safe browser extension practices.

**KQL Query**:

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "chrome.exe" or InitiatingProcessFileName =~ "firefox.exe" or InitiatingProcessFileName =~ "msedge.exe"
| where ProcessCommandLine has "extension-id" and ProcessCommandLine has_any ("read-all-data", "modify-headers") // Look for suspicious extension permissions/actions
```

**MITRE ATT\&CK**: T1176 – Browser Extensions

</details>

<details>
<summary><strong>54. 🔒 SSH Brute Force/Password Spraying</strong></summary>

**Sample Scenario:** Attackers scan public IP ranges for SSH ports and repeatedly attempt logins using common usernames like 'admin', 'test', and 'root' with weak passwords. One system logs over 100 failed attempts from the same IP. The SOC blocks the IP and resets credentials.

**Who is Involved**: SOC Analyst, Server Administrators  
**Immediate Actions**:

  - Block the attacking IP addresses.
  - Lock affected user accounts.
  - Review successful SSH logins from suspicious sources.
  - Implement stronger SSH authentication (keys, MFA).

**KQL Query**:

```kusto
Syslog
| where ProcessName == "sshd" and Message has "Failed password"
| summarize FailedAttempts = count() by SourceIP, UserAccount
| where FailedAttempts > 20 // Adjust threshold
```

**MITRE ATT\&CK**: T1110 – Brute Force

</details>

<details>
<summary><strong>55. ☁️ S3 Bucket/Cloud Storage Misconfiguration</strong></summary>

**Sample Scenario:** A developer accidentally grants public-read access to an S3 bucket containing sensitive financial data. The SOC detects this via CloudTrail logs and revokes access within minutes, preventing external data scraping.

**Who is Involved**: Cloud Security Team, SOC Tier 2, DevOps  
**Immediate Actions**:

  - Immediately revoke public access to the misconfigured bucket/storage.
  - Review access policies and permissions.
  - Assess if data was accessed or exfiltrated.

**KQL Query**:

```kusto
// KQL for cloud provider logs (e.g., AWS CloudTrail, Azure Storage Logs)
// Example for AWS:
AWSCloudTrail
| where EventName == "PutBucketAcl" or EventName == "PutObjectAcl"
| where RequestParameters.AccessControlList.Grants has "http://acs.amazonaws.com/groups/global/AllUsers" // Public access granted
```

**MITRE ATT\&CK**: T1538 – Cloud Storage Object Discovery

</details>

<details>
<summary><strong>56. 🔑 Password Spraying Across Multiple Accounts</strong></summary>

**Sample Scenario:** A malicious actor tries logging into 100 user accounts using the password 'Spring2024!'. The IAM team observes failed attempts from one IP and confirms this as a password spraying attempt. The IP is blocked and affected accounts are locked.

**Who is Involved**: SOC Analyst, IAM Team  
**Immediate Actions**:

  - Identify the common password being sprayed.
  - Block the attacking IP addresses.
  - Force password reset for any compromised accounts.
  - Implement account lockout policies.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedCount = count() by IpAddress, bin(5m) // Group by IP and time
| where FailedCount > 50 // High number of failed logins from one IP
| extend DistinctAccounts = dcount(AccountUpn)
| where DistinctAccounts > 10 // Targeting many accounts
```

**MITRE ATT\&CK**: T1110 – Brute Force

</details>

<details>
<summary><strong>57. 🕵️ Process Argument Spoofing</strong></summary>

**Sample Scenario:** A process named svchost.exe is launched with a suspicious argument pointing to a remote PowerShell payload. Analysts trace the activity and discover it's malware trying to masquerade as a Windows service.

**Who is Involved**: SOC Tier 2, Forensics  
**Immediate Actions**:

  - Isolate the affected system.
  - Analyze the process execution chain and actual arguments.
  - Identify the source of the spoofed process.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName =~ "svchost.exe" // Or another common benign process
| where ProcessCommandLine has "suspicious_command" and ProcessCommandLine !has "legitimate_svchost_arguments" // Look for suspicious arguments that don't match typical use
```

**MITRE ATT\&CK**: T1036.004 – Masquerading: Process Argument Spoofing

</details>

<details>
<summary><strong>58. 📂 Archive Compression for Exfiltration</strong></summary>

**Sample Scenario:** A user unknowingly infected with malware triggers a rule when large .zip and .7z files are created in an unusual directory. SOC finds these were created by a script run by the malware and blocks the exfiltration channel.

**Who is Involved**: SOC Tier 2, Data Governance  
**Immediate Actions**:

  - Identify large archive files being created and transferred.
  - Block outbound transfers of suspicious archives.
  - Investigate the source and content of the archives.

**KQL Query**:

```kusto
DeviceFileEvents
| where FileName endswith_any (".zip", ".rar", ".7z", ".tar.gz")
| where InitiatingProcessFileName !in~ ("winzip.exe", "winrar.exe", "7z.exe", "backup_tool.exe") // Exclude known archiving tools
| where FileSize > 100000000 // Files larger than 100MB, adjust as needed
```

**MITRE ATT\&CK**: T1560.001 – Archive Collected Data: Archive via Utility

</details>

<details>
<summary><strong>59. 🔄 Bypass User Account Control (UAC)</strong></summary>

**Sample Scenario:** A user’s machine executes fodhelper.exe with a payload that silently launches cmd.exe as administrator. Analysts identify the UAC bypass method and isolate the system.

**Who is Involved**: SOC Tier 2, Endpoint Security  
**Immediate Actions**:

  - Identify the UAC bypass technique used.
  - Patch the vulnerability if applicable.
  - Isolate the system and scan for additional compromise.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("sdclt.exe", "fodhelper.exe", "eventvwr.exe") // Common UAC bypass binaries
| where ProcessCommandLine has "C:\\Windows\\System32\\cmd.exe" // Or other elevated command
| where InitiatingProcessFileName !in~ ("explorer.exe") // Exclude direct user interaction if possible
```

**MITRE ATT\&CK**: T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control

</details>

<details>
<summary><strong>60. 🌐 Ingress Tool Transfer (Direct Download)</strong></summary>

**Sample Scenario:** A suspicious PowerShell session downloads Mimikatz from raw.githubusercontent.com. The SOC blocks the session and quarantines the endpoint.

**Who is Involved**: SOC Analyst, Network Security  
**Immediate Actions**:

  - Block direct downloads of known malicious tools.
  - Investigate the source IP and user.
  - Scan the downloading system for malware.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemoteUrl contains_any ("pastebin.com", "github.com", "raw.githubusercontent.com") // Common places for direct download of tools/scripts
| where RemoteUrl has_any (".exe", ".ps1", ".vbs", ".dll") // Common malicious file extensions
| where InitiatingProcessFileName !in~ ("explorer.exe", "browser.exe") // Exclude user-initiated downloads if possible
```

**MITRE ATT\&CK**: T1105 – Ingress Tool Transfer

</details>

<details>
<summary><strong>61. 👻 User Account Creation (Suspicious)</strong></summary>

**Sample Scenario:** A new account 'sys_backup_admin' is created outside of normal onboarding processes. Investigation reveals the account was created by a compromised domain admin.

**Who is Involved**: SOC Analyst, IAM Team  
**Immediate Actions**:

  - Investigate the legitimacy of the new account.
  - Disable or delete unauthorized accounts.
  - Identify the source of account creation.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "AccountCreated"
| where AccountUpn !in~ ("onboarding_script_account", "it_admin_account") // Exclude known legitimate creations
```

**MITRE ATT\&CK**: T1136 – Create Account

</details>

<details>
<summary><strong>62. 🛠️ Account Manipulation (Privilege Escalation)</strong></summary>

**Sample Scenario:** A user account ‘john.doe’ is granted Domain Admin privileges without proper change ticket. The IAM team reverses the change and flags it as unauthorized.

**Who is Involved**: IAM Team, SOC Tier 3  
**Immediate Actions**:

  - Revert unauthorized account privilege changes.
  - Force password reset for affected accounts.
  - Identify the source of the manipulation.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "UserModified" and (AdditionalFields contains "admin" or AdditionalFields contains "privilege") // Look for privilege-related modifications
| where AccountUpn !in~ ("admin_automation_account") // Exclude known legitimate changes
```

**MITRE ATT\&CK**: T1098 – Account Manipulation

</details>

<details>
<summary><strong>63. 📡 Network Service Scanning</strong></summary>

**Sample Scenario:** A host initiates over 500 connections to various ports across multiple servers within 10 minutes. SOC confirms it as a port scan and blocks the IP.

**Who is Involved**: Network Security, SOC Analyst  
**Immediate Actions**:

  - Block the scanning IP address.
  - Review firewall logs for allowed scans.
  - Identify any vulnerable open ports discovered.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionAttempt" and RemotePort in (21, 22, 23, 80, 443, 445, 3389) // Common scanned ports
| summarize ConnectionCount = count() by RemoteIP, RemotePort
| where ConnectionCount > 50 // Adjust threshold for aggressive scanning
```

**MITRE ATT\&CK**: T1046 – Network Service Discovery

</details>

<details>
<summary><strong>64. 🔍 Process Discovery (Unusual Enumeration)</strong></summary>

**Sample Scenario:** A compromised endpoint runs tasklist in a script to enumerate active processes and send details to a remote server. This triggers a detection alert.

**Who is Involved**: SOC Tier 2, Threat Hunter  
**Immediate Actions**:

  - Investigate the process enumerating other processes.
  - Look for signs of suspicious tools or scripts.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("tasklist", "Get-Process", "ps aux") // Common process discovery commands
| where InitiatingProcessFileName !in~ ("taskmgr.exe", "powershell.exe", "cmd.exe") // Exclude benign user/system commands
| where InitiatingProcessCommandLine !has "legitimate_script.ps1" // Exclude known legitimate scripts
```

**MITRE ATT\&CK**: T1057 – Process Discovery

</details>

<details>
<summary><strong>65. 🌐 System Network Configuration Discovery</strong></summary>

**Sample Scenario:** A PowerShell script runs ipconfig /all and netstat on an endpoint, initiated by a user with no admin rights. SOC investigates and confirms the system was infected by malware performing internal recon.

**Who is Involved**: SOC Analyst, Network Security  
**Immediate Actions**:

  - Investigate who is attempting to discover network configurations.
  - Look for signs of network mapping or enumeration tools.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("ipconfig", "ifconfig", "route print", "netstat -an") // Common network config commands
| where InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe", "explorer.exe") // Exclude benign user/system commands
```

**MITRE ATT\&CK**: T1016 – System Network Configuration Discovery

</details>

<details>
<summary><strong>66. 💻 Remote System Discovery</strong></summary>

**Sample Scenario:** nbtscan is executed by a script to map all devices in a subnet. SOC confirms it was executed by a compromised account and isolates the host.

**Who is Involved**: SOC Tier 2, Network Security  
**Immediate Actions**:

  - Identify the source of the remote system discovery.
  - Block the attacking IP if external.
  - Look for connections to newly discovered systems.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("ping", "nbtscan", "net view") // Common remote system discovery commands
| where InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe") // Exclude benign user/system commands
| where isnotempty(RemoteIP)
```

**MITRE ATT\&CK**: T1018 – Remote System Discovery

</details>

<details>
<summary><strong>67. 👥 Account Discovery (Local/Domain)</strong></summary>

**Sample Scenario:** The attacker runs net user and net group to enumerate all available users and groups within the domain. Logs show the source host was not authorized for such actions.

**Who is Involved**: SOC Analyst, IAM Team  
**Immediate Actions**:

  - Investigate who is attempting to discover accounts.
  - Look for enumeration tools or scripts.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("net user", "net group", "Get-LocalGroupMember") // Common account discovery commands
| where InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe") // Exclude benign user/system commands
```

**MITRE ATT\&CK**: T1087 – Account Discovery

</details>

<details>
<summary><strong>68. 🤝 Permission Groups Discovery</strong></summary>

**Sample Scenario:** An unknown PowerShell session queries Active Directory groups and their members. The SOC investigates and finds a compromised internal user.

**Who is Involved**: SOC Analyst, IAM Team  
**Immediate Actions**:

  - Investigate who is attempting to discover permission groups.
  - Look for suspicious tools or scripts.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("net localgroup", "Get-ADGroupMember") // Common group discovery commands
| where InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe") // Exclude benign user/system commands
```

**MITRE ATT\&CK**: T1069 – Permission Groups Discovery

</details>

<details>
<summary><strong>69. 📦 Software Discovery</strong></summary>

**Sample Scenario:** A script using wmic product get is run across endpoints to identify installed software. The activity originated from a non-IT system, indicating compromise.

**Who is Involved**: SOC Analyst, System Administrators  
**Immediate Actions**:

  - Investigate who is attempting to discover installed software.
  - Look for inventory tools or scripts.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\*'", "wmic product get name,version") // Common software discovery commands
| where InitiatingProcessFileName !in~ ("powershell.exe", "cmd.exe") // Exclude benign user/system commands
```

**MITRE ATT\&CK**: T1518 – Software Discovery

</details>

<details>
<summary><strong>70. ℹ️ System Information Discovery</strong></summary>

**Sample Scenario:** Malware executes systeminfo and hostname on infected devices and sends results to a C2 server. Alert is triggered by unusual command usage.

**Who is Involved**: SOC Analyst, System Administrators  
**Immediate Actions**:

  - Investigate who is attempting to gather system information.
  - Look for suspicious tools or scripts.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("systeminfo", "hostname", "whoami") // Common system info commands
| where InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe") // Exclude benign user/system commands
```

**MITRE ATT\&CK**: T1082 – System Information Discovery

</details>

<details>
<summary><strong>71. 🖥️ Image Tampering (OS/Software)</strong></summary>

**Sample Scenario:** An alert shows a system DLL file in System32 directory was modified by an unknown process. Integrity check fails, and the system is isolated.

**Who is Involved**: SOC Tier 3, Forensics, System Administrators  
**Immediate Actions**:

  - Validate system integrity (checksums, baselines).
  - Restore from a known good image/backup.
  - Investigate the source of the tampering.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath has_any ("C:\\Windows\\System32\\", "C:\\Program Files\\")
| where ActionType == "FileModified" and FileName has_any (".exe", ".dll", ".sys") // Look for modification of critical system files
| where InitiatingProcessFileName !in~ ("msiexec.exe", "svchost.exe", "wuauclt.exe") // Exclude legitimate updates/installers
```

**MITRE ATT\&CK**: T1600 – Ingress Tool Transfer

</details>

<details>
<summary><strong>72. 💾 Rootkit Installation</strong></summary>

**Sample Scenario:** An analyst detects a kernel-level driver loaded from an unsigned source. On analysis, the tool attempts to hide processes and network connections, confirming rootkit behavior.

**Who is Involved**: Forensics, SOC Tier 3, IR Lead  
**Immediate Actions**:

  - Isolate the affected system immediately.
  - Perform an offline forensic analysis.
  - Reimage the system from a clean baseline.

**KQL Query**:

```kusto
// Rootkits are designed to evade detection, so direct KQL is challenging.
// Look for low-level system changes or driver installations.
DeviceEvents
| where ActionType == "DriverLoaded" and not(FileName contains "Microsoft") // Look for unsigned/uncommon drivers
| where InitiatingProcessFileName != "System" // Driver loading not initiated by system
```

**MITRE ATT\&CK**: T1014 – Rootkit

</details>

<details>
<summary><strong>73. 🔄 Bootkit Installation</strong></summary>

**Sample Scenario:** The system bootloader file bootmgr is altered outside of Windows Update processes. Forensics team investigates and confirms bootkit presence.

**Who is Involved**: Forensics, SOC Tier 3, IR Lead  
**Immediate Actions**:

  - Isolate the affected system.
  - Perform a thorough offline forensic analysis of the boot sector.
  - Reimage the system from a clean baseline.

**KQL Query**:

```kusto
// Similar to rootkits, direct detection is hard. Focus on MBR/boot sector modifications.
DeviceFileEvents
| where FileName =~ "bootmgr" and ActionType == "FileModified" // Highly suspicious modification of boot manager
```

**MITRE ATT\&CK**: T1542.003 – Boot or Logon Autostart Execution: Bootkit

</details>

<details>
<summary><strong>74. ⚙️ Firmware Modification</strong></summary>

**Sample Scenario:** Firmware tampering alert is raised for a server's baseboard management controller (BMC). System logs indicate changes made outside approved maintenance windows.

**Who is Involved**: SOC Tier 3, System Administrators, Hardware Vendors  
**Immediate Actions**:

  - Validate firmware integrity.
  - Re-flash with trusted firmware.
  - Investigate the source of the unauthorized modification.

**KQL Query**:

```kusto
// Firmware modifications are very low-level and hard to detect with typical endpoint logs.
// This would typically involve specific firmware integrity monitoring tools.
// KQL would be based on alerts from such tools.
Alerts
| where Title contains "Firmware Tampering"
```

**MITRE ATT\&CK**: T1010 – Firmware Modification

</details>

<details>
<summary><strong>75. 🤝 Compromise of Trusted Relationship</strong></summary>

**Sample Scenario:** An attacker gains access to a federated identity provider and uses it to access internal applications. The attack is caught via unusual federated login activity.

**Who is Involved**: IR Lead, IAM Team, Network Security, SOC Tier 3  
**Immediate Actions**:

  - Identify the compromised trust relationship (e.g., VPN, federated identity).
  - Revoke compromised credentials/certificates.
  - Re-establish trust with validated entities.

**KQL Query**:

```kusto
IdentityLogonEvents
| where LogonType == "Federated" and isnotempty(TargetAccountUpn)
| where IpAddress !in (KnownTrustedFederationIPs) // Unusual login from a trusted federation
```

**MITRE ATT\&CK**: T1545 – Compromise of Trusted Relationship

</details>

<details>
<summary><strong>76. 🛠️ Use of Trusted Development Tools</strong></summary>

**Sample Scenario:** A legitimate tool like msbuild.exe is used to compile a malicious script. The action is not triggered from Visual Studio, raising an alert. The SOC confirms misuse of trusted tools for lateral movement.

**Who is Involved**: SOC Tier 2, DevOps, Development Teams  
**Immediate Actions**:

  - Investigate the unusual use of development tools (e.g., compilers, debuggers).
  - Verify user intent and project legitimacy.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("msbuild.exe", "csc.exe", "gdb.exe") // Common development tools
| where ProcessCommandLine has_any ("malicious_code", "suspicious_arguments") // Look for unusual arguments
| where InitiatingProcessFileName !in~ ("visualstudio.exe", "vscode.exe") // Exclude known IDEs
```

**MITRE ATT\&CK**: T1552 – Use of Trusted Development Tools

</details>

<details>
<summary><strong>77. 🎭 Masquerading - Right-to-Left Override (RTLO)</strong></summary>

**Sample Scenario:** A user receives a file named invoicegpj.exe which appears as a JPEG image due to RTLO character. The file executes malware when opened. Email gateway failed to catch the spoof.

**Who is Involved**: SOC Analyst, Email Security Team  
**Immediate Actions**:

  - Block emails with RTLO characters in filenames.
  - Educate users about this technique.
  - Scan for files with RTLO characters in their names.

**KQL Query**:

```kusto
EmailEvents
| where FileName has "\u202e" // Unicode Right-to-Left Override character
```

**MITRE ATT\&CK**: T1036.002 – Masquerading: Right-to-Left Override

</details>

<details>
<summary><strong>78. 🎭 Masquerading - Space After Filename</strong></summary>

**Sample Scenario:** A file report.pdf .exe is detected in downloads. Because of the space, it looks like a PDF to users. The SOC confirms it’s a trojan and blocks further distribution.

**Who is Involved**: SOC Analyst, Endpoint Security  
**Immediate Actions**:

  - Scan for executable files with spaces after their names.
  - Educate users about this technique.

**KQL Query**:

```kusto
DeviceFileEvents
| where FileName contains ".exe " or FileName contains ".dll " // Space after extension
| where ActionType == "FileCreated"
```

**MITRE ATT\&CK**: T1036.001 – Masquerading: Invalid Code Signature

</details>

<details>
<summary><strong>79. 🎭 Masquerading - Valid Digitally Signed Binary</strong></summary>

**Sample Scenario:** rundll32.exe is launched with suspicious arguments but has a valid Microsoft signature. Analysts discover a malicious DLL sideloaded into the signed binary.

**Who is Involved**: SOC Tier 2, Threat Hunter  
**Immediate Actions**:

  - Verify the true origin and purpose of the signed binary.
  - Check for known abused signed binaries.
  - Investigate parent process and command line.

**KQL Query**:

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName has_any ("svchost.exe", "rundll32.exe") // Common signed binaries
| where ProcessCommandLine has "suspicious_activity" // Look for suspicious command line arguments
| where FileSignatureState == "Valid"
```

**MITRE ATT\&CK**: T1036.003 – Masquerading: Valid Digitally Signed Binary

</details>

<details>
<summary><strong>80. 🎭 Masquerading - Hidden Window</strong></summary>

**Sample Scenario:** A PowerShell script launches processes with the -WindowStyle Hidden flag. Users are unaware something is running in the background. The SOC traces it to malware performing beaconing.

**Who is Involved**: SOC Tier 2, Endpoint Security  
**Immediate Actions**:

  - Identify the process running with a hidden window.
  - Investigate the parent process and its purpose.
  - Isolate the system if malicious.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "-WindowStyle Hidden" or ProcessCommandLine has "-NoWindow" // Common parameters for hidden windows
| where InitiatingProcessFileName !in~ ("svchost.exe", "explorer.exe") // Exclude benign processes
```

**MITRE ATT\&CK**: T1146 – Masquerading: Hidden Window

</details>

<details>
<summary><strong>81. 😈 Rogue Security Software</strong></summary>

**Sample Scenario:** A user reports a new antivirus tool claiming many threats. The SOC finds it's 'rogueware' named macoptimizer.exe, designed to lure users into paying for fake threats.

**Who is Involved**: SOC Analyst, Desktop Support  
**Immediate Actions**:

  - Remove the rogue security software.
  - Scan the affected system with legitimate antivirus.
  - Educate users about fraudulent software.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName has_any ("scanguard.exe", "macoptimizer.exe", "adaware.exe") and ProcessCommandLine has "scan" // Common rogue AV names and actions
| where InitiatingProcessFileName !in~ ("explorer.exe") // Unlikely to be directly launched by user
```

**MITRE ATT\&CK**: T1564.004 – Hide Artifacts: Rogue Security Software

</details>

<details>
<summary><strong>82. 💧 Drive-by Download (Watering Hole)</strong></summary>

**Sample Scenario:** Multiple employees visit a partner website that was compromised to host malware. Visiting the page results in a silent download and execution of a trojan.

**Who is Involved**: SOC, Web Security Team  
**Immediate Actions**:

  - Block access to the malicious website.
  - Identify users who visited the compromised site.
  - Scan affected systems for malware.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemoteUrl has "malicious_watering_hole.com" // Replace with identified malicious URL
| where ActionType == "ConnectionAttempt"
| where InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe", "msedge.exe") // Originating from browser
```

**MITRE ATT\&CK**: T1189 – Drive-by Compromise

</details>

<details>
<summary><strong>83. 📧 Spearphishing Attachment</strong></summary>

**Sample Scenario:** A targeted email is sent to the finance team with a .doc attachment containing embedded macros. Once opened, the macro installs an infostealer.

**Who is Involved**: Email Security Team, SOC Analyst  
**Immediate Actions**:

  - Block sender and associated domains.
  - Recall malicious attachments from user inboxes.
  - Analyze the attachment in a sandbox.

**KQL Query**:

```kusto
EmailEvents
| where ThreatTypes has "Malware" and AttachmentCount > 0
| where SenderFromAddress has "suspicious@domain.com" // Identify sender
```

**MITRE ATT\&CK**: T1566.001 – Phishing: Spearphishing Attachment

</details>

<details>
<summary><strong>84. 🔗 Spearphishing Link</strong></summary>

**Sample Scenario:** A CEO receives a phishing email with a URL spoofing a known vendor portal. The link leads to a fake login page designed to harvest credentials.

**Who is Involved**: Email Security Team, SOC Analyst  
**Immediate Actions**:

  - Block sender and associated domains.
  - Block access to the malicious URL.
  - Alert users not to click the link.

**KQL Query**:

```kusto
EmailEvents
| where ThreatTypes has "Phish" and UrlCount > 0
| where Urls has "malicious-link.com" // Identify malicious link
```

**MITRE ATT\&CK**: T1566.002 – Phishing: Spearphishing Link

</details>

<details>
<summary>
<strong>85. ⛓️ Supply Chain Compromise: Compromise Software Dependencies</strong>
</summary>

**Sample Scenario:** A popular open-source npm package used internally is updated with malicious code. Developers unknowingly deploy this in production.

**Who is Involved**: IR Lead, Software Development, Vendor Management  
**Immediate Actions**:

  - Identify compromised software dependencies in projects.
  - Roll back to known good versions of dependencies.
  - Isolate development environments.
  - Communicate with affected vendors.

**KQL Query**:

```kusto
// This is highly dependent on software development tooling logs (e.g., package managers, build systems).
// Conceptual query if logs are integrated:
DevOpsPipelineEvents
| where EventType == "DependencyDownloaded" and PackageName has "compromised_package"
```

**MITRE ATT\&CK**: T1195.002 – Supply Chain Compromise: Compromise Software Dependencies and Development Tools

</details>

<details>
<summary><strong>86. 👃 Compromise via Network Sniffing</strong></summary>

**Sample Scenario:** SOC detects tcpdump running on a non-admin system. Investigation reveals the attacker was capturing unencrypted credentials from the internal network.

**Who is Involved**: Network Security, SOC Tier 3, Forensics  
**Immediate Actions**:

  - Identify the compromised host performing sniffing.
  - Block the host's network access.
  - Analyze captured traffic if available.
  - Implement network segmentation and encryption.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("wireshark.exe", "dumpcap.exe", "tcpdump") // Common sniffing tools
| where InitiatingProcessFileName !in~ ("powershell.exe", "cmd.exe") // Exclude benign usage
```

**MITRE ATT\&CK**: T1040 – Network Sniffing

</details>

<details>
<summary><strong>87. 👤 Man-in-the-Browser</strong></summary>

**Sample Scenario:** A user complains about strange banking behavior. Investigation finds malware injected a script into the browser to alter displayed balances and steal login sessions.

**Who is Involved**: SOC Tier 2, Endpoint Security, Forensic  
**Immediate Actions**:

  - Isolate the affected system.
  - Scan for malware targeting browsers.
  - Force password resets for any accounts used on the compromised browser.

**KQL Query**:

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe", "msedge.exe")
| where ProcessCommandLine has_any ("inject", "hook") // Look for injection attempts into browser processes
| where InitiatingProcessFileName !in~ ("system", "trusted_browser_update.exe") // Exclude legitimate processes
```

**MITRE ATT\&CK**: T1185 – Man-in-the-Browser

</details>

<details>
<summary><strong>88. 🔑 Pass-the-Hash (PtH) Attack</strong></summary>

**Sample Scenario:** Logs show lateral movement using NTLM logons and reused token SIDs. Analysts confirm hash was extracted using Mimikatz and reused across machines.

**Who is Involved**: SOC Tier 3, IAM Team, Forensics  
**Immediate Actions**:

  - Force password resets for affected accounts.
  - Implement Kerberos Armoring (FAST).
  - Isolate the system where the hash was obtained.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "Logon" and LogonType == "Network" // Often network logons
| where AuthenticationPackage == "NTLM" and TargetAccountSid != "" // NTLM authentication, look for specific attributes
| where isnotempty(ProcessTokenUserSid) and ProcessTokenUserSid != TargetAccountSid // Indications of token reuse
```

**MITRE ATT\&CK**: T1550.002 – Use Alternate Authentication Material: Pass the Hash

</details>

<details>
<summary><strong>89. 🎫 Pass-the-Ticket (PtT) Attack</strong></summary>

**Sample Scenario:** An attacker uses Kerberos tickets stolen from a memory dump to impersonate users across services without needing passwords.

**Who is Involved**: SOC Tier 3, IAM Team, Forensics  
**Immediate Actions**:

  - Invalidate forged tickets.
  - Force password resets for affected accounts.
  - Investigate the source of ticket theft.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "TGSRequested" or ActionType == "TGTRequested"
| where LogonType == "Service" // Often associated with service accounts
| where isnotempty(TargetUserSid) and TargetUserSid contains "S-1-5-21" // Look for suspicious TGT/TGS requests
| where isnotempty(AuthenticationPackage) and AuthenticationPackage == "Kerberos"
```

**MITRE ATT\&CK**: T1550.003 – Use Alternate Authentication Material: Pass the Ticket

</details>

<details>
<summary><strong>90. 🖥️ Remote Code Execution (RCE) - Public-Facing Application</strong></summary>

**Sample Scenario:** An unpatched web server receives a crafted POST request that executes system commands. Analysts find the system was running an outdated CMS vulnerable to RCE.

**Who is Involved**: Web Security, SOC Tier 2, Application Owners  
**Immediate Actions**:

  - Take the vulnerable application offline or restrict access.
  - Patch the vulnerability.
  - Forensically analyze for successful RCE and further compromise.

**KQL Query**:

```kusto
// Depends heavily on web server and application logs.
// Example: looking for common RCE commands in web requests.
WebAppLogs
| where Url contains_any ("cmd.exe", "powershell.exe", "sh -c")
| where HttpStatus == 200 // Successful execution
```

**MITRE ATT\&CK**: T1190 – Exploit Public-Facing Application

</details>

<details>
<summary><strong>91. 💻 Command and Scripting Interpreter - PowerShell</strong></summary>

**Sample Scenario:** A user system is flagged for launching PowerShell with obfuscated and encoded commands. Investigation reveals the script downloads and executes a second-stage payload.

**Who is Involved**: SOC Tier 2, Threat Hunter  
**Immediate Actions**:

  - Investigate unusual or obfuscated PowerShell commands.
  - Verify user intent and script origin.
  - Block execution of known malicious PowerShell scripts.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-NoProfile", "IEX", "Invoke-Expression", "Invoke-Webrequest") // Common malicious PowerShell techniques
| where InitiatingProcessFileName !in~ ("explorer.exe", "System") // Exclude benign system/user processes
```

**MITRE ATT\&CK**: T1059.001 – Command and Scripting Interpreter: PowerShell

</details>

<details>
<summary><strong>92. 🍎 Command and Scripting Interpreter - AppleScript</strong></summary>

**Sample Scenario:** An Apple device runs osascript to control the system using a script pulled from a phishing email. The script sends sensitive files to a remote host.

**Who is Involved**: SOC Analyst, macOS Administrators  
**Immediate Actions**:

  - Investigate suspicious AppleScript executions.
  - Identify the source and purpose of the script.
  - Block untrusted script execution.

**KQL Query**:

```kusto
// Requires macOS endpoint logging for process executions and command lines.
// Conceptual KQL for macOS:
MacProcessEvents
| where FileName =~ "osascript" // AppleScript interpreter
| where ProcessCommandLine has_any ("do shell script", "run script")
| where InitiatingProcessFileName !in~ ("Finder", "System") // Exclude benign processes
```

**MITRE ATT\&CK**: T1059.002 – Command and Scripting Interpreter: AppleScript

</details>

<details>
<summary><strong>93. 🔌 Execution Through API (e.g., COM/DCOM)</strong></summary>

**Sample Scenario:** An attacker uses dllhost.exe to invoke COM objects and spawn commands via powershell.exe. The technique bypasses some EDR controls.

**Who is Involved**: SOC Tier 2, Forensics  
**Immediate Actions**:

  - Identify the API being abused and the calling process.
  - Investigate the context of the execution.
  - Look for associated malware or persistence.

**KQL Query**:

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "dllhost.exe" or InitiatingProcessFileName =~ "rundll32.exe" // Common hosts for COM/DCOM
| where ProcessCommandLine has_any ("CoCreateInstance", "GetObject", "activator.CreateInstance") // API calls indicating COM/DCOM interaction
| where InitiatingProcessFileName !in~ ("system", "svchost.exe") // Exclude common benign processes
```

**MITRE ATT\&CK**: T1106 – Execution Through API

</details>

<details>
<summary><strong>94. 💉 Process Injection - DLL Injection</strong></summary>

**Sample Scenario:** Malware injects a DLL into explorer.exe to blend into user activity. Memory analysis confirms presence of a credential harvester.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Isolate the affected system.
  - Capture memory dump for analysis.
  - Identify the injected DLL and the injecting process.
  - Determine the payload and its capabilities.

**KQL Query**:

```kusto
DeviceImageLoadEvents
| where ImagePath has_any (".dll") and InitiatingProcessFileName != FileName // DLL loaded into another process
| where InitiatingProcessFileName !in~ ("svchost.exe", "explorer.exe") // Exclude benign DLL loads
```

**MITRE ATT\&CK**: T1055.001 – Process Injection: DLL Injection

</details>

<details>
<summary><strong>95. 👻 Process Injection - Process Hollowing</strong></summary>

**Sample Scenario:** An attacker launches a legitimate notepad.exe, unmaps its memory, and injects malicious code. Analysts detect the mismatch in the loaded image.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Isolate the affected system.
  - Capture memory dump for analysis.
  - Identify the hollowed process and the injecting process.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "NtUnmapViewOfSection" or ProcessCommandLine has "SetThreadContext" // Common API calls for process hollowing
| where InitiatingProcessFileName != FileName // Process injecting into another
```

**MITRE ATT\&CK**: T1055.012 – Process Injection: Process Hollowing

</details>

<details>
<summary><strong>96. 🧵 Process Injection - Thread Hijacking</strong></summary>

**Sample Scenario:** Analysts detect QueueUserAPC API calls used to insert malicious code into another thread. Memory dump confirms the payload was Cobalt Strike beacon.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Isolate the affected system.
  - Capture memory dump for analysis.
  - Identify the hijacked thread and the injecting process.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "OpenThread" or ProcessCommandLine has "SuspendThread" or ProcessCommandLine has "QueueUserAPC" // Common API calls for thread hijacking
| where InitiatingProcessFileName != FileName // Process injecting into another
```

**MITRE ATT\&CK**: T1055.006 – Process Injection: Thread Hijacking

</details>

<details>
<summary><strong>97. 🔑 Access Token Manipulation - Token Impersonation/Theft</strong></summary>

**Sample Scenario:** Logs show CreateProcessWithTokenW used to start new admin-level processes. Investigation reveals compromised tokens used to elevate access.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Identify the process performing token manipulation.
  - Revoke compromised tokens/sessions.
  - Investigate how initial access was gained.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("CreateProcessWithTokenW", "DuplicateTokenEx", "SetTokenInformation") // API calls related to token manipulation
| where InitiatingProcessFileName !in~ ("lsass.exe", "services.exe") // Exclude benign system processes
```

**MITRE ATT\&CK**: T1134.001 – Access Token Manipulation: Token Impersonation/Theft

</details>

<details>
<summary><strong>98. 🔑 Access Token Manipulation - Create Process with Token</strong></summary>

**Sample Scenario:** The attacker uses a harvested token to spawn cmd.exe as an administrator. The source system was compromised via spearphishing.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Identify the new process created with an elevated token.
  - Investigate the source of the token and the parent process.
  - Revoke compromised tokens.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "CreateProcessWithToken" // Direct API call for creating process with token
| where InitiatingProcessFileName !in~ ("lsass.exe", "services.exe") // Exclude benign system processes
```

**MITRE ATT\&CK**: T1134.002 – Access Token Manipulation: Create Process with Token

</details>

<details>
<summary><strong>99. 👤 Create Account - Local Account (Suspicious)</strong></summary>

**Sample Scenario:** A new local user 'svc_backup1' is created on a production server at midnight. The account is used to establish persistence.

**Who is Involved**: SOC Analyst, IAM Team  
**Immediate Actions**:

  - Investigate the legitimacy of the local account.
  - Disable or delete unauthorized accounts.
  - Identify the source of account creation.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "net user" and ProcessCommandLine has "add"
| where InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe") // Exclude benign administrative commands
| where AccountName != "LegitimateLocalAdmin" // Exclude known local admin creations
```

**MITRE ATT\&CK**: T1136.001 – Create Account: Local Account

</details>

<details>
<summary><strong>100. 👥 Create Account - Domain Account (Suspicious)</strong></summary>

**Sample Scenario:** An unexpected domain account 'tempadmin.test' is created from a compromised helpdesk workstation. SOC revokes the account and blocks the workstation.

**Who is Involved**: SOC Tier 2, IAM Team, Active Directory Administrators  
**Immediate Actions**:

  - Investigate the legitimacy of the new domain account.
  - Disable or delete unauthorized accounts.
  - Identify the source of account creation (e.g., compromised DC, compromised admin workstation).

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "AccountCreated" and AccountType == "Domain"
| where AccountUpn !in~ ("legitimate_domain_admin_script_account") // Exclude known automation
```

**MITRE ATT\&CK**: T1136.002 – Create Account: Domain Account

</details>

<details>
<summary><strong>101. 📁 Data Staging for Exfiltration</strong></summary>

**Sample Scenario:** A large volume of .sql and .csv files is copied to C:\Users\Public\. The staging location matches known exfiltration patterns.

**Who is Involved**: SOC Tier 2, Data Governance, Forensics  
**Immediate Actions**:

  - Identify the staging location and any suspicious files.
  - Prevent further data transfer to the staging area.
  - Investigate the source of the data collection.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath has_any ("C:\\ProgramData\\", "C:\\Temp\\", "C:\\Users\\Public\\") // Common staging directories
| where FileName has_any (".zip", ".rar", ".7z", ".tar.gz", ".bak", ".sql", ".csv") // Common archive/data types
| where ActionType == "FileCreated" and FileSize > 1000000 // Large files, adjust threshold
| where InitiatingProcessFileName !in~ ("winzip.exe", "winrar.exe", "7z.exe", "backup_tool.exe") // Exclude known archiving tools
```

**MITRE ATT\&CK**: T1074 – Data Staged

</details>

<details>
<summary><strong>102. 📦 Data Compressed for Exfiltration</strong></summary>

**Sample Scenario:** A script compresses large files from HR and Finance directories into data_backup.7z. Analysts confirm the action wasn’t part of any scheduled backup.

**Who is Involved**: SOC Tier 2, Data Governance, Forensics  
**Immediate Actions**:

  - Identify the compressed files and their origin.
  - Block any outbound transfer of these files.
  - Investigate the process that performed the compression.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("zip.exe", "rar.exe", "7z.exe", "tar.exe") or ProcessCommandLine has_any (".zip", ".rar", ".7z", ".tar.gz")
| where InitiatingProcessFileName !in~ ("explorer.exe", "msiexec.exe") // Exclude benign user/installer actions
| where InitiatingProcessParentFileName !in~ ("explorer.exe") // Exclude user-initiated archiving
```

**MITRE ATT\&CK**: T1560.001 – Archive Collected Data: Archive via Utility

</details>

<details>
<summary><strong>103. 💾 Data Encrypted for Exfiltration</strong></summary>

**Sample Scenario:** OpenSSL is used on a user's machine to encrypt hundreds of .docx and .pdf files before they are transferred via FTP.

**Who is Involved**: SOC Tier 2, Data Governance, Forensics  
**Immediate Actions**:

  - Identify the encrypted files and their source.
  - Prevent further transfer of encrypted data.
  - Investigate the encryption process and key if possible.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("gpg.exe", "openssl.exe") or ProcessCommandLine has_any ("--encrypt", "-aes256", ".pgp", ".gpg") // Common encryption tools/flags
| where InitiatingProcessFileName !in~ ("outlook.exe") // Exclude legitimate email encryption
```

**MITRE ATT\&CK**: T1560.002 – Archive Collected Data: Archive via Custom Cryptography

</details>

<details>
<summary><strong>104. 🌐 Data Exfiltration Over Web Service</strong></summary>
  
**Sample Scenario:** A script sends sensitive files to transfer.sh from a non-browser process. The SOC confirms the device was compromised by infostealer malware.

**Who is Involved**: SOC Tier 2, Network Security, Web Security  
**Immediate Actions**:

  - Identify the web service used for exfiltration.
  - Block access to the malicious web service URL.
  - Investigate the data being exfiltrated and its source.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemotePort in (80, 443) and RemoteUrl contains_any ("pastebin.com", "file.io", "transfer.sh") // Common web services used for data sharing
| where InitiatingProcessFileName !in~ ("chrome.exe", "firefox.exe", "msedge.exe") // Exclude normal Browse
| where isnotempty(RequestUri) and RequestUri has "upload" // Look for upload indicators
```

**MITRE ATT\&CK**: T1567.002 – Exfiltration Over Web Service: Exfiltration to Cloud Storage

</details>

<details>
<summary><strong>105. 📧 Data Exfiltration Over Email</strong></summary>

**Sample Scenario:** A user sends an external email with attachments named employee_info.csv and client_list.sql. Email DLP triggers and blocks the message.

**Who is Involved**: Email Security Team, SOC Tier 2, Data Governance  
**Immediate Actions**:

  - Block the sender and recipient if external and suspicious.
  - Recall malicious emails.
  - Review email attachments for sensitive data.

**KQL Query**:

```kusto
EmailEvents
| where ActionType == "EmailSent" and AttachmentCount > 0 and RecipientEmailAddress has "external_domain.com" // Sending attachments externally
| where AttachmentName has_any (".zip", ".rar", ".7z", ".sql", ".bak", ".csv") // Suspicious attachment types
```

**MITRE ATT\&CK**: T1567.001 – Exfiltration Over Web Service: Exfiltration to Code Repository

</details>

<details>
<summary><strong>106. 🗑️ Disk Wipe</strong></summary>

**Sample Scenario:** diskpart.exe and format commands are executed remotely on a shared server. Analysts identify the commands were issued by a previously compromised admin account.

**Who is Involved**: IR Lead, Forensics, SOC Tier 3  
**Immediate Actions**:

  - Isolate the system immediately.
  - Power off if possible to preserve forensic data.
  - Attempt data recovery from backups.
  - Identify the destruction tool or method.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("sdelete.exe", "diskpart.exe") or ProcessCommandLine has_any ("clean", "format fs=ntfs quick", "/p") // Commands for disk wiping
| where InitiatingProcessFileName !in~ ("explorer.exe", "cmd.exe") // Exclude common benign usage
```

**MITRE ATT\&CK**: T1488 – Disk Wipe

</details>

<details>
<summary><strong>107. 🌐 Web Compromise via SQL Injection</strong></summary>

**Sample Scenario:** Attackers inject SQL commands via URL parameters in a login page. Logs show a successful dump of customer data using union select payloads.

**Who is Involved**: Web Security, SOC Tier 2, Application Owners  
**Immediate Actions**:

  - Take the vulnerable web application offline or restrict access.
  - Patch the vulnerability.
  - Review logs for data exfiltration.

**KQL Query**:

```kusto
// Requires web server logs.
WebAppLogs
| where UrlQuery has_any ("union select", "sleep(", "xp_cmdshell") // Common SQLi payloads
| where HttpStatus == 200 // Successful injection
```

**MITRE ATT\&CK**: T1190 – Exploit Public-Facing Application

</details>

<details>
<summary><strong>108. 📜 Web Compromise via Cross-Site Scripting (XSS)</strong></summary>

**Sample Scenario:** Users report unexpected popups on a forum site. Analysts find a stored XSS injected via comment fields, stealing session tokens.

**Who is Involved**: Web Security, SOC Tier 2, Application Owners  
**Immediate Actions**:

  - Identify and remove the malicious script.
  - Patch the XSS vulnerability.
  - Alert users if their sessions may have been compromised.

**KQL Query**:

```kusto
// Requires web server logs or WAF logs.
WebAppLogs
| where UrlQuery has_any ("<script>", "javascript:", "onload=") // Common XSS patterns
| where HttpStatus == 200 // Successful delivery
```

**MITRE ATT\&CK**: T1190 – Exploit Public-Facing Application

</details>

<details>
<summary><strong>109. ⚠️ Unsecured Cloud API Exposure</strong></summary>

**Sample Scenario:** Public access to a cloud API is granted via wildcard * permissions in an access policy. Logs show enumeration attempts by external IPs.

**Who is Involved**: Cloud Security Team, DevOps, SOC Tier 2  
**Immediate Actions**:

  - Immediately revoke public access to the API.
  - Review API gateway configurations and access policies.
  - Audit API logs for unauthorized access.

**KQL Query**:

```kusto
// Requires cloud provider API logs (e.g., Azure Activity, AWS CloudTrail).
CloudApiLogs
| where EventName contains "apiGateway" or EventName contains "apiManagement"
| where isnotempty(RequestParameters.Policy) and RequestParameters.Policy has "Allow" and RequestParameters.Policy has "*" // Publicly accessible policy
```

**MITRE ATT\&CK**: T1133 – External Remote Services

</details>

<details>
<summary><strong>110. 🔑 Cloud Instance Metadata Access</strong></summary>

**Sample Scenario:** A containerized app with access to instance metadata makes suspicious requests to retrieve IAM tokens. The app was misconfigured, exposing credentials.

**Who is Involved**: Cloud Security Team, DevOps, SOC Tier 2  
**Immediate Actions**:

  - Investigate the process accessing instance metadata.
  - Ensure only authorized processes have access to metadata.
  - Review IAM roles and permissions.

**KQL Query**:

```kusto
// Requires cloud provider logs and potentially endpoint logs on the instance.
// Conceptual query for instance accessing metadata endpoint:
DeviceNetworkEvents
| where RemoteUrl contains "169.254.169.254" or RemoteUrl contains "localhost/latest/meta-data/" // AWS/Azure metadata service IPs/URLs
| where InitiatingProcessFileName !in~ ("cloud_init.exe", "agent.exe") // Exclude legitimate processes
```

**MITRE ATT\&CK**: T1552.001 – Unsecured Credentials: Cloud Instance Metadata API

</details>

<details>
<summary><strong>111. 🛡️ Defacement of Public Website</strong></summary>

**Sample Scenario:** A defaced homepage appears with a political message. SOC traces the source to a webshell planted weeks earlier in an image upload feature.

**Who is Involved**: Web Security, Communications, SOC Tier 1  
**Immediate Actions**:

  - Take the defaced website offline.
  - Restore from a clean backup.
  - Conduct a forensic analysis to identify how defacement occurred.
  - Update public-facing statements.

**KQL Query**:

```kusto
// Requires web server file integrity monitoring or content delivery network (CDN) logs.
FileIntegrityEvents
| where FilePath contains "wwwroot" and FileName in~ ("index.html", "default.html", "about.html")
| where ActionType == "FileModified" and InitiatingProcessFileName !in~ ("webdeploy.exe", "git.exe") // Exclude legitimate deployments
```

**MITRE ATT\&CK**: T1491 – Defacement

</details>

<details>
<summary><strong>112. 💥 Distributed Denial of Service (DDoS) Attack</strong></summary>

**Sample Scenario:** Public-facing services become unreachable due to massive SYN flood from botnet traffic. The SOC activates upstream DDoS protection.

**Who is Involved**: Network Security, Infrastructure Team, SOC Tier 2  
**Immediate Actions**:

  - Activate DDoS mitigation services.
  - Block attacking IP ranges if identified.
  - Scale up resources if possible.
  - Alert ISPs and upstream providers.

**KQL Query**:

```kusto
NetworkFlows
| summarize TotalTraffic = sum(BytesTransferred) by DestinationIP, DestinationPort, bin(1m)
| where DestinationIP == "Public_Web_Server_IP" and DestinationPort in (80, 443)
| where TotalTraffic > 10000000000 // High traffic volume (e.g., 10GB/min), adjust threshold
```

**MITRE ATT\&CK**: T1499 – Endpoint Denial of Service

</details>

<details>
<summary><strong>113. 🔑 Pass-the-Hash (PtH) (Lateral Movement)</strong></summary>

**Sample Scenario:** Analysts observe NTLM authentication from one server to another using the same hash for multiple services. Log correlation confirms PtH across the subnet.

**Who is Involved**: SOC Tier 2, IAM Team, Forensics  
**Immediate Actions**:

  - Isolate the source and destination systems of the PtH.
  - Force password resets for affected accounts.
  - Implement account monitoring.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "Logon" and LogonType == "Network"
| where AuthenticationPackage == "NTLM" and TargetAccountSid != ""
| where isnotempty(ProcessTokenUserSid) and ProcessTokenUserSid != TargetAccountSid // Look for token reuse across network
| where RemoteIP != LocalIP // Lateral movement
```

**MITRE ATT\&CK**: T1550.002 – Use Alternate Authentication Material: Pass the Hash

</details>

<details>
<summary><strong>114. 🎫 Pass-the-Ticket (PtT) (Lateral Movement)</strong></summary>

**Sample Scenario:** A golden ticket is forged and used to access file servers across domains. Ticket lifetime is unusually long, triggering the alert.

**Who is Involved**: SOC Tier 2, IAM Team, Forensics  
**Immediate Actions**:

  - Invalidate forged tickets.
  - Force password resets for affected accounts.
  - Isolate compromised systems.

**KQL Query**:

```kusto
IdentityLogonEvents
| where ActionType == "TGSRequested" or ActionType == "TGTRequested"
| where LogonType == "Service" // Often service accounts
| where isnotempty(TargetUserSid) and TargetUserSid contains "S-1-5-21"
| where RemoteIP != LocalIP // Lateral movement
```

**MITRE ATT\&CK**: T1550.003 – Use Alternate Authentication Material: Pass the Ticket

</details>

<details>
<summary><strong>115. 🎣 Rogue DHCP Server</strong></summary>

**Sample Scenario:** A network segment reports IP conflicts. Switch logs show a new unauthorized DHCP server giving incorrect gateway settings.

**Who is Involved**: Network Security, System Administrators  
**Immediate Actions**:

  - Locate and disconnect the rogue DHCP server.
  - Review network configuration for unauthorized changes.
  - Force IP renewals on affected clients.

**KQL Query**:

```kusto
// Requires network device logs (e.g., switch logs showing DHCP snooping violations)
NetworkEvents
| where EventType == "RogueDHCPServerDetected"
| where SourceIP != "LegitimateDHCPServerIP"
```

**MITRE ATT\&CK**: T1565.001 – Impair Process Control: Compromise Network Device

</details>

<details>
<summary><strong>116. ⚠️ ARP Poisoning / ARP Cache Spoofing</strong></summary>

**Sample Scenario:** Internal systems report intermittent connectivity. Packet captures reveal mismatched MAC addresses for known gateways, indicating ARP spoofing.

**Who is Involved**: Network Security, SOC Tier 2  
**Immediate Actions**:

  - Identify the source of the ARP poisoning.
  - Isolate the attacking host.
  - Clear ARP caches on affected devices.
  - Implement ARP inspection on switches.

**KQL Query**:

```kusto
// Requires network device logs showing ARP table changes or specific network monitoring tools.
NetworkEvents
| where EventType == "ARPSpoofingDetected" or EventType == "DuplicateIPAddress"
| where DestinationMAC != "LegitimateMACAddress" // Indicating spoofed MAC
```

**MITRE ATT\&CK**: T1557.001 – Adversary-in-the-Middle: ARP Cache Poisoning

</details>

<details>
<summary><strong>117. 🌐 Port Forwarding / Tunneling</strong></summary>

**Sample Scenario:** ngrok.exe is executed on a desktop, exposing internal applications to the internet via public tunnels. The SOC blocks the process and investigates intent.

**Who is Involved**: Network Security, SOC Tier 2  
**Immediate Actions**:

  - Identify the system initiating the port forward/tunnel.
  - Block the connection and disable the tunneling software.
  - Investigate the purpose of the tunnel.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("ssh.exe", "plink.exe", "ngrok.exe") or ProcessCommandLine has_any ("-L", "-R", "-D") // Common tunneling tools/flags
| where InitiatingProcessFileName !in~ ("powershell.exe", "cmd.exe") // Exclude benign usage
```

**MITRE ATT\&CK**: T1572 – Protocol Tunneling

</details>

<details>
<summary><strong>118. 🔑 Credentials from Web Browsers</strong></summary>

**Sample Scenario:** Malware runs on a user's system and reads Chrome's Login Data SQLite file directly. Forensics confirms browser credentials were accessed by a rogue executable.

**Who is Involved**: Forensics, SOC Tier 2  
**Immediate Actions**:

  - Isolate the affected system.
  - Force password resets for any accounts stored in the browser.
  - Scan for malware targeting browser credentials.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath contains_any ("AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\") // Common browser credential locations
| where ActionType == "FileRead" and InitiatingProcessFileName !in~ ("chrome.exe", "firefox.exe", "msedge.exe") // Read by non-browser process
```

**MITRE ATT\&CK**: T1555.003 – Credential Access: Credentials from Web Browsers

</details>

<details>
<summary><strong>119. 📄 Credentials from Password Managers</strong></summary>

**Sample Scenario:** keepass.exe data file is accessed by malicious.ps1. Investigation reveals attacker dumped the KeePass database for offline cracking.

**Who is Involved**: Forensics, SOC Tier 2  
**Immediate Actions**:

  - Isolate the affected system.
  - Force password resets for any accounts stored in the password manager.
  - Scan for malware targeting password managers.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath contains_any ("AppData\\Roaming\\LastPass\\", "AppData\\Local\\KeePass\\") // Common password manager locations
| where ActionType == "FileRead" and InitiatingProcessFileName !in~ ("lastpass.exe", "keepass.exe") // Read by non-manager process
```

**MITRE ATT\&CK**: T1555.005 – Credential Access: Credentials from Password Managers

</details>

<details>
<summary><strong>120. ☁️ Credentials from Cloud Sync Directories</strong></summary>

**Sample Scenario:** Sensitive tokens and config files in a synced OneDrive folder are read by malware. Logs show these were then sent to a known C2 server.

**Who is Involved**: Forensics, Cloud Security Team, SOC Tier 2  
**Immediate Actions**:

  - Isolate the affected system.
  - Force password resets for affected cloud accounts.
  - Review cloud sync application logs.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath contains_any ("OneDrive", "Dropbox", "Google Drive") // Common cloud sync directories
| where FileName contains_any (".credentials", ".config", ".token") // Common credential file names
| where ActionType == "FileRead" and InitiatingProcessFileName !in~ ("onedrive.exe", "dropbox.exe", "googledrive.exe") // Read by non-sync process
```

**MITRE ATT\&CK**: T1555.004 – Credential Access: Credentials from Cloud Sync Directories

</details>

<details>
<summary><strong>121. 💥 Exploitation for Client Execution - Malicious Image</strong></summary>

**Sample Scenario:** An HR staff opens a .jpg attachment from email. The image contains malicious EXIF data that exploits a vulnerable image viewer plugin.

**Who is Involved**: SOC Tier 2, Email Security Team, Desktop Support  
**Immediate Actions**:

  - Block malicious image files via email/web gateways.
  - Scan systems that opened the image.
  - Educate users on opening untrusted image files.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("mspaint.exe", "photos.exe") // Common image viewers
| where InitiatingProcessFileName =~ "outlook.exe" or InitiatingProcessFileName =~ "chrome.exe" // Opened from email or browser
| where InitiatingProcessCommandLine has_any (".jpeg", ".png", ".gif") and InitiatingProcessCommandLine has "malicious_pattern" // Look for suspicious image names/paths
```

**MITRE ATT\&CK**: T1203 – Exploitation for Client Execution

</details>

<details>
<summary><strong>122. 📄 Exploitation for Client Execution - Malicious PDF</strong></summary>

**Sample Scenario:** A user opens a PDF from an unknown vendor. Embedded JavaScript silently installs malware using a known Adobe Reader exploit.

**Who is Involved**: SOC Tier 2, Email Security Team, Desktop Support  
**Immediate Actions**:

  - Block malicious PDF files.
  - Sandbox suspicious PDFs.
  - Scan systems that opened the PDF.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("acrord32.exe", "sumatrapdf.exe") // Common PDF viewers
| where InitiatingProcessFileName =~ "outlook.exe" or InitiatingProcessFileName =~ "chrome.exe" // Opened from email or browser
| where InitiatingProcessCommandLine has ".pdf" and InitiatingProcessCommandLine has "suspicious_pattern" // Look for suspicious PDF names/paths
```

**MITRE ATT\&CK**: T1203 – Exploitation for Client Execution

</details>

<details>
<summary><strong>123. 🕸️ Web Traffic Redirect to Malicious Site</strong></summary>

**Sample Scenario:** Employees visiting a news site are redirected to malicious-redirect.com. The site was compromised to include a malicious ad script.

**Who is Involved**: Network Security, Web Security, SOC Analyst  
**Immediate Actions**:

  - Identify the source of the redirection (e.g., compromised ad, DNS poisoning, compromised router).
  - Block the malicious redirection.
  - Alert users who may have been redirected.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionAttempt" and RemotePort in (80, 443)
| where RemoteUrl has "malicious_redirect.com" and InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe") // Browser connecting to malicious site
| where ReferrerUrl has "legitimate_site.com" // Redirect from a legitimate site
```

**MITRE ATT\&CK**: T1189 – Drive-by Compromise

</details>

<details>
<summary><strong>124. 📤 Exfiltration to Removable Media</strong></summary>

**Sample Scenario:** A user connects a USB drive and transfers over 2GB of .csv and .sql files within minutes. SOC investigates user intent and device usage.

**Who is Involved**: SOC Tier 2, Desktop Support, Data Governance  
**Immediate Actions**:

  - Investigate the files copied to removable media.
  - Block further write access to removable media.
  - Interview the user to understand intent.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath has_any ("E:\\", "F:\\", "G:\\") and ActionType == "FileCreated" // Common drive letters for USB
| where InitiatingProcessFileName !in~ ("explorer.exe") // Not simple drag-and-drop by user
| where FileName has_any (".zip", ".rar", ".7z", ".sql", ".bak") // Suspicious file types
```

**MITRE ATT\&CK**: T1052.001 – Exfiltration Over Physical Medium: Exfiltration to Removable Media

</details>

<details>
<summary><strong>125. ⚙️ Indicator Removal - Timestomp</strong></summary>

**Sample Scenario:** File modification timestamps are set to 2009, while system was built in 2022. The tool timestomp.exe is found in the user's temp folder.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Identify files with inconsistent timestamps.
  - Use forensic tools to recover original timestamps if possible.
  - Identify the tool used for timestomping.

**KQL Query**:

```kusto
// Requires file integrity monitoring tools that capture timestamp changes, not just file creation/modification.
// Conceptual query for a system that logs detailed file metadata changes:
FileIntegrityEvents
| where ActionType == "TimestampModified" and FileName has "suspicious_file.exe"
| where InitiatingProcessFileName !in~ ("svchost.exe", "explorer.exe") // Exclude benign processes
```

**MITRE ATT\&CK**: T1070.006 – Indicator Removal: Timestomp

</details>

<details>
<summary><strong>126. 🔗 Shortcut Modification (Persistence)</strong></summary>

**Sample Scenario:** A .lnk file on the desktop is modified to launch a hidden script before opening the legitimate application. The script connects to an external IP.

**Who is Involved**: SOC Tier 2, Endpoint Security  
**Immediate Actions**:

  - Identify modified shortcuts and their target.
  - Remove the malicious shortcut.
  - Scan for associated malware.

**KQL Query**:

```kusto
DeviceFileEvents
| where FileName endswith ".lnk" and ActionType == "FileModified"
| where InitiatingProcessFileName !in~ ("explorer.exe", "installer.exe") // Exclude legitimate shortcut modifications
| where InitiatingProcessCommandLine has "malicious_command" // Look for suspicious command in shortcut properties
```

**MITRE ATT\&CK**: T1547.009 – Boot or Logon Autostart Execution: Shortcut Modification

</details>

<details>
<summary><strong>127. 🛡️ Network Gateway Compromise</strong></summary>

**Sample Scenario:** Firewall settings are changed to allow open inbound ports. SOC confirms config changes originated from a non-approved source IP.

**Who is Involved**: Network Security, IR Lead, SOC Tier 3  
**Immediate Actions**:

  - Isolate the compromised gateway.
  - Restore from a trusted backup or reconfigure.
  - Review logs for unauthorized access or configuration changes.
  - Force re-authentication for all users.

**KQL Query**:

```kusto
// Requires network device logs (e.g., router/firewall logs)
NetworkDeviceLogs
| where EventType == "ConfigurationChange" and Message has "unauthorized" // Look for suspicious config changes
| where SourceIP !in (LegitimateAdminIPs)
```

**MITRE ATT\&CK**: T1565.001 – Impair Process Control: Compromise Network Device

</details>

<details>
<summary><strong>128. 💾 Windows Management Instrumentation (WMI) Service Modification</strong></summary>

**Sample Scenario:** wmic commands are used to alter the behavior of a Windows service. Analysts discover it was to enable lateral movement via scheduled task.

**Who is Involved**: SOC Tier 2, System Administrators  
**Immediate Actions**:

  - Revert unauthorized WMI service modifications.
  - Investigate the process that made the change.
  - Scan for associated malware.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "wmic service" and ProcessCommandLine has_any ("start", "stop", "change") // WMI service commands
| where InitiatingProcessFileName !in~ ("svchost.exe", "system") // Exclude benign system processes
```

**MITRE ATT\&CK**: T1543.003 – Create or Modify System Process: Windows Service

</details>

<details>
<summary><strong>129. 📦 Software Deployment Tools Abuse</strong></summary>

**Sample Scenario:** A rogue deployment package is pushed using SCCM, containing a remote shell payload. The account used had domain-wide permissions.

**Who is Involved**: SOC Tier 2, System Administrators, IT Operations  
**Immediate Actions**:

  - Identify the compromised deployment tool/account.
  - Suspend unauthorized deployments.
  - Review deployment logs for malicious packages.

**KQL Query**:

```kusto
// Requires logs from deployment tools (e.g., SCCM, Ansible, Puppet).
DeploymentLogs
| where EventType == "PackageDeployed" and PackageName has "malicious_package" // Look for unknown packages
| where User != "LegitimateDeploymentUser"
```

**MITRE ATT\&CK**: T1072 – System Owner/Developer Mode

</details>

<details>
<summary><strong>130. 🛡️ System Information Discovery - OS Version</strong></summary>

**Sample Scenario:** systeminfo and ver commands are executed on multiple hosts from a central admin system. SOC suspects enumeration by attacker post-compromise.

**Who is Involved**: SOC Analyst, System Administrators  
**Immediate Actions**:

  - Investigate who is attempting to discover OS versions.
  - Look for tools or scripts used for vulnerability scanning.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("ver", "systeminfo | findstr /B /C:\"OS Name\"") // Common OS version commands
| where InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe") // Exclude benign user/system commands
```

**MITRE ATT\&CK**: T1082 – System Information Discovery

</details>

<details>
<summary><strong>131. 📜 System Information Discovery - System Time</strong></summary>

**Sample Scenario:** Malware runs time and date to adjust execution timing to match user activity periods. Logs show the commands run via obfuscated script.

**Who is Involved**: SOC Analyst  
**Immediate Actions**:

  - Investigate who is attempting to discover system time.
  - Verify if it's part of a time-based attack or evasion.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("time", "date") // Common time discovery commands
| where InitiatingProcessFileName !in~ ("cmd.exe", "powershell.exe") // Exclude benign user/system commands
```

**MITRE ATT\&CK**: T1124 – System Time Discovery

</details>

<details>
<summary><strong>132. 🔑 Credential Dumping - Cached Credentials</strong></summary>

**Sample Scenario:** Mimikatz is found running on a system with command line sekurlsa::logonpasswords. Analysts confirm cached creds for domain users were exposed.

**Who is Involved**: Forensics, SOC Tier 2  
**Immediate Actions**:

  - Isolate the affected system.
  - Force password resets for affected accounts.
  - Identify the tool used for dumping cached credentials.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "hashdump.exe") or ProcessCommandLine has "cached" // Tools/keywords for cached credentials
| where InitiatingProcessFileName !in~ ("taskmgr.exe") // Exclude benign process analysis
```

**MITRE ATT\&CK**: T1003.002 – OS Credential Dumping: Cached Credentials

</details>

<details>
<summary><strong>133. 💻 Credential Dumping - LSA Secrets</strong></summary>

**Sample Scenario:** Forensics find a dump of LSA secrets on disk. The attacker used lsadump::lsa /inject method to extract service and user secrets.

**Who is Involved**: Forensics, SOC Tier 2  
**Immediate Actions**:

  - Isolate the affected system.
  - Force password resets for any accounts related to LSA secrets.
  - Identify the tool used to dump LSA secrets.

**KQL Query**:

```kusto
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe") or ProcessCommandLine has "lsadump" // Tools/keywords for LSA secrets
| where InitiatingProcessFileName !in~ ("taskmgr.exe") // Exclude benign process analysis
```

**MITRE ATT\&CK**: T1003.004 – OS Credential Dumping: LSA Secrets

</details>

<details>
<summary><strong>134. 🕸️ Network Sniffing - Wireless</strong></summary>

**Sample Scenario:** A rogue device is found collecting Wi-Fi traffic near the office. Wireless logs indicate use of airodump-ng and signal spikes around sensitive areas.

**Who is Involved**: Network Security, SOC Tier 2  
**Immediate Actions**:

  - Identify the source of wireless sniffing.
  - Block the attacking device.
  - Review wireless security configurations.

**KQL Query**:

```kusto
// Requires wireless security logs or network monitoring tools.
NetworkEvents
| where EventType == "WirelessSniffingDetected"
| where SourceMAC != "LegitimateMACAddress"
```

**MITRE ATT\&CK**: T1040 – Network Sniffing

</details>

<details>
<summary><strong>135. 👻 Rogue DNS Server</strong></summary>

**Sample Scenario:** A fake DNS server starts responding to queries with redirect IPs. Logs from endpoints show unusual resolution behavior pointing to malicious sites.

**Who is Involved**: Network Security, SOC Tier 2, System Administrators  
**Immediate Actions**:

  - Locate and disconnect the rogue DNS server.
  - Review DNS configurations on affected clients.
  - Force DNS cache flushing.

**KQL Query**:

```kusto
// Requires network device logs or specific DNS monitoring tools.
NetworkEvents
| where EventType == "RogueDNSServerDetected"
| where SourceIP != "LegitimateDNSServerIP"
```

**MITRE ATT\&CK**: T1565.001 – Impair Process Control: Compromise Network Device

</details>

<details>
<summary><strong>136. 💬 Command and Control - Standard Application Layer Protocol (HTTP/S)</strong></summary>

**Sample Scenario:** A background process initiates repeated connections to a suspicious IP over port 443. The URL matches a known C2 infrastructure in threat intel.

**Who is Involved**: SOC Tier 2, Network Security, Threat Intelligence  
**Immediate Actions**:

  - Block outbound connections to identified C2 IPs/domains.
  - Isolate affected hosts.
  - Analyze network traffic for IOCs.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemotePort in (80, 443) and RemoteUrl in (ThreatIntelligenceIndicator | where Active == true and Url != "" | project Url)
| where ActionType == "ConnectionAttempt" and InitiatingProcessFileName !in~ ("chrome.exe", "firefox.exe") // Exclude normal Browse
```

**MITRE ATT\&CK**: T1071.001 – Application Layer Protocol: Web Protocols

</details>

<details>
<summary><strong>137. 📧 Command and Control - Standard Application Layer Protocol (SMTP)</strong></summary>

**Sample Scenario:** An internal host starts sending outbound SMTP traffic to an external mail server not used by the org. Emails contain base64-encoded payloads.

**Who is Involved**: SOC Tier 2, Email Security Team, Network Security  
**Immediate Actions**:

  - Block outbound SMTP connections to identified C2 domains.
  - Isolate affected hosts.
  - Analyze email headers and content for IOCs.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemotePort == 25 and Protocol == "TCP" // SMTP port
| where RemoteUrl in (ThreatIntelligenceIndicator | where Active == true and Url != "" | project Url) // C2 domain in TI
| where InitiatingProcessFileName !in~ ("outlook.exe", "thunderbird.exe") // Exclude legitimate email clients
```

**MITRE ATT\&CK**: T1071.003 – Application Layer Protocol: Mail Protocols

</details>

<details>
<summary><strong>138. 📦 Command and Control - Standard Application Layer Protocol (FTP)</strong></summary>

**Sample Scenario:** ftp.exe is seen uploading encrypted .zip files from a production system. The receiving IP is not whitelisted or part of business ops.

**Who is Involved**: SOC Tier 2, Network Security  
**Immediate Actions**:

  - Block outbound FTP connections to identified C2 domains.
  - Isolate affected hosts.
  - Analyze FTP logs for unusual file transfers.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemotePort in (20, 21) and Protocol == "TCP" // FTP ports
| where RemoteUrl in (ThreatIntelligenceIndicator | where Active == true and Url != "" | project Url) // C2 domain in TI
| where InitiatingProcessFileName !in~ ("filezilla.exe", "ftp.exe") // Exclude legitimate FTP clients
```

**MITRE ATT\&CK**: T1071.002 – Application Layer Protocol: File Transfer Protocols

</details>

<details>
<summary><strong>139. 📈 Ingress Tool Transfer - Via Remote Services</strong></summary>

**Sample Scenario:** psexec.exe is used to copy and execute a malicious binary on another host. The activity bypasses typical file transfer detection.

**Who is Involved**: SOC Analyst, Network Security  
**Immediate Actions**:

  - Block unauthorized remote service access.
  - Identify the source of the tool transfer.
  - Scan the receiving system for malware.

**KQL Query**:

```kusto
DeviceFileEvents
| where ActionType == "FileCreated" and FolderPath has_any ("C:\\Windows\\Temp\\", "C:\\Users\\Public\\") // Common remote transfer directories
| where InitiatingProcessFileName in~ ("psexec.exe", "winrm.exe", "ssh.exe") // Common remote access tools
| where FileName has_any (".exe", ".dll", ".ps1") // Common tool types
```

**MITRE ATT\&CK**: T1105 – Ingress Tool Transfer

</details>

<details>
<summary><strong>140. 🛡️ Ingress Tool Transfer - Via Removable Media</strong></summary>

**Sample Scenario:** Malware executable found in a USB drive is copied into C:\Windows\Temp and executed. The file is later confirmed to be Cobalt Strike payload.

**Who is Involved**: SOC Analyst, Desktop Support  
**Immediate Actions**:

  - Block further tool transfer via removable media.
  - Scan the removable media and the receiving system.
  - Investigate the user and purpose.

**KQL Query**:

```kusto
DeviceFileEvents
| where ActionType == "FileCreated" and FolderPath has_any ("E:\\", "F:\\", "G:\\") // Common removable media paths
| where FileName has_any (".exe", ".dll", ".ps1") // Common tool types
| where InitiatingProcessFileName !in~ ("explorer.exe") // Not simple drag-and-drop
```

**MITRE ATT\&CK**: T1105 – Ingress Tool Transfer

</details>

<details>
<summary><strong>141. 👻 Unsecured Credentials - Hardcoded Credentials</strong></summary>

**Sample Scenario:** Code scanning alerts show a .ps1 script containing plaintext credentials for the backup server. Git commit history shows it was exposed for 3 weeks.

**Who is Involved**: SOC Tier 2, Development Teams, IT Security  
**Immediate Actions**:

  - Identify the application/script with hardcoded credentials.
  - Remove hardcoded credentials and implement secure credential management.
  - Force password resets for affected accounts.

**KQL Query**:

```kusto
// Requires code/script scanning tools integrated with logs.
// Conceptual query based on alerts from such tools:
CodeScanningAlerts
| where Category == "HardcodedCredential"
| where FileName has_any (".py", ".sh", ".ps1", ".config") // Common script/config files
```

**MITRE ATT\&CK**: T1552.001 – Unsecured Credentials: Hardcoded Credentials

</details>

<details>
<summary><strong>142. 🔒 Unsecured Credentials - Credentials in Files</strong></summary>

**Sample Scenario:** .csv file containing usernames,passwords is created on the desktop and copied to a shared drive. It was readable by all domain users.

**Who is Involved**: SOC Tier 2, Data Governance, System Administrators  
**Immediate Actions**:

  - Identify files containing credentials.
  - Secure or delete the files.
  - Force password resets for affected accounts.

**KQL Query**:

```kusto
DeviceFileEvents
| where FileName has_any (".pem", ".key", ".config", ".txt", ".csv") // Common file types for credentials
| where FilePath contains_any ("password", "credential", "secret") // Keywords in file paths
| where ActionType == "FileCreated" or ActionType == "FileModified"
```

**MITRE ATT\&CK**: T1552.001 – Unsecured Credentials: Credentials in Files

</details>

<details>
<summary><strong>143. 🖥️ Persistence - Boot or Logon Autostart Execution: Windows Services</strong></summary>

**Sample Scenario:** A new service named svcWinLog is created to launch a reverse shell. The service is configured to auto-start on boot.

**Who is Involved**: SOC Tier 2, System Administrators  
**Immediate Actions**:

  - Identify unauthorized services configured for autostart.
  - Disable or remove the malicious service.
  - Investigate the service executable.

**KQL Query**:

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "sc create" or ProcessCommandLine has "sc config"
| where ProcessCommandLine has "binpath" // Specifies executable path
| where InitiatingProcessFileName !in~ ("svchost.exe", "system") // Exclude benign system processes
```

**MITRE ATT\&CK**: T1543.003 – Create or Modify System Process: Windows Service

</details>

<details>
<summary><strong>144. 📜 Persistence - Boot or Logon Autostart Execution: Startup Folder</strong></summary>

**Sample Scenario:** An .exe file is found in the startup folder named update-checker.exe. The file initiates a connection to a foreign IP at every login.

**Who is Involved**: SOC Analyst, Endpoint Security  
**Immediate Actions**:

  - Identify unauthorized files in startup folders.
  - Remove the malicious files.
  - Scan for associated malware.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath contains_any ("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") // Startup folders
| where ActionType == "FileCreated"
| where FileName has_any (".exe", ".bat", ".vbs", ".lnk") // Executable file types
```

**MITRE ATT\&CK**: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

</details>

<details>
<summary><strong>145. 🔗 Persistence - Boot or Logon Autostart Execution: Logon Script</strong></summary>

**Sample Scenario:** A malicious .vbs file is pushed via GPO logon scripts. Every domain user runs the script upon login, which installs spyware.

**Who is Involved**: SOC Tier 2, System Administrators, IAM Team  
**Immediate Actions**:

  - Identify unauthorized logon scripts (GPO, user profile).
  - Remove the malicious script.
  - Review GPO changes.

**KQL Query**:

```kusto
DeviceFileEvents
| where FolderPath contains_any ("%systemroot%\\System32\\GroupPolicy\\User\\Scripts\\Logon", "C:\\Windows\\SYSVOL\\sysvol\\") // Common logon script paths
| where FileName has_any (".bat", ".cmd", ".vbs", ".ps1") // Script file types
| where ActionType == "FileCreated" or ActionType == "FileModified"
```

**MITRE ATT\&CK**: T1037.001 – Boot or Logon Autostart Execution: Logon Script

</details>

<details>
<summary><strong>146. 💻 Persistence - Boot or Logon Autostart Execution: Image File Execution Options Injection</strong></summary>

**Sample Scenario:** Registry entry sets debugger for calc.exe to malware.exe, causing every launch of calculator to run malicious code instead.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Identify malicious IFEO debugger entries.
  - Remove the unauthorized registry entries.
  - Investigate the debugger executable.

**KQL Query**:

```kusto
DeviceRegistryEvents
| where RegistryKey has "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" and RegistryValueName == "Debugger"
| where ActionType == "RegistryKeySet"
| where RegistryValueData has_any (".exe", ".dll") and RegistryValueData !in~ ("drwtsn32.exe", "windbg.exe") // Common legitimate debuggers
```

**MITRE ATT& boundless**: T1546.015 – Event Triggered Execution: Image File Execution Options Injection

</details>

<details>
<summary><strong>147. ⚙️ Persistence - Boot or Logon Autostart Execution: COM Hijacking</strong></summary>

**Sample Scenario:** COM object Shell.Application is hijacked via registry. When a user opens File Explorer, the malware DLL is loaded silently.

**Who is Involved**: Forensics, SOC Tier 3  
**Immediate Actions**:

  - Identify hijacked COM objects.
  - Correct the registry entries to point to legitimate DLLs.
  - Investigate the malicious DLL.

**KQL Query**:

```kusto
DeviceRegistryEvents
| where RegistryKey has_any ("CLSID\\", "InProcServer32\\") // COM-related registry keys
| where ActionType == "RegistryKeySet" and RegistryValueName == "InProcServer32"
| where RegistryValueData has_any ("Temp", "AppData") // DLL loaded from suspicious path
| where InitiatingProcessFileName !in~ ("msiexec.exe", "svchost.exe") // Exclude benign installations
```

**MITRE ATT\&CK**: T1546.014 – Event Triggered Execution: COM Hijacking

</details>

<details>
<summary><strong>148. 💬 Persistence - Boot or Logon Autostart Execution: Screensaver</strong></summary>

**Sample Scenario:** SCRNSAVE.EXE registry value is set to a fake .scr file that launches malware when the screen is idle for 5 minutes.

**Who is Involved**: SOC Analyst, System Administrators  
**Immediate Actions**:

  - Identify malicious screensaver executables.
  - Revert screensaver settings to legitimate ones.
  - Scan for associated malware.

**KQL Query**:

```kusto
DeviceRegistryEvents
| where RegistryKey has "Control Panel\\Desktop" and RegistryValueName == "SCRNSAVE.EXE"
| where ActionType == "RegistryKeySet"
| where RegistryValueData has_any ("Temp", "AppData") // Screensaver from suspicious path
| where InitiatingProcessFileName !in~ ("rundll32.exe") // Exclude benign system processes
```

**MITRE ATT\&CK**: T1547.008 – Boot or Logon Autostart Execution: Screensaver

</details>

<details>
<summary><strong>149. 📤 Data Exfiltration - Alternative Protocol (ICMP)</strong></summary>

**Sample Scenario:** ICMP packets are sent from a host in regular intervals, each with a fixed payload size. Analysts confirm encoded files were tunneled via ping.

**Who is Involved**: Network Security, SOC Tier 2  
**Immediate Actions**:

  - Block outbound ICMP traffic to untrusted destinations.
  - Analyze ICMP packet data for suspicious content.
  - Isolate affected hosts.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where Protocol == "ICMP" and RemoteIPType == "Public"
| summarize PacketCount = count() by DeviceName, RemoteIP
| where PacketCount > 1000 // High volume of ICMP packets
| extend Reason = "Possible ICMP Tunnel"
```

**MITRE ATT\&CK**: T1048.001 – Exfiltration Over Alternative Protocol: Exfiltration Over ICMP

</details>

<details>
<summary><strong>150. 🌐 Data Exfiltration - Alternative Protocol (DNS)</strong></summary>

**Sample Scenario:** SOC observes thousands of outbound DNS queries containing base64-encoded chunks. Upon analysis, it's confirmed that internal documents were being exfiltrated over DNS tunneling.

**Who is Involved**: Network Security, SOC Tier 2  
**Immediate Actions**:

  - Block outbound DNS queries to untrusted DNS servers.
  - Analyze DNS query content for encoded data.
  - Isolate affected hosts.

**KQL Query**:

```kusto
DeviceNetworkEvents
| where RemotePort == 53 and Protocol == "UDP"
| where RemoteUrl has_any (".txt", ".exe", "base64data") // Unusual data patterns in DNS queries
| summarize QueryCount = count() by DeviceName, RemoteUrl
| where QueryCount > 500 // High volume of suspicious DNS queries
```

**MITRE ATT\&CK**: T1048.002 – Exfiltration Over Alternative Protocol: Exfiltration Over DNS

</details>
