🛡️ CyArt Red Teaming — Week 2
Intern: Ganavi N
Program: CyArt Internship Program
Week: 2 — Advanced Threat Analysis, Security Frameworks & Incident Response

---
📁 Repository Structure
```
cyart-red-teaming/
└── Week 2/
    ├── README.md
    ├── Documentation/
    │   ├── theoretical_knowledge_report.pdf
    │   ├── practical_application_report.pdf
    │   └── incident_response_report.pdf
    ├── Screenshots/
    │   ├── 01_sigma_rule_test.png
    │   ├── 02_elastic_query_results.png
    │   ├── 03_remnux_strings_output.png
    │   ├── 04_hybrid_analysis_report.png
    │   ├── 05_openvas_scan_results.png
    │   ├── 06_defectdojo_import.png
    │   ├── 07_suricata_rule_test.png
    │   ├── 08_wazuh_alert.png
    │   ├── 09_crowdsec_block.png
    │   └── 10_ale_risk_matrix.png
    ├── Code/
    │   ├── sigma_powershell.yml
    │   ├── suricata_block.rules
    │   └── ale_calculator.xlsx
    └── Capstone/
        ├── capstone_report.pdf
        └── attack_flowchart.png
```
---
📚 Theoretical Knowledge
1. Advanced Threat Analysis
🔷 STRIDE Threat Modeling
STRIDE is a threat modeling framework used to identify security threats by category:
Category	Full Form	Example Threat
S	Spoofing	Attacker impersonates a legitimate user via stolen credentials
T	Tampering	Modifying data in transit (e.g., MITM attack on HTTP traffic)
R	Repudiation	User denies performing an action; no audit logs exist
I	Information Disclosure	Sensitive data leaked via misconfigured S3 bucket
D	Denial of Service	SYN flood overwhelms a web server, making it unavailable
E	Elevation of Privilege	Low-privileged user exploits SUID binary to gain root
Applied to a Web Application:
Login page → Spoofing risk (weak authentication)
API endpoints → Tampering risk (no input validation)
Admin panel → Elevation of Privilege (broken access control)
---
🔷 MITRE ATT&CK Framework
The MITRE ATT&CK framework documents adversary tactics, techniques, and procedures (TTPs).
Key Tactics (in order):
#	Tactic	Example Technique
1	Reconnaissance	T1595 — Active Scanning
2	Initial Access	T1566 — Phishing
3	Execution	T1059 — Command & Scripting Interpreter
4	Persistence	T1053 — Scheduled Task/Job
5	Privilege Escalation	T1068 — Exploitation for Privilege Escalation
6	Defense Evasion	T1027 — Obfuscated Files or Information
7	Credential Access	T1110 — Brute Force
8	Lateral Movement	T1021 — Remote Services
9	Collection	T1005 — Data from Local System
10	Exfiltration	T1041 — Exfiltration Over C2 Channel
Phishing mapped to ATT&CK:
Tactic: Initial Access
Technique: T1566.001 (Spearphishing Attachment)
---
🔷 Advanced Attack Vectors
APT (Advanced Persistent Threat):
Long-term, stealthy intrusion by well-funded actors
Example: APT29 (Cozy Bear) — Russian state-sponsored group
Supply Chain Attack:
Compromise software/hardware before it reaches the target
Example: SolarWinds 2020 — Attackers inserted malicious code into Orion software updates, affecting 18,000+ organizations including US government agencies
Zero-Day Exploit:
Exploits an undisclosed, unpatched vulnerability
Detection is extremely difficult — no signature exists yet
Example: Stuxnet used 4 zero-days against Iranian nuclear facilities
---
2. Security Frameworks
🔷 NIST Cybersecurity Framework (CSF)
Function	Purpose	Example Activity
Identify	Asset inventory, risk assessment	Catalog all servers and their data classification
Protect	Access controls, encryption, training	Enable MFA, encrypt drives, conduct security awareness
Detect	Monitoring, anomaly detection	Deploy SIEM (ELK Stack / Wazuh) for log analysis
Respond	Incident handling, communication	Follow IR playbook, notify stakeholders
Recover	Restoration, lessons learned	Restore from backup, update controls post-incident
Implementation Tiers:
Partial — Ad hoc, no formal processes
Risk-Informed — Aware but inconsistent
Repeatable — Formal policies defined
Adaptive — Continuously improved, threat-informed
---
🔷 ISO 27001 Key Controls
Control	Domain	Description
A.12.3	Operations Security	Information backup
A.12.4	Operations Security	Logging and monitoring
A.14.2	System Acquisition	Security in development
A.8.2.1	Asset Management	Classification of information
A.16.1	Incident Management	Reporting security events
Ransomware Scenario mapped to ISO 27001:
A.12.3 → Regular encrypted backups (offline/offsite)
A.8.2.1 → Classify sensitive data to prioritize recovery
A.16.1 → Report incident within defined timeframe
---
3. Incident Response Lifecycle (SANS)
```
Preparation → Detection → Containment → Eradication → Recovery → Lessons Learned
```
Phase	Key Actions
Preparation	Playbooks, tools, training, communication plans
Detection	SIEM alerts, IDS/IPS, user reports
Containment	Isolate affected systems, block malicious IPs
Eradication	Remove malware, patch vulnerability
Recovery	Restore from clean backup, monitor for re-infection
Lessons Learned	Update playbooks, report findings
---
4. Risk Management
ALE Calculation:
```
ALE = SLE × ARO

SLE (Single Loss Expectancy) = Asset Value × Exposure Factor
ARO (Annualised Rate of Occurrence) = How often per year the event occurs

Example — Ransomware:
  SLE = $10,000
  ARO = 0.2 (once every 5 years)
  ALE = $10,000 × 0.2 = $2,000/year
```
Risk Matrix (5×5):
	Very Low Impact	Low	Medium	High	Critical
Almost Certain	Low	Medium	High	Critical	Critical
Likely	Low	Medium	High	High	Critical
Possible	Very Low	Low	Medium	High	High
Unlikely	Very Low	Very Low	Low	Medium	High
Rare	Very Low	Very Low	Low	Low	Medium
Ransomware scenario: Likelihood = Possible, Impact = Critical → HIGH risk
---
🔧 Practical Application
Task 1 — Threat Hunting with Sigma Rules
Tool: Elastic Security + Sigma Rules
Sigma Rule — Suspicious PowerShell Activity:
```yaml
title: Suspicious PowerShell Activity
status: stable
description: Detects PowerShell execution with -Command flag
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-Command'
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```
Elastic Query Results (Event ID 4688):
Timestamp	Process	Command Line	Notes
2024-04-29 10:00:00	powershell.exe	-Command Write-Host Test	Suspicious execution
2024-04-29 10:02:15	powershell.exe	-Command Get-Process	Enumeration attempt
2024-04-29 10:05:44	powershell.exe	-Command Invoke-WebRequest	Potential download
📸 See: Screenshots/01_sigma_rule_test.png, Screenshots/02_elastic_query_results.png
---
Task 2 — Malware Analysis (REMnux)
Tool: REMnux, Hybrid Analysis
Static Analysis — strings output summary (50 words):
Running `strings calc.exe > output.txt` on REMnux revealed Windows API calls including `CreateProcess`, `GetModuleHandle`, and `RegOpenKeyEx`, indicating registry interaction. The string `Microsoft.NET` identified the runtime dependency. The path `C:\Windows\System32` confirmed system-level execution. No obfuscation or suspicious URL patterns were found, consistent with a legitimate Windows binary.
REMnux Commands:
```bash
strings calc.exe > output.txt
peframe calc.exe
head -50 output.txt
```
📸 See: Screenshots/03_remnux_strings_output.png, Screenshots/04_hybrid_analysis_report.png
---
Task 3 — Vulnerability Management Pipeline
Tools: OpenVAS → DefectDojo
Top 3 Vulnerabilities (Metasploitable2 — 192.168.10.4):
Vulnerability	CVSS Score	Severity	Description	Remediation
vsftpd 2.3.4 Backdoor	10.0	CRITICAL	Remote backdoor — opens shell on port 6200	Upgrade vsftpd immediately
Samba usermap_script RCE	9.3	CRITICAL	Unauthenticated RCE via Samba username field	Patch Samba to 3.6.x+
UnrealIRCd Backdoor	7.5	HIGH	Hardcoded backdoor in IRC daemon	Remove/disable IRC service
📸 See: Screenshots/05_openvas_scan_results.png, Screenshots/06_defectdojo_import.png
---
Task 4 — Incident Response Simulation
Tools: Velociraptor, MITRE Caldera
Phishing Simulation — 100-word summary:
A mock phishing payload was deployed using MITRE Caldera on a Windows VM. The attack began with a crafted email containing a malicious link that executed a PowerShell command upon click. Caldera's agent established a C2 channel, simulating attacker persistence. Velociraptor was then used to collect forensic artifacts: process listings (`SELECT * FROM processes`) revealed the PowerShell process spawned from Outlook, while network connections (`SELECT * FROM netstat`) showed outbound traffic to the C2 IP. All artifacts were exported to CSV and analysed for IOCs including suspicious process names, parent-child relationships, and unexpected outbound connections.
Artifact Collection (Velociraptor VQL):
```sql
-- Collect running processes
SELECT Pid, Name, Exe, CommandLine, CreateTime FROM processes
WHERE Name =~ "powershell|cmd|wscript"

-- Collect network connections
SELECT Pid, Family, Type, Status, Laddr, Raddr FROM netstat
WHERE Status = "ESTABLISHED"
```
📸 See: Screenshots/ (Velociraptor + Caldera outputs)
---
Task 5 — Network Defense with Suricata
Suricata Rule:
```
drop ip 192.168.10.4 any -> any any (msg:"Block Malicious IP 192.168.10.4"; sid:1000001; rev:1;)
```
ATT&CK Mapping:
Alert	Tactic	Technique ID	Technique Name	Notes
Suspicious HTTP	Command and Control	T1071.001	Web Protocols	Outbound C2 traffic
SYN Flood	Impact	T1498	Network DoS	Volumetric attack
SSH Brute Force	Credential Access	T1110.001	Password Guessing	Repeated auth failures
Port Scan	Reconnaissance	T1046	Network Service Discovery	Pre-exploit recon
📸 See: Screenshots/07_suricata_rule_test.png
---
Task 6 — Risk Assessment (ALE)
Ransomware Scenario:
```
Asset Value        = $50,000
Exposure Factor    = 20% (0.20)
SLE                = $50,000 × 0.20 = $10,000
ARO                = 0.2 (once every 5 years)
ALE                = $10,000 × 0.2  = $2,000/year

Countermeasure cost: $500/year (offline backup)
ALE after control:  $10,000 × 0.05 = $500/year
Cost-benefit:       $2,000 − $500 = $1,500 savings/year ✅
```
📸 See: Screenshots/10_ale_risk_matrix.png
---
Task 7 — Incident Response Report
📄 See: Documentation/incident_response_report.pdf
IR Flowchart:
```
[Detection] → [Triage] → [Containment] → [Eradication] → [Recovery] → [Lessons Learned]
     ↓              ↓            ↓               ↓              ↓               ↓
  SIEM Alert    Severity    Isolate Host    Remove IOC     Restore       Update Playbook
               Assessment   Block IP       Patch Vuln     from Backup   & Controls
```
---
Task 8 — Capstone: Full Incident Response Cycle
Attack Simulation: vsftpd 2.3.4 backdoor via Metasploit
Attacker IP: 192.168.10.3 (Kali) → Target: 192.168.10.4 (Metasploitable2)
Wazuh Detection Alerts:
Timestamp	Source IP	Alert Description	MITRE Technique	Severity
2024-04-29 11:00:00	192.168.10.3	FTP Login Attempt	T1078	Medium
2024-04-29 11:00:02	192.168.10.3	VSFTPD Backdoor Triggered	T1190	Critical
2024-04-29 11:00:05	192.168.10.3	Root Shell Opened (port 6200)	T1059	Critical
2024-04-29 11:02:11	192.168.10.3	Outbound Reverse Shell	T1105	High
Containment — CrowdSec Block:
```bash
sudo cscli decisions add --ip 192.168.10.3 --duration 24h --reason "vsftpd exploit"
# Verify block
ping 192.168.10.3   # Should timeout if firewall rules applied
```
200-word Capstone Report:
On 29 April 2024, an attack was detected against the internal test server (192.168.10.4) from IP 192.168.10.3. The attacker exploited the vsftpd 2.3.4 backdoor vulnerability (CVE-2011-2523, CVSS 10.0), achieving unauthenticated root access within two seconds of initiating the FTP connection. Wazuh SIEM generated four sequential alerts mapping to MITRE ATT&CK techniques T1190 (Initial Access), T1059 (Execution), and T1105 (Command and Control). Immediate containment was performed by adding the attacker IP to CrowdSec's blocklist, preventing further connections. A Netcat reverse shell attempt post-exploitation was blocked. Root cause analysis identified the unpatched vsftpd service as the entry point. Recommendations: (1) immediately replace vsftpd 2.3.4 with a patched version or disable the FTP service entirely; (2) implement network segmentation to isolate public-facing services; (3) configure Wazuh with automated response rules to block attacking IPs in real time; (4) enforce a patch management policy with monthly vulnerability scans using OpenVAS. All artifacts and logs have been preserved for forensic review.
📸 See: Capstone/capstone_report.pdf, Screenshots/08_wazuh_alert.png, Screenshots/09_crowdsec_block.png
---
🔗 Tools & Resources Used
Tool	Purpose	Link
MITRE ATT&CK	Threat framework reference	attack.mitre.org
Elastic Security	SIEM + threat hunting	elastic.co
Sigma Rules	Detection rule format	github.com/SigmaHQ/sigma
OpenVAS / GVM	Vulnerability scanning	greenbone.net
DefectDojo	Vulnerability management	defectdojo.com
Suricata	Network IDS/IPS	suricata.io
Wazuh	Host-based SIEM	wazuh.com
CrowdSec	Collaborative IPS	crowdsec.net
Velociraptor	Endpoint forensics	docs.velociraptor.app
MITRE Caldera	Adversary simulation	caldera.mitre.org
REMnux	Malware analysis	remnux.org
Hybrid Analysis	Sandbox analysis	hybrid-analysis.com
NIST CSF	Security framework	nist.gov/cyberframework
---
📌 Submission Checklist
[x] README.md with full workflow and steps
[ ] theoretical_knowledge_report.pdf
[ ] practical_application_report.pdf
[ ] incident_response_report.pdf
[ ] All screenshots in Screenshots/ folder
[ ] sigma_powershell.yml
[ ] suricata_block.rules
[ ] ale_calculator.xlsx
[ ] capstone_report.pdf
[ ] attack_flowchart.png
---
CyArt Internship Program — Week 2 | Ganavi N
