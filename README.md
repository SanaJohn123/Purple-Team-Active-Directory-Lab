# 🛡 Purple Team Active Directory Lab: Attack & Defense

![Security Status](https://img.shields.io/badge/Security-Hardened-blue) ![Environment](https://img.shields.io/badge/Environment-Active%20Directory-orange) ![Tools](https://img.shields.io/badge/Tools-Kali%20%7C%20Sysmon%20%7C%20AppLocker-red)

## 📌 Project Overview
*Role:* Security Researcher / Lab Engineer

This project simulates a real-world corporate environment to practice the full lifecycle of a cyberattack (*Red Team) and the subsequent hardening and detection (Blue Team*).

I deployed a vulnerable Active Directory network, performed a complete compromise chain (from reconnaissance to Domain Admin), and then remediated the vulnerabilities using enterprise-grade controls like *AppLocker* and *Sysmon*.

---

## 🏗 Network Architecture
*Hypervisor:* Oracle VirtualBox  
*Network Segments:* Dual-Adapter Setup (NAT + Internal Isolated Network 192.168.10.x)

| Machine | OS | Role | IP Address |
| :--- | :--- | :--- | :--- |
| *DC-Server* | Windows Server 2022 | Domain Controller, DNS, AD DS | 192.168.10.5 |
| *Win11-Client* | Windows 11 Enterprise | Victim Workstation | 192.168.10.4 |
| *Attacker* | Kali Linux 2024 | Red Team Operations | 192.168.10.10 |

> [Link to Network Diagram.png] > (You can upload your diagram to the Diagrams folder and link it here)

---

## 🔴 Phase 1: Red Team Operations (The Attack)
Simulating an external breach and internal lateral movement.

### 1. Reconnaissance & Enumeration
* Used *Nmap* to identify live hosts and open ports (SMB 445, WinRM 5985).
* Utilized *Enum4linux* to extract user lists ("John Parker"), password policies, and group memberships without initial credentials.

### 2. Exploitation (Remote Code Execution)
* Exploited the *WinRM* service using *Evil-WinRM* with compromised credentials.
* Established a stable, interactive PowerShell session on the Domain Controller.

### 3. Credential Dumping
* Performed a *DCSync attack* using *Impacket-secretsdump*.
* Extracted NTLM hashes for all domain users, including the *Administrator* and *KRBTGT* (Golden Ticket) account.

![Evil-WinRM Attack](Screenshots/evil-winrm-shell.png)
Evidence: Successful Remote Shell on the Domain Controller.

---

## 🔵 Phase 2: Blue Team Defense (The Hardening)
Analyzing the attack traces and implementing controls to stop it.

### 1. Forensic Analysis
* Deployed *Sysmon* to capture detailed execution logs.
* Analyzed *Event Viewer* to pinpoint the attack:
    * *Event ID 4720:* Detected unauthorized user creation (hacker_spy).
    * *Event ID 1:* Captured the specific command line arguments used by the attacker.

### 2. Application Whitelisting (AppLocker)
* Configured *Group Policy (GPO)* to enforce strict execution rules.
* *The Rule:* Created a "Wildcard Path Rule" to *DENY* execution of cmd.exe and powershell.exe for standard users.
* *The Result:* Completely neutralized the standard Evil-WinRM shell.

![AppLocker Block](Screenshots/applocker-block.png)
Evidence: Standard user "John" blocked from running Command Prompt.

---

## 🚩 Phase 3: Advanced Evasion (The Bypass)
Simulating an Advanced Persistent Threat (APT) to test defense limits.

Even with AppLocker active, I demonstrated a *"Living off the Land" (LOLBin)* attack to bypass security.

* *Technique:* Used the trusted Microsoft binary *MSBuild.exe* to compile and execute malicious C# code in memory.
* *Payload:* Obfuscated XML payload to evade static Antivirus signatures.
* *Outcome:* Achieved *Arbitrary Code Execution (ACE)*, spawning a Calculator instance despite strict blocking rules.

![MSBuild Bypass](Screenshots/calc-bypass.png)
Evidence: Calculator running via MSBuild, bypassing the blocked CMD in the background.

---

## 🛠 Tools & Technologies Used
* *Infrastructure:* Active Directory Domain Services, DNS, DHCP.
* *Security Standards:* Group Policy Objects (GPO), AppLocker, Windows Firewall.
* *Attack Tools:* Nmap, Metasploit, Evil-WinRM, Impacket, Netcat.
* *Monitoring:* Sysmon, Windows Event Viewer.

## 📄 Documentation
* [Download Full Project Report (PDF)]()
