# 🎣 Phishing-to-Malware Attack Simulation & Incident Response

![Lab Type](https://img.shields.io/badge/Lab%20Type-Offensive%20%2B%20Defensive-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Metasploitable2-557C94?style=for-the-badge)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)

## 📋 Lab Overview

This lab simulates a full **phishing-to-malware attack lifecycle** from both the attacker and SOC analyst perspective. A malicious ELF binary disguised as an invoice document was delivered to a victim machine, establishing a reverse Meterpreter shell and achieving persistence via crontab. The incident was then investigated and documented in a formal Incident Response Report.

**Date:** June 17, 2026  
**Analyst:** Lillian Jones  
**Environment:** VMware Fusion — MacBook Air

-----

## 🖥️ Lab Environment

|Role         |Machine          |IP Address     |OS                   |
|-------------|-----------------|---------------|---------------------|
|Attacker / C2|Kali Linux 2026.1|172.16.148.132 |Debian Linux 6.18.12 |
|Victim       |Metasploitable2  |172.16.148.133 |Ubuntu Linux (legacy)|
|Network      |VMware Host-Only |172.16.148.0/24|—                    |

-----

## ⚔️ Attack Chain

```
[ATTACKER - Kali 172.16.148.132]
        │
        │  1. WEAPONIZATION
        │     msfvenom generates invoice_june2026.elf
        │     linux/x86/meterpreter/reverse_tcp payload
        │
        │  2. DELIVERY
        │     SCP transfer to victim /tmp/
        │     (simulates phishing email attachment download)
        │
        ▼
[VICTIM - Metasploitable2 172.16.148.133]
        │
        │  3. EXECUTION
        │     chmod +x invoice_june2026.elf && ./invoice_june2026.elf &
        │     PID 98588 spawned
        │
        │  4. C2 CALLBACK
        │     Reverse TCP → 172.16.148.132:4444
        │     Meterpreter session 1 opened @ 00:14:50
        │
        │  5. PERSISTENCE
        │     crontab: * * * * * /tmp/invoice_june2026.elf
        │     Re-executes every 60 seconds
        │
        ▼
[ATTACKER ACHIEVES]
  ✓ Interactive shell (Meterpreter)
  ✓ System enumeration (sysinfo, ps, netstat, /etc/passwd)
  ✓ Persistence (T1053.003 Cron Job)
```

-----

## 🔍 Key Evidence Collected

|#|Evidence                |Detail                                            |
|-|------------------------|--------------------------------------------------|
|1|Malicious binary on disk|`/tmp/invoice_june2026.elf` — 207 bytes ELF 32-bit|
|2|Active C2 connection    |`172.16.148.132:46284 → :4444 ESTABLISHED`        |
|3|Malicious process       |PID 98588 `invoice_june2` visible in netstat      |
|4|Meterpreter session     |Session 1 opened `2026-06-17 00:14:50 -0400`      |
|5|Crontab persistence     |`* * * * * /tmp/invoice_june2026.elf`             |
|6|Cron re-execution       |PIDs 124713, 124715 — payload relaunched every 60s|
|7|Parent process chain    |`ruby (88984)` → `invoice_june2 (98588)`          |
|8|/etc/passwd enumeration |Full user list extracted post-compromise          |

-----

## 🛡️ MITRE ATT&CK Mapping

|Tactic           |Technique             |ID       |Evidence                                     |
|-----------------|----------------------|---------|---------------------------------------------|
|Initial Access   |Phishing              |T1566    |Payload delivered as spoofed invoice document|
|Execution        |Unix Shell            |T1059.004|ELF binary executed; spawned /bin/sh         |
|Command & Control|Non-App Layer Protocol|T1095    |Raw TCP reverse shell on port 4444           |
|Command & Control|Non-Standard Port     |T1571    |TCP 4444 used for C2                         |
|Discovery        |Process Discovery     |T1057    |`ps aux` enumerated all running processes    |
|Discovery        |Network Connections   |T1049    |`netstat -antp` revealed active connections  |
|Discovery        |Account Discovery     |T1087    |`cat /etc/passwd` enumerated local users     |
|Persistence      |Cron Job              |T1053.003|`* * * * *` crontab re-executes payload      |
|Defense Evasion  |Masquerading          |T1036    |Binary named to appear as invoice document   |

-----

## 📡 Indicators of Compromise (IOCs)

```
TYPE            INDICATOR                              CONTEXT
─────────────────────────────────────────────────────────────────────
File            invoice_june2026.elf                   Malware payload — /tmp/
File            cron.txt                               Persistence config — /tmp/
IP              172.16.148.132                         C2 server (attacker)
Port            TCP 4444                               Meterpreter C2 port
Process         invoice_june2 (PID 98588)              Initial payload execution
Process         /bin/sh -c invoice_june2026.elf        Cron-spawned shell
Crontab         * * * * * /tmp/invoice_june2026.elf    Persistence mechanism
Connection      172.16.148.132:46284 → :4444           Active C2 channel
```

-----

## 🔎 Detection Opportunities

**Snort/Suricata — Detect Meterpreter C2:**

```
alert tcp any any -> any 4444 (msg:"Possible Meterpreter C2 on port 4444"; sid:9000001; rev:1;)
```

**Auditd — Monitor Crontab Modifications:**

```
-w /var/spool/cron -p wa -k crontab_modification
```

**Key Behavioral Indicators:**

- ELF binary executing from `/tmp/` — legitimate software never runs from /tmp
- Outbound TCP to port 4444 — known Metasploit default C2 port
- `/bin/sh` spawned by cron executing a binary from `/tmp/`
- Process name matching filename pattern (invoice_*.elf)

-----

## 🧰 Tools Used

|Tool                      |Purpose                    |
|--------------------------|---------------------------|
|`msfvenom`                |Payload generation         |
|`Metasploit multi/handler`|C2 listener                |
|`meterpreter`             |Post-exploitation framework|
|`netstat`                 |Network connection analysis|
|`ps aux`                  |Process enumeration        |
|`crontab`                 |Persistence mechanism      |

-----

## 📁 Repository Contents

```
phishing-incident-response/
├── README.md                                    ← This file
├── report/
│   └── IR_Report_Phishing_LillianJones_2026.docx  ← Full IR report
├── evidence/
│   ├── 01_payload_created.png                   ← msfvenom output
│   ├── 02_listener_session_opened.png           ← Meterpreter session
│   ├── 03_netstat_c2_active.png                 ← Live C2 connection
│   ├── 04_persistence_crontab.png               ← Crontab entry
│   └── 05_cron_reexecution_ps.png               ← Multiple payload PIDs
└── iocs.txt                                     ← IOC reference file
```

-----

## 📄 Incident Response Report

A full professional IR report is included in the `/report` directory covering:

- Executive Summary
- Attack Timeline
- Forensic Evidence & IOCs
- MITRE ATT&CK Mapping
- Detection Rules
- Containment & Remediation Steps
- Lessons Learned

-----

## 👩‍💻 About

**Lillian Jones** | Cybersecurity Analyst  
AAS Cybersecurity & Networking — DeVry University (Expected February 2027)  
Pursuing CompTIA Security+ | SOC Analyst Candidate  
GitHub: [LJones910109](https://github.com/LJones910109)
