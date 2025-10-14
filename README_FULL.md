# TryHackMe — Summit (Purple-Team Detection Lab)

## Overview
This project documents my work on the TryHackMe **Summit** room — a purple-team simulation focused on threat detection engineering.  
I configured security tools, wrote detection rules, and tuned alerts to identify and prevent the execution of multiple malware samples on a simulated Windows workstation.

## Objectives
- Detect and respond to five staged malware samples (`sample1.exe` – `sample5.exe`).
- Build and validate detection logic using SIEM queries, YARA, and Sigma rules.
- Map detections to **MITRE ATT&CK** and prioritize indicators using the **Pyramid of Pain**.
- Capture the final **Sphinx flag** after completing all detections.

## What I Did
- Deployed and monitored a virtual target environment.
- Developed and refined Sigma and YARA detection rules.
- Tuned SIEM alerts to minimize false positives.
- Mapped behavioral detections to MITRE ATT&CK tactics (Execution, Persistence, Defense Evasion).
- Documented detection timestamps and validation notes.

## Tools & Skills
`Detection Engineering` · `YARA/Sigma` · `SIEM/EDR` · `Windows Event Logs`  
`MITRE ATT&CK Mapping` · `Incident Response` · `Threat Simulation`

## Results
- Detected all five malware samples and obtained the final Sphinx flag.
- Improved detection resilience by shifting from static IOC-based rules to behavior-driven detections.
- Reinforced understanding of purple-team collaboration and iterative tuning.

## Sanitized Examples
**Sigma Rule Example**
```yaml
title: Suspicious Child Process of Explorer
description: Detects suspicious child processes spawned from explorer.exe
logsource:
  product: windows
detection:
  selection:
    ParentImage|contains: '\explorer.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
  condition: selection
level: high
```

**YARA Example**
```yara
rule suspicious_sample_behavior {
  strings:
    $a = "UnusualPersistenceCall"
  condition:
    $a
}
```

## Evidence
- Redacted screenshots showing detection results and final flag.
- Timeline of detections (available in `/evidence/detection_timeline.md`).

## Notes
All sensitive data and internal IPs have been redacted.  
This repository contains **educational content only**.

---

### 📜 LICENSE
MIT License © 2025 Shobande Wariz Ayobami
