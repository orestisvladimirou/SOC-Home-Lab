# SOC Home Lab v1.0 — CV project entry

**SOC Home Lab — Wazuh SIEM & Detection Engineering** | Personal project | 2026  
**Technologies:** Wazuh SIEM 4.14.9, Ubuntu Linux, Windows Hyper-V, auditd, Python, Bash, GitHub, MITRE ATT&CK

- Built and secured a segmented virtual SOC lab with a Wazuh manager, dashboard and monitored Ubuntu endpoint; configured log ingestion, auditd, file integrity monitoring and SSH event visibility.
- Developed and validated **seven custom Wazuh detection rules** covering configuration tampering, privileged commands, identity discovery, cron activity, account changes and sudoers modifications, with positive and negative tests.
- Implemented a **Level 10 multi-stage correlation** linking user discovery and cron modification within 120 seconds, then verified both triggering and non-triggering scenarios.
- Investigated security alerts and documented incident response, SSH-focused CIS hardening and vulnerability triage; verified **10 persistent auditd watches** after an endpoint reboot with **zero lost audit records** reported.

**Repository:** https://github.com/orangemetal/SOC-Home-Lab  
**Visibility:** Private pending owner-approved public release; the link will not be viewable to most recruiters until access is granted.

## Shorter version (space-constrained CV)

**SOC Home Lab — Detection Engineering (Wazuh, Ubuntu, Hyper-V)** | 2026

- Built a segmented virtual SOC monitoring environment and developed **7 custom Wazuh detection rules**, including a **Level 10 MITRE ATT&CK-mapped multi-stage correlation**, tested using positive and negative controls.
- Conducted incident-response investigations, Linux auditd and SSH hardening, and vulnerability triage; verified **10 persistent audit watches** following endpoint reboot.

## Interview discussion points

Describe the detection chain `100102` → `100103` → `100104`, explain why matching audit user ID and a 120-second window help reduce noise without proving malicious intent, and demonstrate how a negative control ruled out an isolated cron write. Then contrast the Linux account database and sudoers path-change detectors with actual changes in account privileges. The lab's principal limitations were the deliberately narrow command/path coverage, benign changes that can raise alerts, the scanner's unresolved historical package-index gap, and the difference between vulnerability detection and remediation.
