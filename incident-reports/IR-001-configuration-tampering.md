# IR-001 — Simulated configuration file tampering

| Field | Detail |
| --- | --- |
| Case | `IR-001` |
| Classification | **Authorized lab exercise; no verified compromise** |
| Status | **Closed — Recovery verified** |
| Alert | Wazuh custom FIM rule `100100`, Level 10 |
| Endpoint | `soc-endpoint` (`10.77.77.30`), Ubuntu 24.04.5 LTS |
| SIEM | Wazuh 4.14.9 |
| File | `/opt/soc-fim-test/critical-config.conf` |
| ATT&CK context | T1565.001 — Stored Data Manipulation (simulated) |
| Event window | October 28–29, 2026 |

## 1. Executive summary

A controlled exercise simulated tampering with a configuration file inside a dedicated test directory monitored by Wazuh File Integrity Monitoring (FIM). The original file contained `security_mode=normal` and was intentionally changed to `security_mode=disabled`.

Custom rule `100100` generated a Level 10 alert for the modification. Investigation correlated the FIM evidence (path, change event, before/after hashes and timestamps) with Ubuntu `sudo` journal entries. The file was then restored to its known-good value. Wazuh generated another file modification alert during recovery, and the recovered SHA-256 matched the original SHA-256.

This was **not a real security breach**; the test file did not control actual system security.

## 2. Scope and evidence sources

- **Endpoint telemetry:** Wazuh agent's real-time `syscheck` FIM stream.
- **Security events:** Wazuh indexed alerts, including `rule.id: 100100`.
- **Local corroboration:** `journalctl -t sudo` showing the `endpointadmin` account executing privileged `tee` against the test file.
- **Host verification:** `cat`, `stat`, `sha256sum` on the Ubuntu endpoint.

A `sudo` audit entry identifies the authenticated local account and executed command. It does not independently establish the real-world person operating that session.

## 3. Reconstructed timeline

Times below are in **UTC**, as shown in Ubuntu's journal/`stat` output. The Wazuh dashboard displayed equivalent times **two hours later** in the browser's local time zone.

| UTC timestamp | Observed activity |
| --- | --- |
| 2026-10-28 23:22:50 | `endpointadmin` used `sudo tee` to create the monitored test configuration with the normal value. |
| 2026-10-28 23:23:37 | `endpointadmin` used `sudo tee` again to change the file to `security_mode=disabled`. |
| 2026-10-28 23:23:37 | Wazuh FIM recorded a real-time modification and generated rule `100100` (Level 10). |
| 2026-10-28 23:36:33–23:36:38 | Investigator checked current file contents, ownership, permissions, modification time and `sudo` journal. |
| 2026-10-28 23:37:26 | Known-good value restored using `sudo tee`. |
| 2026-10-28 23:37:26 | Wazuh generated a further rule `100100` alert for the recovery modification; original hash restored. |

## 4. Key technical findings

**Alert details**

- Detection: `syscheck_integrity_changed`, `syscheck.event: modified`.
- File: `/opt/soc-fim-test/critical-config.conf`.
- Rule: `100100`, Level 10, custom group `soc_lab`.
- Changed attributes included file size, `mtime`, MD5, SHA-1 and SHA-256.
- File ownership after modification: `root:root`; permissions `644`.
- Ubuntu `sudo` journal associated the change with `endpointadmin` executing `/usr/bin/tee /opt/soc-fim-test/critical-config.conf`.

**Cryptographic integrity check**

| State | SHA-256 |
| --- | --- |
| Before unauthorized-change simulation (known good) | `cdd61b78080715eb1425003023e858f388923763267b420703b07b55983100a3` |
| After simulated tampering | `3f99971dc1dba642cfbbacc3777821c1ef5ac7366ebe4832591744cb755e0207` |
| After authorized recovery | `cdd61b78080715eb1425003023e858f388923763267b420703b07b55983100a3` |

The restored hash matches the original exactly. This supports **byte-for-byte restoration of the contents** represented by the hash; it does not by itself establish recovery of all file metadata or a complete host recovery.

## 5. Incident response

**Triage:** Classified the Level 10 alert as a targeted file modification in the lab's dedicated FIM directory.

**Investigation:** Reviewed the alert context and paired the change timestamp with `sudo` journal events. Confirmed that `security_mode=disabled` was the observed post-change value.

**Containment decision:** No isolation, account suspension or network blocking was necessary: the action was an approved exercise on a harmless test file. This decision must not be generalized to a real compromised system.

**Recovery:** Replaced the test file content with `security_mode=normal`.

**Verification:** Checked the restored contents and SHA-256 on the host, and reviewed Wazuh's second alert. The second alert was classified as **authorized recovery activity**, not a new attacker event.

## 6. Lessons learned

1. Custom Wazuh FIM rules can escalate high-interest file changes above generic alerts.
2. Combining endpoint logs with SIEM telemetry improves the reconstruction of a file-change timeline.
3. Hash comparison provides strong evidence of restored **contents**.
4. A detection alert should be investigated in context; authorized recovery can trigger the same rule as malicious tampering.
5. Evidence should be documented without overstating the exercise as a real intrusion.

## 7. Evidence index

Screenshots are intentionally **not included yet**. Before publishing, review images for sensitive information and place approved, sanitized exports in [`evidence/`](../evidence/README.md):

- Original rule `100100` Level 10 alert with before/after SHA-256.
- Endpoint output showing simulated changed value and relevant `sudo` entries.
- Recovery rule `100100` alert with restored SHA-256.
- Terminal output confirming the known-good contents and hash.

## 8. Closure

**Outcome:** Simulated tampering successfully detected and investigated; test configuration restored; hash verification passed; no evidence of an actual adversarial intrusion was identified in this exercise.
