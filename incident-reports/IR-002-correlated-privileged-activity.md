# IR-002 — Correlated privileged activity and configuration tampering

| Field | Detail |
| --- | --- |
| Case ID | `IR-002` |
| Classification | **Authorized, simulated SOC incident** — no verified compromise |
| Status | **Recovery verified**; local journal corroboration not yet archived |
| Endpoint | `soc-endpoint`, Wazuh agent `001`, lab IP `10.77.77.30` |
| Monitoring | Wazuh 4.14.9; `journald` sudo events and real-time file integrity monitoring (FIM) |
| Rules | `100101` (Level 8) and `100100` (Level 10) |
| Test file | `/opt/soc-fim-test/critical-config.conf` |
| Exercise date | October 29, 2026 (dashboard-local time) |

## 1. Executive summary

This authorized lab scenario tested a short sequence of events that would warrant investigation if observed without context:

1. A privileged command referencing the Linux authentication file `/etc/shadow` generated custom Wazuh rule **100101**, Level **8**.
2. Approximately **8.7 seconds** later, modification of a designated test configuration file generated custom rule **100100**, Level **10**.
3. The harmless test file was returned to its previously established known-good contents. A further Wazuh FIM alert recorded the recovery modification, including the restored SHA-256, which matched the established original.

These alerts demonstrate **time-correlated observations**, not proof of a common attacker, credential theft, or a causal relationship between the two events. Both actions were part of the lab exercise. No actual system security setting was disabled.

## 2. Detection and timeline

**Time basis:** Times in the screenshots below are displayed as dashboard-local time (UTC+02:00). UTC times are two hours earlier.

| Dashboard time, October 29, 2026 | Observation | Evidence status |
| --- | --- | --- |
| **02:07:23.604** | Rule `100101`, Level 8 — `/usr/bin/stat /etc/shadow` appeared on `soc-endpoint`. | Confirmed in Wazuh events overview |
| **02:07:32.306** | Rule `100100`, Level 10 — `critical-config.conf` modified on the same endpoint. | Confirmed in Wazuh events overview |
| **02:10:03.755** | Rule `100100`, Level 10 — another FIM modification event for `critical-config.conf` during recovery. | Confirmed in Wazuh event detail |

**Alert spacing:** The two initial alerts are **8.702 seconds** apart. Three older matching alerts also appeared in the same hour-long query; these were excluded from the IR-002 sequence as belonging to prior exercises.

The lab instructions generated the events using:

```bash
sudo /usr/bin/stat /etc/shadow > /dev/null
printf 'security_mode=disabled\nir002_case=simulated\n' | sudo tee /opt/soc-fim-test/critical-config.conf
```

`stat` obtains **metadata only** and does not read or exfiltrate password hashes. The other command modified only a synthetic test file in the FIM directory.

**Evidence limitation:** The Wazuh alert overview supports the timing, host, and rule correlation; the incident-specific `sudo journalctl` command output has not yet been provided for independent review in this report. Therefore, the specific `sudo` account and session attribution for **IR-002** remain **not independently corroborated by archived journal evidence**. Previous incident IR-001 included local journal corroboration, but that cannot be substituted for IR-002.

## 3. Recovery and integrity evidence

The lab's known-good test content from IR-001 is:

```text
security_mode=normal
```

The planned IR-002 simulation changed it to:

```text
security_mode=disabled
ir002_case=simulated
```

The recovery event explicitly records a file size change **44 → 21 bytes**, consistent with removal of the simulated marker and restoration of the one-line configuration.

| State | SHA-256 | Source |
| --- | --- | --- |
| Known-good value established during IR-001 | `cdd61b78080715eb1425003023e858f388923763267b420703b07b55983100a3` | Prior verified Wazuh/terminal evidence |
| Before IR-002 recovery (tampered state) | `95c0d9f67dbddca1dba638e0ea025ae42d2bef19bee66a67ab8133b2ef8ed8d3` | IR-002 recovery alert `syscheck.sha256_before` |
| After IR-002 recovery | `cdd61b78080715eb1425003023e858f388923763267b420703b07b55983100a3` | IR-002 recovery alert `syscheck.sha256_after` |

The post-recovery SHA-256 matches the established baseline exactly. This supports **byte-for-byte recovery of the test file contents**; it does not prove recovery of every possible attribute or the host as a whole.

The visible recovery event showed:

- Wazuh rule: `100100`, Level `10`
- Agent: `001` / `soc-endpoint`
- Decoder: `syscheck_integrity_changed`
- Event type: `modified`
- File: `/opt/soc-fim-test/critical-config.conf`
- Wazuh event ID: `1793232603.19570`
- Changed fields included file size, modification time, MD5, SHA-1 and SHA-256

The alert for recovery is **not a second hostile act**. The rule matches both unauthorized changes and authorized restoration of the monitored file.

## 4. Triage, severity and response decision

**Triage severity:** The two rules assign Levels **8** and **10** to their individual alerts. These are **rule severities**, not a validated overall business-impact score. The observed pair would justify analyst review when context is unknown.

**Corroborated facts:** The two alert types originated from the same endpoint within 8.702 seconds. The file-integrity alert confirmed a change to a designated test configuration file. Recovery was later observed by FIM and the known-good SHA-256 was restored.

**Not established:** The alerts do not show actual password hash access, exfiltration, persistence, lateral movement, or compromise. Without the IR-002 `sudo` journal excerpt, shared-account attribution should not be stated as an independently verified finding.

**Containment decision:** Do **not** isolate the VM, disable `endpointadmin`, or block the management host for this authorized simulation. There is no evidence of ongoing unauthorized activity, and destructive or disruptive containment would be disproportionate. In a genuine incident, account identity, approval, command execution context, exposure and scope would be checked before taking such actions.

**Recovery:** Restore the synthetic configuration to `security_mode=normal` and validate its hash. The Wazuh recovery alert confirms the known-good SHA-256.

## 5. Lessons learned

1. Multiple custom alerts can be grouped into a coherent investigative timeline without automatically inferring attack progression.
2. FIM captures file-level integrity evidence; sudo journal events are needed to strengthen actor and command attribution.
3. Rule severity and true incident impact are separate assessments.
4. An authorized remediation can trigger the same high-severity rule as a suspicious modification.
5. Comparing post-recovery hashes to a known-good baseline makes file-content restoration testable.

## 6. Evidence and follow-up

**Reviewed screenshot evidence in the conversation:**
- IR-002 Wazuh events list showing the two new alerts at **02:07:23.604** and **02:07:32.306**.
- IR-002 recovery alert at **02:10:03.755**, showing before/after sizes and SHA-256 hashes.

These IR-002 screenshots have **not yet been uploaded to the repository**; do not confuse the earlier [IR-001 screenshots](../evidence/README.md) with evidence for this separate case.

**Pending evidence for a fully corroborated case:**
- Preserve a sanitized excerpt of the IR-002 `sudo` journal entries and confirm the executing account and commands.
- Add sanitized IR-002 screenshots to the [evidence gallery](../evidence/README.md), clearly labeled as this exercise.

## 7. Outcome

**Recovery verified; investigation documentation completed with an explicit local-log evidence gap.** This exercise shows custom alert correlation, severity analysis, justified non-containment in an authorized lab, and FIM-confirmed recovery. It does **not** demonstrate a real adversarial intrusion.
