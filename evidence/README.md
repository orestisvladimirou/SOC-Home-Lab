# SOC lab evidence gallery

These screenshots were captured from the **authorized October 2026 home-lab exercises** and added after review. Each image is an excerpt of an existing user-provided capture: **cropped to relevant fields**, with unrelated screen areas removed, and converted to **high-contrast monochrome** to improve readability and avoid including irrelevant interface information. Some images join noncontiguous portions of the **same original screenshot** into a compact vertical layout; no alert fields or result values were invented.

All user identifiers visible in the selected screenshots are **lab-only accounts** (for example `endpointadmin`), and all shown IP addresses are **private `10.77.77.0/24` lab addresses**. No credentials, tokens, session cookies, private keys or signing keys are included.

## Verified evidence

| File | What the image shows | Related documentation |
| --- | --- | --- |
| [SSH CIS: 20/20 passed](ssh-cis-20-of-20.png) | The Wazuh assessment filtered to `sshd`, displaying all 20 checks as Passed | [Hardening](../security-hardening/README.md) |
| [FIM custom positive](fim-custom-positive.png) | `100100`, Level 10, for a modified `critical-config.conf` | [Rule 100100](../detection-rules/README.md) |
| [Sudo custom positive](sudo-custom-positive.png) | `100101`, Level 8, for `/usr/bin/stat /etc/shadow` | [Rule 100101](../detection-rules/README.md) |
| [Sudo negative control](sudo-custom-negative.png) | Ordinary `5402` event for `/usr/bin/stat /etc/hosts`, not `100101` | [Rule 100101](../detection-rules/README.md) |
| [IR-001 recovery alert](ir001-recovery.png) | `100100` recovery modification showing the restored SHA-256 | [IR-001](../incident-reports/IR-001-configuration-tampering.md) |
| [IR-001 terminal hash](ir001-terminal-hash.png) | The harmless test file restored to `security_mode=normal` with verified `sha256sum` | [IR-001](../incident-reports/IR-001-configuration-tampering.md) |

### SSH hardening — 20 passing checks

![20 of 20 passing SSH-related CIS checks](ssh-cis-20-of-20.png)

### Detection engineering — positive and negative examples

![Custom FIM rule 100100 fires on sensitive file modification](fim-custom-positive.png)

![Custom sudo rule 100101 fires for /etc/shadow reference](sudo-custom-positive.png)

![Normal sudo event for /etc/hosts negative control](sudo-custom-negative.png)

### Incident recovery — Wazuh and endpoint verification

![Wazuh alert for restored configuration file](ir001-recovery.png)

![Ubuntu terminal verifying restored configuration and SHA-256](ir001-terminal-hash.png)

## IR-002 — correlated alert evidence to be archived

A second authorized exercise generated rule `100101` (Level 8) followed **8.702 seconds later** by rule `100100` (Level 10) on the same endpoint. A subsequent FIM alert recorded a recovery modification and the known-good SHA-256. See [IR-002 — correlated privileged activity and configuration tampering](../incident-reports/IR-002-correlated-privileged-activity.md).

The **IR-002 event overview, recovery alert, and endpoint `sudo` journal screenshots were all reviewed in the conversation**, but their image files are **not committed to this repository yet**. A timestamped, sanitized transcription of the journal's relevant lines has been added to the [IR-002 report](../incident-reports/IR-002-correlated-privileged-activity.md). It confirms that `endpointadmin` used the same `pts/1` session to run the test commands with elevated privileges. We should still add cropped and sanitized IR-002 screenshots as visual evidence later.

## VM-001 — kernel vulnerability assessment (pending screenshot publication)

The lab identified **101 Critical** and **862 High** Wazuh vulnerability inventory records for the running Ubuntu kernel `6.8.0-147-generic`. The [VM-001 case study](../vulnerability-management/VM-001-rdma-kernel-exposure.md) documents the package checks, the RDMA module exposure assessment and the temporary `modprobe` configuration for `siw` and `rtrs-server`.

The VM-001 vulnerability dashboard and terminal verification screenshots were reviewed during the exercise but **have not yet been committed to GitHub**. Suggested sanitized evidence:
- `vm001-active-kernel-findings.png` — Critical/High Wazuh inventory summary for the running kernel.
- `vm001-module-availability.png` — Kernel configuration and module files, without unrelated terminal content.
- `vm001-mitigation-verification.png` — Dry-run `install /bin/false` output and `lsmod` showing both targeted modules unloaded.

Do not label a reduced vulnerability count or a configured module restriction as a kernel patch.

## Interpreting the evidence

- The **20/20** result applies **only to the displayed SSH-specific subset** of CIS checks. It is **not the overall CIS compliance score**.
- Rule `100100` does not distinguish attacker tampering from approved restoration: the recovery alert is correctly labeled as **authorized**.
- `sudo stat /etc/shadow` accesses **file metadata**, not password hashes. The custom alert is an investigative signal, **not evidence of credential theft**.
- The FIM *negative-control* test generated two ordinary FIM events, and the custom query returned zero matches, as observed during the exercise. **A screenshot of that particular zero-result query was not captured**, so it is not presented as image evidence.
- These screenshots demonstrate the described individual tests, not exhaustive coverage or production readiness.

## Review checklist before public release

Before changing repository visibility to public, re-review the complete repository history, images and linked documentation for personal details, credentials, identifiers, and any claims that require qualification. The screenshots remain on the **private** repository while this review is pending.
