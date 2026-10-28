# Custom Wazuh detection rules

These rules were developed and tested in the SOC home lab using Wazuh **4.14.9**, Ubuntu **24.04.5 LTS**, and monitored agent `soc-endpoint` (`001`).

The repository contains **only the custom rules authored for the lab**, not Wazuh's built-in rules, any credentials or certificate material.

## Detection catalog

| Rule | Severity | Input | Trigger | Validation |
| --- | --- | --- | --- | --- |
| [`100100`](soc_lab_fim_rules.xml) | 10 | Wazuh FIM (`syscheck`), parent `550` | Real-time *modification* of `/opt/soc-fim-test/critical-config.conf` | Positive + negative tests, live alert |
| [`100101`](soc_lab_sudo_rules.xml) | 8 | Decoded `sudo` logs, parent `5402` or `5403` | Privileged command with whitespace-delimited `/etc/shadow` argument | Positive + negative `wazuh-logtest` tests, live alert |

### Rule 100100 — Sensitive configuration change

- **Purpose:** Elevate a targeted FIM modification from the normal built-in file-integrity alert to a specific Level 10 investigation signal.
- **MITRE ATT&CK context:** T1565.001 (Stored Data Manipulation), as a classification of the simulated change, **not a claim of an actual attacker**.
- **Positive:** Write `security_mode=disabled` to the existing lab file → rule `100100` generated a live alert.
- **Negative:** Create and modify `control-config.conf` in the same directory → ordinary FIM events appeared; **no** `100100` alert for that path.
- **Recovery:** Restore `security_mode=normal` → the same rule generated another expected alert. Detection alone does not determine if a modification is malicious or authorized.

### Rule 100101 — Privileged command referencing authentication file

- **Purpose:** Surface elevated administrative commands referencing the sensitive `/etc/shadow` path for investigation.
- **Why two parent IDs:** `wazuh-logtest` selected rule `5403` (first observed `sudo` execution) even when normal live events could match `5402`. The rule was corrected to `<if_sid>5402,5403</if_sid>` to handle both.
- **Positive:** `sudo /usr/bin/stat /etc/shadow > /dev/null` → live `100101`, Level 8.
- **Negative:** `sudo /usr/bin/stat /etc/hosts > /dev/null` → normal `5402`, Level 3.
- **Interpretation:** `stat` checks file metadata; it does **not** demonstrate password hash extraction, exfiltration or compromise.

## Installation on a Wazuh manager

For an appropriately isolated practice environment, copy the XML files to `/var/ossec/etc/rules/`, assign the manager's `wazuh:wazuh` ownership and restrictive permissions, validate, then restart the manager to load changes:

```bash
sudo chown wazuh:wazuh /var/ossec/etc/rules/soc_lab_*_rules.xml
sudo chmod 640 /var/ossec/etc/rules/soc_lab_*_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
# Restart only after the configuration test passes:
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

The rule files expect compatible parent rule IDs and event fields. Confirm them against the installed Wazuh ruleset before reuse in other versions.

## Testing approach

1. Validate ruleset syntax with `wazuh-analysisd -t`.
2. Test positive and negative log samples with `wazuh-logtest`.
3. Generate controlled endpoint activity.
4. Confirm the indexed alert's `rule.id`, `rule.level`, `agent.name`, decoded fields and file path or command.
5. Verify **negative controls**, not just positive detection.
6. Investigate benign triggers and potential false positives before enabling automated response.

## Limitations and future improvements

- A rule matching an exact path or command argument will not cover every way to access or modify a sensitive file. For example, rule 100101 is **not** an exhaustive credential-access detector.
- Rule 100100 also triggers on authorized recovery: analyst context matters.
- No automatic containment was configured for either custom rule.
- Expand testing to alternate command formats, permissions, false positives and alert-volume tuning before treating these as production-quality detections.

See [IR-001](../incident-reports/IR-001-configuration-tampering.md) for an investigation driven by rule 100100.
