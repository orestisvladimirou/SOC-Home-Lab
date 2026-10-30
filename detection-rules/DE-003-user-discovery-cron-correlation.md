# DE-003 — Auditd user-discovery and cron-change correlation

**Status:** Positive and negative live tests passed, 30 October 2026 (UTC).  
**Environment:** Windows Hyper-V SOC home lab; Wazuh 4.14.9; Ubuntu 24.04.5 LTS agent `001` (`soc-endpoint`, `10.77.77.30`).  
**Scope:** Authorized controlled detection tests on a monitored lab endpoint, **not** an intrusion or successful persistence.

## Objective

Identify a short sequence in which an account runs a user-identity discovery command and subsequently modifies monitored cron configuration. The multi-stage alert is a **triage signal**, not proof of compromise.

## Rule chain

| Rule | Level | Source / condition | Interpretation |
| --- | ---: | --- | --- |
| [100102](100102-soc-lab-exec.xml) | 5 | Auditd execution event (parent `80789`); `audit.key=soc_lab_exec_test`; `audit.exe=/usr/bin/id` | Test identity-discovery execution |
| [100103](100103-soc-lab-cron.xml) | 8 | Auditd monitored write/attribute event (parent `80780`); `audit.key=soc_lab_cron_change` | Monitored cron configuration activity |
| [100104](100104-soc-lab-correlation.xml) | 10 | Correlation anchored on `100103`, previous `100102`, `frequency=2`, `timeframe=120`, matching `audit.auid` | Multi-stage discovery followed by cron activity |

The rules were inspected on the manager in `/var/ossec/etc/rules/`; `wazuh-analysisd -t` exited **0**, `wazuh-manager` was **active**, and agent `001` was **active**. The three XML files in this repository are transcribed from the displayed manager definitions; they were not remotely exported from the VM.

The endpoint's displayed audit watch list included:

```text
-w /usr/bin/id -p x -k soc_lab_exec_test
-w /etc/crontab -p wa -k soc_lab_cron_change
-w /etc/cron.d -p wa -k soc_lab_cron_change
-w /etc/cron.daily -p wa -k soc_lab_cron_change
```

## Positive control — correlated activity

1. On the endpoint, execute `/usr/bin/id` after `sudo -v` to exercise the identity-discovery watch.
2. Inside the configured 120-second correlation timeframe, write a **comment-only** file under monitored `/etc/cron.d`, using `printf ... | sudo tee /etc/cron.d/soc-lab-correlation-test.disabled`. The `.disabled` test file contained **no runnable cron entry**.
3. Read `/var/ossec/logs/alerts/alerts.json` on the **Wazuh manager**, and inspect the indexed Wazuh dashboard event.

**Observed result:** Rule **100104**, **Level 10**, was indexed at **2026-10-30T09:04:41.425Z**. Its alert carried:

- `agent.name=soc-endpoint`, `agent.id=001`, `agent.ip=10.77.77.30`.
- `data.audit.auid=1000`; the audit record rendered the audit login identity as `endpointadmin`, with `uid=0`/root effective execution under `sudo`.
- `data.audit.exe=/usr/bin/tee`, `data.audit.key=soc_lab_cron_change`.
- Target `/etc/cron.d/soc-lab-correlation-test.disabled`.
- MITRE ATT&CK metadata **T1033** (System Owner/User Discovery) and **T1053.003** (Cron).

The user-discovery **100102** alerts were visible in the manager's alert query. The resulting indexed **100104** document independently establishes that the correlation fired. Because the correlated event is the cron modification, its own `audit.exe` is `/usr/bin/tee`, not `/usr/bin/id`.

## Negative control — standalone cron activity

1. Inspect most recent agent `001` alert for rule `100102`. The displayed check reported **326 seconds** since the last identity-discovery alert, beyond the 120-second window (130-second margin used as a readiness threshold).
2. Without executing `/usr/bin/id` again, write a separate comment-only file at `/etc/cron.d/soc-lab-negative-test.disabled`.
3. Query manager `alerts.json` for that **exact target path**, comparing rule IDs `100103` and `100104`.

**Observed result:** Exactly **one 100103** alert at **2026-10-30T09:11:14.454Z**, and **zero 100104** alerts matched the negative-control target. The terminal printed **`NEGATIVE CONTROL PASSED`**.

Both temporary `.disabled` files were removed with `sudo rm -f`, and separate absence checks printed successful cleanup messages. Their names and contents were deliberate safety constraints: no actual cron job or payload was installed.

## Detection interpretation and limitations

- This is a **single positive and single negative live-test sequence** in an isolated lab. It confirms observed behavior for the tested telemetry and ordering; it does not prove comprehensive detection coverage, absence of false positives, or production readiness.
- The user-discovery rule targets **only** the `/usr/bin/id` executable (with its audit watch); other discovery commands and paths are not covered by this test.
- The cron rule depends on **configured auditd watches** and matching decoded fields. Unwatched persistence paths, auditd/agent interruption, or telemetry loss can cause misses.
- `audit.auid` associates audit events with a login audit identity, **not** definitive proof that the same person intentionally performed both steps. Authorized administration may produce the sequence.
- The MITRE tags describe relevant **techniques**, not confirmed attacker intent or successful scheduled-task persistence.
- No automatic isolation or blocking response was added.
- The alert was reviewed through the Wazuh dashboard and terminal output during testing. **Sanitized DE-003 screenshots have not yet been committed** to the repository; do not cite nonexistent image files.

## Further tuning

Test additional `id` invocation contexts, variants of cron writes, alternate users/sessions, repeated event sequences, and clock/ingestion delays. Compare `audit.auid` values and parent event decoding on the live manager before expanding the rule. Preserve alert IDs, timestamps, exact conditions, and false-positive observations in further revisions.
