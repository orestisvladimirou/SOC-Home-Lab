# SOC Home Lab v1.0 — Portfolio and publication review

**Review date:** 30 October 2026  
**Scope:** `main` branch of `orangemetal/SOC-Home-Lab` (private at review).  
**Decision:** **Technically ready for CV / private recruiter demonstration.** **Public release on hold** pending the repository owner's privacy decision and a complete Git-history review. No visibility change was made.

## Portfolio verification

- Seven custom Wazuh XML rules, unique IDs **100100–100106**, present on `main`. Their source matches the tested rule definitions described in the corresponding investigations.
- **DE-003:** discovery-to-cron alert correlation passed a positive test and a standalone cron negative control. No actual cron persistence was established.
- **DE-004:** auditd account-database monitoring passed useradd, read-only and userdel controls; all eight earlier audit watches were verified after a controlled endpoint reboot.
- **DE-005:** sudoers-path monitoring passed write, read-only and removal controls; **all ten** SOC lab audit watches, including two sudoers watches, were verified after a controlled endpoint reboot. Both `auditd` and `wazuh-agent` were active; `augenrules --check` showed No change, `auditctl -s` showed enabled 1 / lost 0 / backlog 0, `visudo -c` parsed OK, and Wazuh agent `001` was Active.
- **IR-001 / IR-002**, hardening, and vulnerability-management case studies describe the limits of their specific authorized simulations, tests and scanner findings.
- **Evidence gallery:** **14** committed PNG excerpts from earlier verified tests. The separate post-reboot screenshot was reviewed in conversation but **is not currently included** as an independent gallery image.
- **Link integrity:** all **167 relative Markdown links and embedded image references** found across the 15 tracked Markdown documents resolved to tracked paths at the time of review.
- **Structural consistency:** the seven XML rule files have unique expected rule IDs and levels; four archived auditd configuration files reproduce the ten tested watches. The new [offline checker](../scripts/check_repository.py) can parse the XML, check file links, and validate PNG chunk CRCs from a clone. This final connected-repository review cross-checked IDs, watch paths, and link targets, but **did not execute the Python checker against a full local clone** or rerun live Wazuh analysis.

## Final runtime check boundary

The last observed VM tests on **30 October 2026** showed successful Wazuh rule triggering, read-only negative controls, cleanup detection, `auditd` persistence after reboot, and agent connectivity. Those observations are documented in the individual reports. GitHub source inspection **cannot confirm that the VMs are running now**. A fresh operational check would need to run `wazuh-analysisd -t` and `agent_control -l` on the manager, plus `auditctl -l`, `augenrules --check` and `visudo -c` on the endpoint.

## Privacy and security assessment

The repository remained private during this review. The current Git tree contains no `.env`, private-key, VM-disk or capture-file artifacts by filename. A pattern review of the current text files found **no obvious embedded SSH private keys, GitHub tokens, common cloud access-key patterns, or hard-coded secret assignments**. The `.gitignore` excludes typical sensitive keys, credentials, `.env`, PCAP, logs and VM images.

Important disclosure considerations:

1. **Git commit metadata:** Among the repository's historical commits, both a GitHub `noreply` address and a **personal Gmail author email** were observed. Making the repository public can expose author names/emails embedded in Git history. The owner should decide whether this is acceptable or arrange a deliberate history rewrite with appropriate backups.
2. **Lab environment metadata:** Documentation discloses **private (RFC1918) addresses**, local account names, OS/kernel/Wazuh versions, firewall rules and network layout. These are not secrets by themselves but should be approved for publication. The repository does not expose a live internet-accessible address in its architecture documentation.
3. **History scope:** The accessible history listed **79 commits** at review; the earliest and an intermediate tree were sampled for filenames and did not reveal suspicious secret-bearing artifacts, but **the complete contents of every historical revision have not been exhaustively secret-scanned**. `.gitignore` never guarantees sensitive files were absent from past commits.
4. **Images:** The 14 current evidence PNGs were previously cropped and reviewed for relevant terminal output. Re-review every image at its full original resolution for personal identifiers, workstation names, hidden credentials or unexpected UI context before publication.
5. **Remaining engineering backlog:** Some VM vulnerability remediation and historical Wazuh package-index backfill remain open, and standalone screenshots for IR-002 and vulnerability-management exercises remain uncommitted. These are **explicitly scoped follow-up items**; they do not invalidate completion of the v1.0 hands-on portfolio. Neither vulnerability remediation nor comprehensive compliance is claimed.

## Publication decision / approval gate

**Current: PRIVATE. No automatic change to public visibility.**

Before voluntarily publishing, complete the owner-controlled steps:

- [ ] Confirm personal author-email exposure is acceptable **or** safely sanitize repository history.
- [ ] Inspect the current 14 evidence PNGs at full resolution and review private lab identifiers/network details.
- [ ] Run an exhaustive history-aware secret scan from a trusted local clone (for example, Gitleaks with `git` history available), triage hits, and rotate any real secrets found rather than merely deleting a commit.
- [ ] Confirm that open vulnerability and inventory limitations are described without implying remediation.
- [ ] Explicitly approve the visibility change.

**CV status:** Ready. Refer to `SOC Home Lab v1.0` as a completed *hands-on project*, with clearly documented optional future work. Until public visibility is approved, give authorized reviewers access by invitation or omit the GitHub hyperlink from a CV sent to people without access.

**No automated response, malware deployment, real intrusion or elevation of test-account privileges was carried out.**
