# SOC Home Lab v1.0 — Portfolio and publication review

**Review date:** 30 October 2026  
**Scope:** `main` branch of `orangemetal/SOC-Home-Lab` (private at review).  
**Decision:** **Technically ready for CV / private recruiter demonstration.** A Git-history and current-asset privacy review was completed on 30 October 2026; **public release remains on hold pending owner approval of the disclosed author email and lab identifiers, plus an optional specialist history scan**. No visibility change was made.

## Portfolio verification

- Seven custom Wazuh XML rules, unique IDs **100100–100106**, present on `main`. Their source matches the tested rule definitions described in the corresponding investigations.
- **DE-003:** discovery-to-cron alert correlation passed a positive test and a standalone cron negative control. No actual cron persistence was established.
- **DE-004:** auditd account-database monitoring passed useradd, read-only and userdel controls; all eight earlier audit watches were verified after a controlled endpoint reboot.
- **DE-005:** sudoers-path monitoring passed write, read-only and removal controls; **all ten** SOC lab audit watches, including two sudoers watches, were verified after a controlled endpoint reboot. Both `auditd` and `wazuh-agent` were active; `augenrules --check` showed No change, `auditctl -s` showed enabled 1 / lost 0 / backlog 0, `visudo -c` parsed OK, and Wazuh agent `001` was Active.
- **IR-001 / IR-002**, hardening, and vulnerability-management case studies describe the limits of their specific authorized simulations, tests and scanner findings.
- **Evidence gallery:** **14** committed PNG excerpts from earlier verified tests. The separate post-reboot screenshot was reviewed in conversation but **is not currently included** as an independent gallery image.
- **Link integrity:** all **167 relative Markdown links and embedded image references** found across the 15 tracked Markdown documents resolved to tracked paths at the time of review.
- **Structural consistency:** the seven XML rule files have unique expected rule IDs and levels; four archived auditd configuration files reproduce the ten tested watches. The new [offline checker](../scripts/check_repository.py) can parse the XML, check file links, and validate PNG chunk CRCs from a clone. This final connected-repository review cross-checked IDs, watch paths, and link targets, and the owner subsequently **ran the Python checker against a fresh local ZIP**: 7 rule IDs, 10 archived watches, 167 relative links and 14 PNGs — **Repository structural checks passed**. This does not rerun live Wazuh analysis.

## Final runtime check boundary

The last observed VM tests on **30 October 2026** showed successful Wazuh rule triggering, read-only negative controls, cleanup detection, `auditd` persistence after reboot, and agent connectivity. Those observations are documented in the individual reports. GitHub source inspection **cannot confirm that the VMs are running now**. A fresh operational check would need to run `wazuh-analysisd -t` and `agent_control -l` on the manager, plus `auditctl -l`, `augenrules --check` and `visudo -c` on the endpoint.

## Privacy and security assessment

The repository remained private during this review. The current Git tree contains no `.env`, private-key, VM-disk or capture-file artifacts by filename. **All 31 current text files** were scanned for common SSH private-key headers, GitHub/cloud token patterns, bearer tokens, obvious assigned credentials and IPv4/email strings. **No obvious embedded credentials, access tokens or publicly routable IP addresses were identified.** The only email-like values in current text were OpenSSH documentation examples, not personal addresses. The `.gitignore` excludes typical sensitive keys, credentials, `.env`, PCAP, logs and VM images; this does not protect previously committed material.

Important disclosure considerations:

1. **Git commit metadata:** Among the repository's historical commits, both a GitHub `noreply` address and a **personal Gmail author email** were observed. Making the repository public can expose author names/emails embedded in Git history. The owner should decide whether this is acceptable or arrange a deliberate history rewrite with appropriate backups.
2. **Lab environment metadata:** Documentation discloses **private (RFC1918) addresses**, local account names, OS/kernel/Wazuh versions, firewall rules and network layout. These are not secrets by themselves but should be approved for publication. The repository does not expose a live internet-accessible address in its architecture documentation.
3. **History scan (completed 30 October 2026):** All **99 commits reachable on `main`** were inspected through GitHub's commit-diff API. Added text was checked for common private-key headers, GitHub and cloud token patterns, bearer tokens and obvious assigned secret/password values; all changed filenames were checked for private keys, credentials, environment files, captures, database files and VM images. **No matching secrets or suspicious filenames were found.** This was a **pattern-based review of commit patches**, not an independent Gitleaks run or a byte-for-byte secret scan of every historical binary Git object. Binary content from older revisions was not exhaustively inspected.
4. **Evidence images (reviewed 30 October 2026):** All **14 current PNG evidence screenshots** were individually opened and visually inspected. The images display monitored paths, internal `10.77.77.30` addresses, and lab account/hostnames including `endpointadmin`, `socadmin`, `soc-endpoint`, and `soc-wazuh`, but **no visible passwords, SSH private keys, personal email addresses, or external access tokens**. These are real environment identifiers; the owner should approve disclosure of that detail. The repaired `de004-account-deletion.png` and `de005-sudoers-cleanup.png` files passed the user's subsequent PNG integrity check.
5. **Remaining engineering backlog:** Some VM vulnerability remediation and historical Wazuh package-index backfill remain open, and standalone screenshots for IR-002 and vulnerability-management exercises remain uncommitted. These are **explicitly scoped follow-up items**; they do not invalidate completion of the v1.0 hands-on portfolio. Neither vulnerability remediation nor comprehensive compliance is claimed.

## Public-release risk classification

| Finding | Risk | Recommended action |
| --- | --- | --- |
| Historic personal Gmail address in commit author metadata | **Privacy decision** | Keep private until the owner accepts the disclosure, or rewrites history deliberately with backups and coordinated clone refresh |
| Internal IPv4 addresses, usernames, hostnames and lab topology | **Low technical risk; potentially identifiable** | Publish only if the owner is comfortable sharing lab structure and local account naming |
| No common secret patterns found across current text and 99 mainline commit diffs | **Reassuring, not proof of absence** | Optional dedicated full-history scanner if public exposure requires higher assurance |
| Fourteen evidence PNGs visually checked | **No obvious visible credentials** | Keep original evidence unchanged; preserve test authenticity |
| Historical binaries outside current tree | **Not exhaustively byte-scanned** | Include them in a specialized history scan if strict publication assurance is desired |

**Recommendation:** Suitable for CV and selective private sharing **now**. A public release is reasonable only after explicitly accepting the author-email disclosure and lab metadata, or sanitizing them in a controlled process. Never rewrite Git history merely to improve appearance without backing up and planning for existing clones.

## Publication decision / approval gate

**Current: PRIVATE. No automatic change to public visibility.**

Before voluntarily publishing, complete the owner-controlled steps:

- [ ] Confirm personal author-email exposure is acceptable **or** safely sanitize repository history.
- [x] Inspect all 14 current evidence PNGs; no visible credentials found. **Owner acceptance of lab identifiers/network disclosure is still required.**
- [x] Review all 99 reachable `main` commits using filename and common-secret-pattern checks on added text; no apparent secrets found.
- [ ] For higher assurance, optionally run a dedicated history-aware secret scanner (for example, Gitleaks on a trusted local clone) and triage findings. This additional tool was **not** run during the connector-based review.
- [x] Confirm open vulnerability and inventory limitations remain identified as unresolved, not misrepresented as patched or fully remediated.
- [ ] Explicitly approve the visibility change.

**CV status:** Ready. Refer to `SOC Home Lab v1.0` as a completed *hands-on project*, with clearly documented optional future work. Until public visibility is approved, give authorized reviewers access by invitation or omit the GitHub hyperlink from a CV sent to people without access.

**No automated response, malware deployment, real intrusion or elevation of test-account privileges was carried out.**
