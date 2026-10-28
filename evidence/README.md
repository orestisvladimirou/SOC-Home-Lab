# Portfolio evidence — pending review

**No screenshots or raw logs have been committed to this folder yet.** This is an index of the evidence we plan to add once images have been selected and sanitized.

| Proposed file | What it should demonstrate | Status |
| --- | --- | --- |
| `ssh-cis-20-of-20.png` | 20/20 passing **SSH-related** CIS checks | Not added |
| `fim-custom-positive.png` | Rule 100100, Level 10, for the monitored configuration file | Not added |
| `fim-custom-negative.png` | Normal FIM events for `control-config.conf` | Not added |
| `sudo-custom-positive.png` | Rule 100101, Level 8, for `stat /etc/shadow` | Not added |
| `sudo-custom-negative.png` | Normal `sudo` rule for `stat /etc/hosts` | Not added |
| `ir001-recovery.png` | Recovery event and matching original SHA-256 | Not added |

## Safe-publication checklist

- Review the **entire screenshot**, including browser tabs and terminal paths.
- Remove personal account names or identifiers you do not intend to publish.
- Never include passwords, API tokens, session cookies, private SSH keys, CA signing keys, `/etc/shadow` contents or credential hashes.
- Exclude virtual-machine disk images, network captures containing sensitive traffic, unfiltered logs and secret-bearing configuration files.
- Keep descriptions precise: these are **authorized exercises**, not proof of a real attack.
- Use clearly labeled positive and negative controls.

**Important:** Even a private repository has lasting commit history. Do not commit unsanitized artifacts expecting to remove them later without additional work.
