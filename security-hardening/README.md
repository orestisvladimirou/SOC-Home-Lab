# Security hardening and CIS assessment

This section records observed changes to the Ubuntu endpoint (`soc-endpoint`), not a claim of production security.

## Results and scope

The Wazuh CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 showed **20 passing SSH checks out of 20 filtered `sshd` checks** after remediation. This is 100% of the SSH-specific subset, **not 100% overall system compliance**.

An earlier overall SCA scan showed **123 passed, 114 failed, 42 not applicable, score 51%**. This was an earlier snapshot; the current overall score should be read from a new scan.

## Ubuntu endpoint SSH hardening

| Control | Effective value |
| --- | --- |
| Password authentication | `PasswordAuthentication no` |
| Keyboard-interactive authentication | `KbdInteractiveAuthentication no` |
| Public-key authentication | `PubkeyAuthentication yes` |
| Root SSH access | `PermitRootLogin no` |
| Allowed accounts | `AllowUsers endpointadmin` |
| Forwarding | `DisableForwarding yes` |
| Login banner | `Banner /etc/issue.net` |
| Unresponsive client detection | `ClientAliveInterval 300` and `ClientAliveCountMax 3` |
| Authentication grace | `LoginGraceTime 60` |
| Authentication attempts per connection | `MaxAuthTries 4` |
| Concurrent unauthenticated connections | `MaxStartups 10:30:60` |
| Configuration file access | `600 root:root` on main config and drop-ins |

Permitted MACs: `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512` and `hmac-sha2-256`. Legacy SHA-1 and short-tag UMAC options were removed.

The endpoint uses `/etc/ssh/sshd_config.d/10-soc-lab-hardening.conf` and has an explicit `PermitRootLogin no` in its main `/etc/ssh/sshd_config`. No SSH private keys or raw machine configurations are stored in this repository.

### Verification

- `sudo sshd -t` checked syntax before each reload.
- `sudo sshd -T` verified effective directives.
- `sudo systemctl reload ssh` applied validated changes.
- Fresh key-based SSH sessions from Windows were tested **before** closing working sessions.
- Wazuh SCA was refreshed following agent restarts, and the final SSH filtered view showed **20/20 passed**.

## UFW firewall

UFW was active on the endpoint with default **deny incoming** and **allow outgoing**. The rule permitting SSH on `eth0` limited its source to the Windows lab host (`10.77.77.1`). Wazuh agent telemetry and SSH administration were verified after enabling the firewall.

The CIS assessment includes alternative UFW and nftables deployment checks. An nftables-specific failure is not, by itself, evidence of a malfunctioning UFW configuration. We did not disable UFW merely to improve the score.

## Dashboard HTTPS certificates

The original dashboard server certificate did not include the lab IP `10.77.77.10` in its Subject Alternative Name. A separate local dashboard CA was created; its signed certificate contains `IP:10.77.77.10` and `DNS:wazuh-dashboard`. The browser-facing certificate and key were installed alongside preserved originals, and only the dashboard's `server.ssl` certificate/key paths were changed.

OpenSSL verified the certificate chain, IP and matching public/private keys. The public CA certificate fingerprint was compared on the Windows host before installing trust in the **CurrentUser** trusted root store. Brave subsequently displayed a valid certificate and ceased showing the **Not secure** warning after restart.

**Security caveat:** A locally trusted CA can issue certificates for other sites too. Protect the CA signing key, never publish it, and remove the trust when retiring the lab. Private lab access does not substitute for firewalling and access controls.

## Future priorities

- Assess overall CIS failures by actual risk rather than chasing the score.
- Validate vulnerability findings and affected packages before claiming exploitability.
- Document any risk acceptance and practical remediations.
- Continue documenting controlled detections and incident response.

Related: [architecture](../architecture/README.md) · [custom rules](../detection-rules/README.md) · [IR-001](../incident-reports/IR-001-configuration-tampering.md).
