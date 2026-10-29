# Wazuh server firewall hardening — verified lab exercise

**Date:** 29 October 2026  
**System:** `SOC-Wazuh-Server` (Ubuntu 24.04.5 LTS, Wazuh 4.14.9)  
**Status:** Firewall enabled; intended access verified from Windows and the Wazuh endpoint.

## Objective

Reduce the server's network attack surface by permitting only required connections from known management and endpoint hosts while maintaining Wazuh services and administration. All work was performed in a private, authorized Hyper-V SOC lab.

## Baseline before hardening

The Wazuh server had two network interfaces:

| Interface | Observed address | Purpose |
| --- | --- | --- |
| `eth0` | `10.77.77.10/24` | `SOC-Lab` internal network |
| `eth1` | `172.17.136.138/20` at test time | Hyper-V Default Switch, used for outbound connectivity |

`sudo ufw status verbose` initially showed **inactive**. `sudo ufw show added` found no existing user rules, and `sudo nft list ruleset | head -n 80` produced no rules in the observed output.

Before the change, `sudo ss -lntup` showed:

| Port / protocol | Listening service | Bind address / risk |
| --- | --- | --- |
| 22/TCP | `sshd` | All IPv4 and IPv6 interfaces — management access potentially exposed to connected networks |
| 443/TCP | Wazuh dashboard (`node`) | `0.0.0.0` — web interface potentially accessible through both interfaces |
| 1514/TCP | `wazuh-remoted` | `0.0.0.0` — endpoint event transport |
| 1515/TCP | `wazuh-authd` | `0.0.0.0` — agent enrollment |
| 55000/TCP | Wazuh API (`python3`) | All IPv4 and IPv6 interfaces — management API |
| 9200/TCP, 9300/TCP | Indexer (`java`) | `127.0.0.1` mapped loopback — not bound to the external interfaces |
| 53/TCP/UDP | Local DNS resolver | Loopback only |
| 68/UDP | DHCP client | Default Switch interface |

**Exposure interpretation:** A listening socket on all interfaces does not by itself imply exposure to the public internet, and Hyper-V Default Switch uses a NAT-managed virtual network. However, unrestricted management listeners without a host firewall are unnecessary exposure for this lab.

## Firewall policy applied

The active SSH session was confirmed to originate from Windows `10.77.77.1` and terminate at server `10.77.77.10:22`. The user prepared all allow rules *before* enabling UFW.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow in on eth0 from 10.77.77.1 to 10.77.77.10 port 22 proto tcp
sudo ufw allow in on eth0 from 10.77.77.1 to 10.77.77.10 port 443 proto tcp
sudo ufw allow in on eth0 from 10.77.77.30 to 10.77.77.10 port 1514 proto tcp
sudo ufw allow in on eth0 from 10.77.77.30 to 10.77.77.10 port 1515 proto tcp

sudo ufw show added
sudo ufw enable
sudo ufw status verbose
```

The firewall reported **`Status: active`**, with logging **on (low)**, default **deny incoming / allow outgoing**, and exactly the intended four incoming allowances:

| Source | Port | Intent |
| --- | --- | --- |
| Windows host `10.77.77.1`, `eth0` only | 22/TCP | SSH management |
| Windows host `10.77.77.1`, `eth0` only | 443/TCP | Dashboard HTTPS |
| Endpoint `10.77.77.30`, `eth0` only | 1514/TCP | Wazuh agent communication |
| Endpoint `10.77.77.30`, `eth0` only | 1515/TCP | Agent enrollment, only for the existing endpoint |

No inbound allowance was created for the **Wazuh API on TCP 55000** or the **indexer on TCP 9200/9300**. There were no intentional inbound allow rules on `eth1`.

The 1515 enrollment rule was retained for the existing endpoint. It could be further restricted or disabled after future enrollment requirements are assessed.

## Post-change functional and negative-control tests

| Test | Observed result |
| --- | --- |
| UFW status | Active; four source- and interface-restricted rules |
| Existing administrative SSH session | Continued after activation |
| **New Windows PowerShell SSH session** to `10.77.77.10` | **Succeeded**, explicitly confirmed in the test |
| Wazuh dashboard opened in Brave on Windows | **Succeeded**, explicitly confirmed |
| Wazuh manager, indexer, dashboard and Filebeat services | All four reported **active** |
| Wazuh endpoint agent | Active on Ubuntu endpoint |
| Manager's agent inventory | Agent `001` / `soc-endpoint` reported **Active** |
| **Negative-control TCP test from Windows**: `Test-NetConnection 10.77.77.10 -Port 55000` | `PingSucceeded: True`, `TcpTestSucceeded: False` |

The failed TCP 55000 connection is useful evidence of a **blocked management API access path from Windows**. It is not proof that the API is stopped locally or unreachable from every conceivable network path.

One additional SSH login test from within the Wazuh server to itself was observed during the process, but was **not used in place of the separately confirmed Windows-origin SSH connectivity test**.

No SSH authentication settings, Wazuh service configurations, or required service ports were deliberately changed.

## Security impact and boundaries

**Achieved:** A default-deny inbound host firewall with narrow lab-source exceptions; verified continued remote management and monitoring; an observed negative-control failure when attempting direct Windows access to the API.

**Not established or not yet tested:**

- Whether the server's UFW `IPV6` option is enabled and the complete IPv6-specific filtering behavior. `sshd` and the API were listening on IPv6 before hardening, so IPv6 should receive separate validation.
- Independent reachability tests **from the Default Switch (`eth1`)** and from other hosts.
- Overall Wazuh server CIS compliance or CVE remediation; these are separate workstreams.
- Resistance to compromise by a local privileged user who can alter firewall rules.

The Wazuh API service continues listening at the process level; the control restricts remote TCP access using the host firewall. Default **allow outgoing** was retained to avoid breaking dependency or update traffic.

## Safety and recovery notes

Changes to a firewall on a remote server can lock out the operator. This exercise preserved the original session, added the SSH management rule first, and tested a new connection from Windows. If access is unexpectedly lost after future edits, recover using the Hyper-V VM console rather than reverting an old checkpoint.

For authorized troubleshooting from the VM console, `sudo ufw status verbose` and `sudo ufw show added` can be used to inspect the active policy before modifying it.

## Follow-up

1. Verify `grep '^IPV6=' /etc/default/ufw` and record the server's scoped IPv6 addresses.
2. Consider independently testing the Default Switch network interface and agent enrollment policy.
3. Check whether Wazuh API access is required remotely for future integrations before changing the firewall policy.
4. Add cropped, sanitized screenshots of UFW status, agent status, and the negative-control PowerShell test to the evidence gallery.
5. Continue package- and advisory-level evaluation of Wazuh server software vulnerabilities, without equating listening ports with confirmed CVEs.

**Conclusion:** The observed lab tests support that UFW is active, preserves essential administration and telemetry, and blocks a direct Windows-origin connection to the Wazuh API. This is verified exposure reduction, **not a claim of complete system security**.
