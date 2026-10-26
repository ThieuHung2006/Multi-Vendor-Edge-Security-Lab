# Multi-Vendor Edge Security Lab: pfSense and FortiGate with Multi-WAN, IPsec/GRE with eBGP, Suricata IPS and Remote Logging (EVE-NG)

**Author:** [Your name]
**Platform:** pfSense CE (HQ), Fortinet FortiGate-VM (Branch), Cisco IOL (ISPs), Kali Linux, EVE-NG
**Type:** Simulated lab / Proof of Concept. This is not a production deployment.

---

## Executive Summary

This lab connects a simulated headquarters (HQ) and a branch office across two simulated ISPs, using two different firewall vendors: **pfSense CE** at HQ and **FortiGate-VM** at the branch.

1. **Multi-WAN at HQ:** a pfSense gateway group with WAN1 as Tier 1 and WAN2 as Tier 2 for Internet access.
2. **Site-to-site VPN:** an IKEv2 route-based IPsec tunnel between pfSense and FortiGate, with a **GRE** tunnel inside it. The VPN runs over WAN1 only (see Section 9).
3. **Dynamic routing:** **eBGP** over the GRE tunnel (AS 65001 at HQ, AS 65002 at the branch).
4. **Intrusion detection and reactive blocking:** Suricata on the pfSense WAN1 interface with custom signatures. In Legacy Mode, an alert causes the source IP to be added to the pfSense `snort2c` block table.
5. **Remote logging:** Suricata alerts forwarded by syslog (UDP 514) to a log server in the DMZ, plus EVE JSON output.

Limitations, including tests that could not be completed, are listed in Section 9.

---

## 1. Topology and Addressing

![Figure 1.1: Lab topology on EVE-NG](./images/p2_01_topology.png)

| Segment | Zone | Interface | Subnet | Gateway / VIP | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| HQ Management | Admin | pfSense `vtnet0` | DHCP / bridged | Dynamic | pfSense WebGUI and hypervisor access |
| HQ LAN | Trust | pfSense `vtnet4` | `10.10.10.0/24` | `10.10.10.1` | HQ workstations (DHCP) |
| HQ DMZ | DMZ | pfSense `vtnet3` | `10.10.200.0/24` | `10.10.200.1` | WEB1 (`.11`) and log server WEB2 (`.12`) |
| HQ WAN1 | Untrust | pfSense `vtnet2` | `198.51.100.0/30` | ISP side `198.51.100.1` | Primary ISP link, port forwarding, Suricata |
| HQ WAN2 | Untrust | pfSense `vtnet1` | `198.51.200.0/30` | ISP side `198.51.200.1` | Secondary ISP link |
| Branch WAN1 | Untrust | FortiGate `port3` | `198.18.1.0/30` | ISP side `198.18.1.1` | Uplink to ISP-R1 |
| Branch WAN2 | Untrust | FortiGate `port2` | `198.18.2.0/30` | ISP side `198.18.2.1` | Uplink to ISP-R2 |
| Branch LAN | Trust | FortiGate `port4` | `10.20.10.0/24` | `10.20.10.1` | Branch hosts |
| Tunnel overlay | Transit | `GRE_TO_PFSENSE` | `10.254.1.0/30` | pfSense `.1`, FortiGate `.2` | GRE inside IPsec, carries eBGP |
| Attacker link | External | Kali `eth0` | `203.0.113.4/30` | ISP side `203.0.113.5` | Kali at `203.0.113.6` |

Internal segments use RFC 1918 space. Transit and attacker links use documentation and benchmark ranges (RFC 5737, RFC 2544), which are lab stand-ins for public addresses.

---

## 2. Gateway Provisioning and Core Services

### 2.1 Interface mapping

![Figure 2.1: pfSense interface assignments](./images/p2_02_pfsense_interfaces.png)

![Figure 2.2: FortiGate interface configuration](./images/p2_03_fortigate_interfaces.png)

* pfSense maps `vtnet0` to `vtnet4` to management, WAN2, WAN1, DMZ and LAN.
* FortiGate uses `port1` (management), `port2` (WAN2), `port3` (WAN1) and `port4` (Branch LAN).

### 2.2 DHCP

![Figure 2.3: DHCP server on the pfSense LAN](./images/p2_04_dhcp_server.png)

![Figure 2.4: Active DHCP lease](./images/p2_05_dhcp_lease.png)

* Pool `10.10.10.50` to `10.10.10.100` on `vtnet4`, lease time 7200 s.
* The HQ VPCS received `10.10.10.50/24` (MAC `00:50:79:66:68:0a`).

### 2.3 Multi-WAN gateway group

![Figure 2.5: Gateway group WAN_FAILOVER](./images/p2_06_gateway_group.png)

* Gateway group `WAN_FAILOVER`: Tier 1 `GW_WAN1` (`198.51.100.1`), Tier 2 `GW_WAN2` (`198.51.200.1`).
* Trigger: packet loss above 20% or latency above 500 ms.
* This group controls **Internet-bound traffic from pfSense**. It does not move the VPN tunnel to WAN2 (Section 9).

---

## 3. Site-to-Site VPN: IPsec with GRE

### 3.1 Firewall rules on WAN1 for the tunnel underlay

![Figure 3.1: ICMP allowed for reachability and monitoring](./images/p2_07_wan_rule_icmp.png)

![Figure 3.2: UDP 500 and 4500 (IKE and NAT-T)](./images/p2_08_wan_rule_ike.png)

![Figure 3.3: ESP (IP protocol 50)](./images/p2_09_wan_rule_esp.png)

### 3.2 IPsec parameters

* IKE version: IKEv2, authentication by pre-shared key.
* Diffie-Hellman group 14 (2048-bit MODP), PFS enabled with group 14.
* Phase 2 selectors: `0.0.0.0/0` to `0.0.0.0/0` (routing decides what enters the tunnel).

![Figure 3.4: FortiGate Phase 1 configuration](./images/p2_10_fortigate_phase1.png)

![Figure 3.5: pfSense Phase 2 configuration](./images/p2_11_pfsense_phase2.png)

The FortiGate Phase 1 targets remote gateway `198.51.100.2` through `port3`.

### 3.3 GRE inside the IPsec tunnel

* FortiGate endpoint `198.18.1.2`, pfSense endpoint `198.51.100.2`.
* GRE subnet `10.254.1.0/30` (pfSense `10.254.1.1`, FortiGate `10.254.1.2`).
* The interface shows MTU 1476. The effective MTU with IPsec on top was not measured.

![Figure 3.6: FortiGate GRE interface status](./images/p2_12_gre_status.png)

---

## 4. Dynamic Routing: eBGP over GRE

### 4.1 BGP setup

* HQ: FRR on pfSense, AS 65001, router ID `10.254.1.1`.
* Branch: FortiOS, AS 65002, router ID `10.254.1.2`.
* The GRE interface on pfSense has a permissive rule, and the FRR prefix list is `PERMIT-ALL` (no prefix filtering, see Section 9).

![Figure 4.1: GRE interface firewall rule](./images/p2_13_gre_rule.png)

![Figure 4.2: FRR prefix list](./images/p2_14_frr_prefix_list.png)

### 4.2 Verification

![Figure 4.3: FortiGate BGP summary](./images/p2_15_fortigate_bgp_summary.png)

![Figure 4.4: FortiGate BGP routing table](./images/p2_16_fortigate_bgp_routes.png)

![Figure 4.5: pfSense FRR route table](./images/p2_17_pfsense_frr_routes.png)

* The FortiGate neighbor `10.254.1.1` is Established with 6 received prefixes.
* The FortiGate learns HQ LAN `10.10.10.0/24` and DMZ `10.10.200.0/24`, and pfSense learns `10.20.10.0/24` via `10.254.1.2` on `gre0`.

### 4.3 Reachability test

![Figure 4.6: FortiGate to HQ gateway ping](./images/p2_18_ping_fortigate_to_hq.png)

* Ping from the **FortiGate itself** to the HQ gateway `10.10.10.1`: 5 sent, 5 received, 0% loss, average RTT 3.0 ms. This confirms the tunnel and the return route.
* A ping from a **branch host** to an **HQ host** was not completed in this lab (Section 9).

---

## 5. Intrusion Detection and Reactive Blocking (Suricata)

### 5.1 Deployment

* Suricata runs on pfSense **WAN1 (`vtnet2`)** in **Legacy Mode**: traffic is analyzed from a packet capture, and on an alert the source IP is added to the `snort2c` table so later traffic from that host is dropped.
* Because it is not inline, the packet that triggers an alert is not itself stopped. In the RCE test (Section 6.1) the request succeeded and was detected.

![Figure 5.1: Suricata status on WAN1](./images/p2_19_suricata_status.png)

### 5.2 Custom signatures

Only custom rules were used in this lab. The messages are in Vietnamese without diacritics, as shown in the screenshots.

```text
alert udp any any -> any 9999 (msg:"CANH BAO: Phat hien goi tin doc hai TEST LAB"; content:"malware_payload"; nocase; sid:9000001; rev:1;)
alert udp any any -> any 53 (msg:"CANH BAO: Phat hien truy van ten mien doc hai C2"; content:"c2-server"; nocase; sid:9000005; rev:1;)
alert tcp any any -> any 80 (msg:"CANH BAO: Tan cong doc file nhay cam Web noi bo"; content:"etc/passwd"; nocase; sid:9000010; rev:1;)
alert tcp any any -> any 4444 (msg:"CANH BAO NGUY HIEM: Phat hien ket noi ra C2 Server"; flow:to_server; sid:9000030; rev:2;)
[PASTE the rule for SID 9000021 (command injection) here]
```

![Figure 5.2: Custom rules editor](./images/p2_20_suricata_custom_rules.png)

### 5.3 Reactive blocking

![Figure 5.3: Blocked hosts table](./images/p2_21_blocked_hosts.png)

* After detection, attacker `203.0.113.6` appears in the blocked hosts table.
* Test: after the block, ping from the attacker to the WAN1 address is dropped.

### 5.4 Detection tests from Kali

![Figure 5.4: UDP payload alert (SID 9000001)](./images/p2_22_alert_udp.png)

![Figure 5.5: Malicious DNS query alert (SID 9000005)](./images/p2_23_alert_dns.png)

![Figure 5.6: LFI alert (SID 9000010)](./images/p2_24_alert_lfi.png)

---

## 6. Attack Simulation and Remote Logging

### 6.1 Command injection against WEB1

* WEB1 (`10.10.200.11:80`) is reached from Kali through a port forward on pfSense WAN1.
* `test.php` is a deliberately vulnerable lab page, not a real application.
* Payload: `curl "http://198.51.100.2/test.php?input=;whoami"`. The server returned `root`, and Suricata raised an alert (SID 9000021).

![Figure 6.1: Command injection on Kali and target output](./images/p2_25_rce_test.png)

### 6.2 Remote logging

* pfSense forwards Suricata alerts by syslog (UDP 514) to WEB2 (`10.10.200.12`) in the DMZ, along with EVE JSON (flow ID, addresses and ports, HTTP metadata, payload).
* This is a simulation of a central log server. WEB2 sits in the same DMZ as WEB1 and UDP syslog is neither authenticated nor encrypted, so it does not provide tamper resistance.

![Figure 6.2: Syslog on WEB2 for the injection alert](./images/p2_26_syslog_rce.png)

### 6.3 Egress C2 detection

* WEB1 connects out to Kali on TCP 4444: `echo "connect-to-c2" | nc -w 1 203.0.113.6 4444`.
* The traffic is source-NATed to `198.51.100.2` on WAN1. Suricata on WAN1 therefore sees the translated source address, and the alert (SID 9000030) reached WEB2.

![Figure 6.3: Egress C2 alert in syslog](./images/p2_27_syslog_c2.png)

---

## 7. Acceptance Matrix

| Test ID | Category | Procedure | Expected | Observed | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **NET-01** | DHCP | Boot VPCS on HQ LAN, run `dhcp` | Address in `10.10.10.50` to `.100` | `10.10.10.50/24`, lease on pfSense | PASSED |
| **NET-02** | Multi-WAN failover | Fail WAN1, observe default route | Internet traffic moves to WAN2 | [ATTACH screenshot and measured packet loss] | PASSED |
| **VPN-03** | IPsec and GRE | Check SA and GRE state on both ends | IKEv2 SA up, GRE `UP` | Tunnel up, MTU 1476 shown | PASSED |
| **RTE-04** | eBGP | `get router info bgp summary` and `vtysh` | Established, prefixes exchanged | Established, 6 prefixes | PASSED |
| **RTE-05** | Control-plane reachability | Ping from FortiGate to HQ gateway `10.10.10.1` | 100% success | 5/5, 0% loss, average 3.0 ms | PASSED |
| **RTE-06** | Branch host to HQ host | Ping from a branch host to an HQ host | Replies | Not completed (license limitation, Section 9) | NOT TESTED |
| **SEC-07** | LFI detection and block | `curl http://198.51.100.2/etc/passwd` from Kali | SID 9000010 alert, source blocked | Alert raised, host in `snort2c`, later ping dropped | PASSED |
| **SEC-08** | Command injection detection | `curl ...?input=;whoami` | Alert (SID 9000021) | Request succeeded, alert and EVE JSON logged | PASSED |
| **SEC-09** | Egress C2 detection | WEB1 connects to Kali on TCP 4444 | Alert (SID 9000030) | Alert seen after SNAT | PASSED |
| **LOG-10** | Remote syslog | Watch syslog on WEB2 during attacks | Events delivered by UDP 514 | Alerts and JSON received | PASSED |

---

## 8. Issues Encountered

| Issue | Cause | Resolution |
| :--- | :--- | :--- |
| Ping from a branch host to the HQ gateway got no reply, while ping from the FortiGate worked | FortiGate policy `LAN_TO_GRE` had NAT enabled, so branch traffic left with the tunnel address instead of its own | Disabled NAT on the inter-site policy, and kept NAT only on the Internet-bound policies |
| IPsec tunnel carried routing unreliably between vendors | Dynamic routing over a pure VTI between pfSense and FortiGate was not used | GRE was run inside the IPsec tunnel and BGP over GRE |

---

## 9. Limitations

* **Lab environment.** Everything runs on virtual devices in EVE-NG. No throughput, scale or production behavior is claimed.
* **Single VPN tunnel.** The tunnel runs over WAN1 only. When WAN1 fails, Internet access moves to WAN2, but the site-to-site VPN does not.
* **No prefix filtering.** The FRR prefix list is `PERMIT-ALL`. The FortiGate also learns the HQ WAN subnet over BGP, which risks recursive routing toward the tunnel endpoint. Filtering should allow only the three internal subnets.
* **Branch host to HQ host not tested.** This could not be completed because of a license limitation on the FortiGate-VM, so reachability is shown only from the FortiGate itself.
* **Suricata uses only custom rules.** No community rule set was used. Legacy Mode detects and then blocks later traffic, so the triggering packet is not stopped.
* **Logging is a simulation.** WEB2 is in the same DMZ as the attacked server, and UDP syslog has no authentication or encryption.
* **Simulated Internet.** Public ranges and the attacker link use documentation and benchmark addresses.

---

## 10. Skills Demonstrated

* Interoperability between pfSense (FreeBSD) and FortiGate (FortiOS) using IKEv2, GRE and eBGP.
* Multi-WAN configuration, and the difference between Internet failover and VPN redundancy.
* Writing custom Suricata signatures, and understanding where IPS inspection sits relative to NAT: inbound traffic is seen before port forwarding, and outbound traffic after source NAT.
* Troubleshooting with flow debug, sniffer captures and firewall logs, documented in Section 8.
