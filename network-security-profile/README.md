# 🛡️ Home Network Security Posture Audit

This audit summarizes the current state of the SOHO (Small Office/Home Office) network security lab. It reflects layered defenses, segmentation, endpoint hardening, and monitoring practices implemented as of June 2025.

---

## 🔐 Summary

| Category                       | Posture     | Notes                                                                 |
|-------------------------------|-------------|-----------------------------------------------------------------------|
| **Network Segmentation**      | ★★★★★       | IoT VLAN separated from main network; strict inter-VLAN control       |
| **Router Hardening**          | ★★★★☆       | High-end router with static IPs, local management, and secure WiFi    |
| **Endpoint Protection**       | ★★★★☆       | BitLocker, Defender, Malwarebytes, Windows Firewall hardening         |
| **Printer Security**          | ★★★★★       | Static IP, strict inbound/outbound rules, public port blocking        |
| **Threat Monitoring**         | ★★★★☆       | Raspberry Pi syslog server + ELK integration + Fail2Ban              |
| **External Exposure**         | ★★★★★       | CGNAT via Starlink, no services exposed, VPN required outbound        |
| **Vulnerability Management**  | ★★★★☆       | Manual patching + Nessus scanning in place                            |

<br>
<div align="center">
  <img src="images/securityiscool.png" alt="Security is Cool Image" width="100%">
</div>

---

## 🧱 Network Segmentation & VLANs

- 🛑 IoT devices are isolated on a separate guest SSID/VLAN
- ✅ Main VLAN reserved for trusted devices (PCs, printer, Pi)
- 🔄 No lateral access allowed from IoT → Main
- 🎯 Static IP reservations in place for key devices

---

## 🔒 Endpoint & Printer Hardening

- 🖥️ Windows Firewall (`wf.msc`) rules applied:
  - Allow printing only to specific IP/ports
  - Block printer ports (`9100`, `515`, `631`) on public profiles
  - Block all unsolicited inbound connections from printer
- 📦 HP Smart allowed outbound for cloud services
- 🛡️ BitLocker enabled
- 🦠 Malwarebytes + Microsoft Defender coexistence
- 🔐 Printer static IP: `192.168.50.38`

---

## 🛰️ Router & Perimeter Defense

- Router: **ASUS RT-AX86U Pro**
- WAN: **Starlink with CGNAT (no public IP exposure)**
- VPN: **NordVPN active on endpoints**
- DHCP reservations configured
- Admin GUI accessed via local IP (`192.168.50.1`)
- Guest network isolation enforced

---

## 🔍 Threat Detection & Monitoring

- ✅ Raspberry Pi hardened and configured as a dedicated syslog server
  - SSH keys only, password login disabled
  - UFW firewall active with port-level controls
  - SSH restricted to LAN devices only
  - Fail2Ban active to prevent brute-force attacks
- 📡 Pi forwards syslog to ELK stack on desktop for live monitoring
- 🧱 ELK ports (5000, 9200, 5601) restricted to desktop IP only
- ✅ Nessus Essentials scanning partially implemented
- 📝 Windows Event Forwarding or Sysmon still under evaluation
- 🎯 Future: Consider SIEM ingestion (Wazuh, Splunk, or Graylog)

---

## 🌐 Internet Exposure Controls

- ✅ CGNAT via Starlink blocks unsolicited inbound traffic
- 🔒 No port forwarding or public web services exposed
- 🔎 External scans (e.g., Shodan, ShieldsUP) yield no open ports
- 🌍 VPN used for secure outbound browsing

---

## 🧰 Vulnerability Management

- 🔎 Nessus Essentials scanning PC, printer, and router for CVEs
- 🔧 Manual Windows updates + vendor firmware checks
- 📘 Future goal: Document vulnerability findings per scan cycle

---

## 🧠 Takeaway

This lab reflects professional-grade SOHO security architecture. It combines network segmentation, host-level hardening, zero-trust SSH policy, real-time monitoring, and external exposure mitigation — all within a streamlined and replicable home setup.
