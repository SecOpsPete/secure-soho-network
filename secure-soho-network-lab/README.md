## 🛡️ Home Network Security Lab

This lab showcases the design and implementation of a resilient, secure, and segmented home network environment, engineered for hands-on cybersecurity experimentation and IT networking experience. The architecture is anchored by the ASUS RT-AX86U Pro router, complemented by an ASUS ZenWiFi XT9 AX7800 mesh node operating in Access Point (AP) mode. This dual-device configuration provides robust wireless coverage, high-throughput bandwidth, and optimized channel separation tailored for performance, compatibility, and interference reduction across a variety of devices.

Key components of the network include:

- **Segmented Network Topology**: Implements logical separation of trusted devices, IoT endpoints, and guest clients through SSID isolation and VLAN-like segmentation strategies, reducing lateral movement risk in the event of compromise.
  
- **Advanced Wireless Configuration**: Channels are manually assigned and fine-tuned across 2.4GHz and 5GHz bands to minimize congestion and interference, with specific accommodations made for device compatibility (e.g., Roku channel preference).

- **VPN Fusion with NordVPN**: Enables dynamic split tunneling, allowing designated devices to route traffic through secure NordVPN connections while others use direct ISP access, balancing privacy needs with speed and functionality.

- **Firewall Hardening**: The ASUS router firewall settings are manually configured to block unsolicited inbound traffic and prevent common attack vectors, supplemented by additional endpoint protections and UFW (Uncomplicated Firewall) rules on the Raspberry Pi.

- **Centralized Syslog Logging**: A dedicated Raspberry Pi 4 device serves as the centralized syslog server, ingesting and parsing logs from network and system devices. It integrates with the ELK (Elasticsearch, Logstash, Kibana) stack and provides rich visibility into system activity, connection attempts, and potential anomalies.

- **Power Redundancy and Protection**: The entire network infrastructure is safeguarded by a **CyberPower CP1500PFCLCD PFC Sinewave UPS System** (1500VA/1000W), which ensures uninterrupted power delivery during outages and voltage fluctuations. This system includes Automatic Voltage Regulation (AVR), protecting sensitive electronics and preserving uptime during brief brownouts or surges.

- **Scalable Monitoring Capabilities**: The syslog architecture supports ongoing expansion with Filebeat for Elastic Common Schema (ECS) compliance, allowing deeper event correlation, future SIEM integrations, and enhanced alerting capabilities.

- **Resiliency & Redundancy**: Multiple layers of redundancy are being built into the system, including hardware failover capabilities, segmented wireless access, independent logging pipelines, and modular, containerized services. These enhancements support long-term scalability and reliability for lab scenarios simulating enterprise-level security postures.

This evolving lab reflects a practical, real-world approach to network defense-in-depth and operational resilience. It serves as a foundational platform for ongoing experiments in endpoint hardening, event logging, detection engineering, and secure remote connectivity — all within a controlled and observable home environment.


---

## 🌐 Network Diagram

<div align="center">
  <img src="images/Home_Network_Security_Lab_Dia.png" alt="Home Network Diagram" width="65%">
</div>

---

## 🔧 Router Configuration Summary

### ✔️ Wireless Settings

| Band | SSID | Security | Bandwidth | Features |
|------|------|----------|-----------|----------|
| 2.4GHz | SecOpsPete_Main | WPA2-Personal / AES | 20/40 MHz | Wi-Fi 6, PMF Capable, Agile Multiband |
| 5GHz | SecOpsPete_Main | WPA2-Personal / AES | 80 MHz | Wi-Fi 6, TWT, Agile Multiband |
| Guest (2.4GHz) | Old IoT SSID | WPA2-Personal / AES | 20 MHz | Intranet Access Disabled, Device Isolation Enabled |

> The ASUS ZenWiFi XT9 AX7800 is configured as a dedicated Access Point (AP), extending Wi-Fi coverage while maintaining a unified SSID structure and inheriting all security policies from the RT-AX86U Pro core router.

---

### 📡 Advanced Wireless Channel Planning

To optimize wireless stability and device compatibility:

- **Channel 40** manually assigned to the `STARLINK SECURE_AP` 5 GHz guest network broadcast by the **XT9 in AP mode**, ensuring Roku TV compatibility with lower 5 GHz channels.
- **Channel 161** assigned to `Sky Home Net_5G` on the **RT-AX86U Pro** to avoid co-channel interference.
- 2.4 GHz channel fixed to **channel 11** to reduce congestion from overlapping neighboring networks.
- Manual channel planning eliminates DFS-related issues and ensures non-interfering channel reuse between the RT-AX and XT9 AP.

> Unified SSIDs with distinct manual channels on each AP improve roaming behavior and overall RF efficiency in dense environments.

---

## 🔐 Router Hardening & Firewall

| Feature | Status |
|--------|--------|
| HTTPS Admin Access | ✅ Enabled on port 8443 |
| Admin Login Captcha | ✅ Enabled |
| Remote Admin (WAN) | ❌ Disabled |
| Default Admin Username Changed | ✅ Yes |
| WPS | ❌ Disabled |
| UPnP | ❌ Disabled |
| SSH Access | ❌ Disabled |
| Auto-Logout Timer | ✅ 10 minutes |
| IPv6 Firewall | ✅ Enabled (Deny unsolicited traffic) |
| DoS Protection | ✅ Enabled |
| WAN Ping Response | ❌ Disabled |
| IPv4 Inbound Rules | ❌ Disabled |
| Port Forwarding | ❌ Disabled |

<br>

<div align="center">
  <img src="images/Firewall.png" alt="Home Network Diagram" width="70%">
</div>

---

## 🧠 AiProtection (Trend Micro)

| Module | Status |
|--------|--------|
| Malicious Site Blocking | ✅ Enabled |
| Two-Way IPS | ✅ Enabled |
| Infected Device Quarantine | ✅ Enabled |
| Router Security Scan | ✅ All green ✅ |

---

## 🔄 VPN Fusion – Split Tunneling

### NordVPN Integration
- ✅ OpenVPN client profile uploaded
- ✅ Auto-reconnect enabled
- ✅ “Start with WAN” enabled
- ✅ Only selected devices routed through VPN

<br>
<div align="center">
  <img src="images/Fusion.png" alt="Home Network Diagram" width="70%">
</div>

---

### Device Routing Table

| Device | Route |
|--------|--------|
| 🧠 Desktop / Laptop | 🔐 NordVPN |
| 📱 iPhone | 🌐 Starlink WAN |
| 📺 Smart TV | 🌐 Starlink WAN |
| 🔌 IoT Devices (e.g. plugs, switches) | 🌐 Starlink WAN |
| 🖨️ Printer | 🌐 Starlink WAN |
| 🐧 Raspberry Pi (Syslog Server) | 🌐 Starlink WAN |

---

## 📊 Logging and Monitoring

### Raspberry Pi 4 Syslog Server

| Component     | Configuration                                         |
|---------------|-------------------------------------------------------|
| Hardware      | Raspberry Pi 4B (4GB RAM)                             |
| OS            | Raspberry Pi OS Lite                                 |
| Logging Tool  | `rsyslog`                                             |
| Syslog Port   | UDP 514                                               |
| Static IP     | `192.168.50.100`                                      |
| Function      | Receives router logs and forwards them to ELK stack  |
| Log Access    | `/var/log/syslog`, `journalctl`, or view in Kibana   |

> The Raspberry Pi collects system logs from the ASUS router and securely forwards them to a Logstash container running on the desktop. Log lifecycle is controlled via Elasticsearch ILM (7-day retention).

---

### ELK Stack Integration (Desktop)

| Component        | Details                                                    |
|------------------|------------------------------------------------------------|
| Logstash         | Listens on TCP/UDP 5000 for JSON logs                      |
| Elasticsearch    | Stores logs in `logs-generic-default` data stream         |
| Kibana           | Used to visualize and query logs from the Pi and router   |
| ILM Policy       | Retains logs for 7 days, deletes automatically afterward   |

> The ELK stack is running in Docker on a Windows desktop. Logstash is configured to accept logs on port 5000 and forward them into Elasticsearch with a retention policy.

---

### Raspberry Pi Setup Summary

1. **SSH Enabled** via blank `ssh` file placed on the boot volume.
2. **Static IP Set** to `192.168.50.100`.
3. **Installed rsyslog**:
   ```bash
   sudo apt update && sudo apt install -y rsyslog
   ```
4. **Configured `/etc/rsyslog.conf`** to receive and forward logs:
   ```conf
   module(load="imudp")
   input(type="imudp" port="514")

   *.* @@192.168.50.3:5000
   ```
   > Forwards logs to Logstash listener on desktop (`192.168.50.3`).

5. **Restarted rsyslog service**:
   ```bash
   sudo systemctl restart rsyslog
   ```

---

### 🔐 Hardening and Firewall Configuration

| Feature                       | Status     | Details                                                                 |
|------------------------------|------------|-------------------------------------------------------------------------|
| SSH Key Authentication       | ✅ Enabled | Password logins disabled; login restricted to SSH key from desktop     |
| Root Login                   | ❌ Disabled | `PermitRootLogin no` in `sshd_config`                                  |
| UFW Firewall                 | ✅ Active   | Allows SSH from LAN, syslog on UDP 514, and Elastic ports from desktop |
| Elastic Stack Port Filtering | ✅ Applied  | Ports 5000, 9200, 5601 restricted to `192.168.50.3`                    |
| Fail2Ban                     | ✅ Installed & Active | Bans after 5 failed SSH attempts for 1 hour                      |

UFW Rules Summary:
```bash
sudo ufw allow from 192.168.50.0/24 to any port 22
sudo ufw allow 514/udp
sudo ufw allow out on eth0
sudo ufw allow in on lo
sudo ufw allow from 192.168.50.3 to any port 5000
sudo ufw allow from 192.168.50.3 to any port 9200
sudo ufw allow from 192.168.50.3 to any port 5601
sudo ufw enable
```

Fail2Ban Config (`/etc/fail2ban/jail.local`):
```ini
[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
```

Fail2Ban Commands:
```bash
# Check status of the SSH jail
sudo fail2ban-client status sshd

# View current bans (if any)
sudo fail2ban-client status
```

---

### ✅ Validation

| Check                              | Result                          |
|------------------------------------|---------------------------------|
| SSH access restricted to desktop   | ✅ Confirmed                     |
| Syslog data received by Pi         | ✅ Verified via `journalctl`     |
| Logs forwarded to ELK stack        | ✅ Seen in Kibana Discover       |
| Firewall blocks unauthorized ports | ✅ Confirmed with `ufw status`   |
| Fail2Ban enforcement               | ✅ `fail2ban-client status sshd` |
| Log Retention                      | ✅ ILM 7-day delete policy       |
| Kibana query test                  | ✅ `@timestamp < now-7d/d` empty |

---

### Additional Notes

- Confirmed `logstash.conf` uses JSON codec for both TCP/UDP on port 5000.
- All data is centralized in Kibana for easy visualization and alerting.
- ILM policies are enforced through the Kibana UI with confirmed deletion timelines.
- Dashboard visualizations are filtered to reflect only current, retained logs.

```bash
# From Raspberry Pi to test logging:
logger "Test syslog message from Raspberry Pi"
```

✅ The Raspberry Pi syslog server is now fully integrated and operational

---

## 🧪 Validation

| Test | Result |
|------|--------|
| HTTPS login enforced | ✅ https://192.168.50.1:8443 |
| IP Test (PC) | ✅ Shows NordVPN IP (`45.132.159.12`) |
| IP Test (iPhone) | ✅ Shows Starlink IP |
| Guest Network Isolation | ✅ IoT devices can’t reach LAN |
| AiProtection Scan | ✅ All green |
| Syslog Entries Received | ✅ Confirmed from ASUS to Pi |

---

## 📦 Hardware Summary

| Device | Role |
|--------|------|
| ASUS RT-AX86U Pro | Core router, firewall, wireless controller |
| ASUS ZenWiFi XT9 AX7800 | Access Point extending wireless coverage |
| Starlink Ethernet Adapter | Internet uplink (bypass mode) |
| Raspberry Pi 4B | Syslog server, future SIEM/logging node |
| CyberPower CP1500PFCLCD | UPS providing surge protection and battery backup |
| Laptops / PCs | VPN-routed trusted devices |
| IoT Devices | Segmented via guest network |

---

### 🔋 Power Redundancy (UPS)

The entire networking stack is protected by a **CyberPower CP1500PFCLCD PFC Sinewave UPS System**:

- **Capacity:** 1500VA / 1000W
- **Outlets:** 12 total (6 battery + surge, 6 surge-only)
- **Features:** Active PFC compatibility, LCD diagnostics, Automatic Voltage Regulation (AVR)

> This UPS ensures uninterrupted power delivery to critical infrastructure including the ASUS RT-AX86U Pro, ZenWiFi XT9 AP, Raspberry Pi syslog server, and desktop running the ELK stack. It adds resilience during short-term outages and safeguards against voltage fluctuations, aligning the lab environment more closely with enterprise continuity practices.

<br>
<div align="center">
  <img src="images/badass.png" alt="Home Network Diagram" width="100%">
</div>

---

## 🧠 Author

**SecOpsPete**  
[GitHub](https://github.com/SecOpsPete) | Cybersecurity Analyst in training | Network Defense | Threat Hunting | Home Lab Projects
