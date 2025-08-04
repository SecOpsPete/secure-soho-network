# 🛡️ Home Network Security Lab

This project documents a resilient and secure home network built for hands-on cybersecurity experimentation. It’s anchored by an **ASUS RT-AX86U Pro** router and an **ASUS ZenWiFi XT9** mesh node in Access Point (AP) mode, delivering high-performance coverage and stability.

Key features include:

- **Network Segmentation**: Trusted, IoT, and guest devices are isolated via SSIDs and VLAN-like logic to reduce lateral movement risk.
- **Manual Channel Optimization**: Wireless channels are strategically assigned for performance and device compatibility.
- **VPN Fusion**: Select devices route traffic through NordVPN while others use direct ISP access.
- **Firewall Hardening**: Unsolicited traffic is blocked at the router and endpoint level using UFW and secure defaults.
- **Centralized Logging**: A Raspberry Pi syslog server forwards logs to a Dockerized ELK stack for real-time visibility.
- **Power Protection**: A CyberPower UPS provides battery backup and voltage regulation for critical devices.
- **Scalability**: Modular logging, ECS compliance, and containerized services allow future SIEM integration and enterprise-grade monitoring.

This evolving lab serves as a realistic platform for testing endpoint defense, log analysis, and secure networking—all within a controlled home environment.

---

## 🌐 Network Diagram

<div align="center">
  <img src="images/NetworkDiagram.png" alt="Home Network Diagram" width="75%">
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

## 📌 Static IP Addressing Strategy

To maintain consistency, reduce DHCP churn, and simplify device identification in log files and firewall rules, key infrastructure devices are assigned **static IP addresses** through the router’s DHCP reservation table.

### 🎯 Why Static IPs?

Static IP assignments serve several important functions in a secure and segmented home lab:

- **Reliability**: Devices like the syslog server (Raspberry Pi) or VPN-routed desktops maintain the same address, ensuring uninterrupted forwarding, monitoring, and access.
- **Log Integrity**: Centralized logging systems benefit from stable IPs, making it easier to trace events and correlate activity in Kibana dashboards.
- **Firewall Control**: Granular UFW and router-level firewall rules depend on consistent IPs to restrict access (e.g., only allow Logstash ports from `192.168.50.3`).
- **DNS and Hostname Mapping**: Enables optional hostname assignments for clarity across logs and tools.
- **Reduced Conflict**: Prevents accidental DHCP assignment overlap or reassignment that could break scripts, SSH tunnels, or static routes.

### 🧭 Static IP Map

| Device         | MAC Address          | Static IP         | Hostname       |
|----------------|----------------------|--------------------|----------------|
| Peters_Desktop | `D8:43:AE:XX:XX:XX`   | `192.168.50.3`     | —              |
| HP Office Jet  | `80:E8:2C:XX:XX:XX`   | `192.168.50.38`    | —              |
| Raspberry Pi   | `2C:67:6B:XX:XX:XX`   | `192.168.50.100`   | `Raspberry_Pi` |
| PVR_Notebook   | `8C:F8:C5:XX:XX:XX`   | `192.168.50.117`   | —              |

> These IPs are reserved directly in the **ASUS RT-AX86U Pro** router’s DHCP static assignment table to ensure consistency across reboots and firmware updates.

This strategy supports a more **deterministic, auditable, and manageable** home lab environment — particularly important for maintaining service availability and accurate logging in a network defense context.

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

---

## 🧠 AiProtection (Trend Micro)

AiProtection is a built-in security suite powered by **Trend Micro**, integrated directly into the ASUS RT-AX86U Pro router. It provides proactive, router-level threat prevention for all devices on the network — especially useful for IoT and guest clients that may lack built-in defenses.

Unlike endpoint antivirus, AiProtection inspects traffic at the perimeter, offering continuous monitoring and automatic blocking of known threats.

| Module                    | Status      | Description                                                                 |
|---------------------------|-------------|-----------------------------------------------------------------------------|
| **Malicious Site Blocking**    | ✅ Enabled   | Prevents access to known phishing domains and malicious URLs.               |
| **Two-Way IPS**                | ✅ Enabled   | Detects and blocks suspicious inbound and outbound traffic.                 |
| **Infected Device Quarantine**| ✅ Enabled   | Automatically isolates compromised devices to prevent lateral movement.     |
| **Router Security Scan**       | ✅ All green ✅ | Periodic scans confirm strong security posture and no risky configurations. |

> AiProtection provides an added layer of baseline security, complementing the network's segmented topology, firewall rules, and centralized log monitoring. While it doesn't replace host-based security tools, it strengthens the first line of defense at the network edge.

---

## 🔄 VPN Fusion – Split Tunneling

The ASUS RT-AX86U Pro supports **VPN Fusion**, which allows selected devices to use a VPN connection while others access the internet directly via the ISP (Starlink). This setup balances **privacy, speed, and functionality** based on each device's role.

### Device Routing Table

| Device                                | Route            |
|----------------------------------------|------------------|
| 🧠 Desktop / Laptop                    | 🔐 NordVPN       |
| 📱 iPhone                              | 🌐 Starlink WAN  |
| 📺 Smart TV                            | 🌐 Starlink WAN  |
| 🔌 IoT Devices (e.g. plugs, switches)  | 🌐 Starlink WAN  |
| 🖨️ Printer                             | 🌐 Starlink WAN  |
| 🐧 Raspberry Pi (Syslog Server)        | 🌐 Starlink WAN  |

> Devices with privacy or security requirements (like your main desktop) are routed through NordVPN, while bandwidth-sensitive or low-risk devices (like IoT, printers, and media streamers) use the direct Starlink connection.


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

## ✅ Validation

| Check                                  | Result                          |
|----------------------------------------|---------------------------------|
| SSH key-based access from desktop      | ✅ Enabled and tested            |
| SSH access restricted to desktop       | ✅ Confirmed                     |
| Syslog data received by Pi             | ✅ Verified via `journalctl`     |
| Logs forwarded to ELK stack            | ✅ Seen in Kibana Discover       |
| Firewall blocks unauthorized ports     | ✅ Confirmed with `ufw status`   |
| Fail2Ban enforcement                   | ✅ `fail2ban-client status sshd` |
| Log Retention                          | ✅ ILM 7-day delete policy       |
| Kibana query test                      | ✅ `@timestamp < now-7d/d` empty |

> The Raspberry Pi accepts SSH connections only from the desktop, authenticated via public/private key pair. Password-based logins and remote root access are disabled for security.

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
