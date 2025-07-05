### 📡 Windows Log Forwarding Pipeline (NXLog → Syslog → Filebeat → ELK)

This configuration enables real-time forwarding of Windows logs from a local PC to the Raspberry Pi syslog collector using NXLog. The Pi then harvests and ships those logs to the ELK stack via Filebeat for centralized analysis in Kibana.

---

### 🔄 Log Pipeline Flow

```
Windows 10 PC (NXLog)
        ↓ syslog over UDP
Raspberry Pi (rsyslog)
        ↓ local log file
Raspberry Pi (Filebeat)
        ↓ parsed to ECS format
Elasticsearch (Logstore)
        ↓ visualized
Kibana (Discover view)
```

---

### 🧰 Windows: NXLog Setup

**NXLog Version:** `nxlog-ce-3.2.2329`  
**Install Path:** `C:\Program Files\nxlog`  
**Service Name:** `nxlog`

📄 `C:\Program Files\nxlog\conf\nxlog.conf`
```nxlog
Panic Soft
NoFreeOnExit TRUE

define ROOT     C:\Program Files\nxlog
define CERTDIR  %ROOT%\cert
define CONFDIR  %ROOT%\conf\nxlog.d
define LOGDIR   %ROOT%\data

Moduledir %ROOT%\modules
CacheDir  %ROOT%\data
Pidfile   %ROOT%\data\nxlog.pid
SpoolDir  %ROOT%\data
LogFile   %LOGDIR%\nxlog.log

<Extension syslog>
    Module xm_syslog
</Extension>

<Input eventlog>
    Module im_msvistalog
</Input>

<Output out>
    Module      om_udp
    Host        192.168.50.3      # Raspberry Pi IP
    Port        514
    Exec        to_syslog_bsd();
</Output>

<Route 1>
    Path eventlog => out
</Route>
```

> ✅ After saving changes, restart the NXLog service:
> `Run as Administrator` → PowerShell:
> ```powershell
> Restart-Service nxlog
> ```

---

### 📥 Raspberry Pi: rsyslog Setup

**Log file target:** `/var/log/remote/win10-pc.log`

📄 `/etc/rsyslog.d/10-windows.conf`
```rsyslog
$template WinLogFile,"/var/log/remote/win10-pc.log"
if ($fromhost-ip == '192.168.50.15') then -?WinLogFile
& stop
```

> Replace `192.168.50.15` with your Windows PC’s static IP.

Reload rsyslog:
```bash
sudo systemctl restart rsyslog
```

---

### 🐑 Raspberry Pi: Filebeat Setup

**Log source:** `/var/log/remote/*.log`  
**Elasticsearch target:** `http://192.168.50.3:9200`

📄 `/etc/filebeat/filebeat.yml` (relevant snippet)
```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/remote/*.log
    fields:
      lab_role: raspberrypi_syslog_collector
      location: home_network
      owner: peter

output.elasticsearch:
  hosts: ["http://192.168.50.3:9200"]
```

Reload Filebeat:
```bash
sudo systemctl restart filebeat
```

---

### 🧪 Kibana: Verifying Windows Logs

Use the **Discover tab** with the index pattern:  
```
filebeat-*
```

📌 Search query:
```
win10-pc
```

Sample ECS-parsed fields:
- `@timestamp`
- `host.name: raspberrypi`
- `log.file.path: /var/log/remote/win10-pc.log`
- `message: <13>Jul 5 10:32:00 win10-pc Test message from Windows log`

---

### ✅ Status

- [x] **Persistent forwarding** from Windows after reboot
- [x] **Parsed logs visible in Kibana**
- [x] **Logs tagged with `lab_role`, `owner`, and `location`**

---

🛡️ *Part of the [Home Network Security](https://github.com/SecOpsPete/home-network-security) lab repository.*
