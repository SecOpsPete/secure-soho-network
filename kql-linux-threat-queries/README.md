# 🔍 SSH & Linux Intrusion Detection with KQL

This project leverages Kibana Query Language (KQL) to identify suspicious SSH and Linux activity within ELK (Elasticsearch, Logstash, Kibana) environments. These queries are intended to assist blue teams, home lab defenders, and SOC analysts in proactively detecting early-stage intrusion behavior, privilege escalation attempts, and command-line abuse on Linux systems.

> These queries were developed and tested against syslog data parsed from a Raspberry Pi log collector feeding into the ELK stack.

---

## 📁 Use Case

Each query targets a distinct attack surface, ranging from brute-force login attempts to netcat shell activity and cron job tampering. The detections focus on textual pattern matching in the `message` field for environments where log normalization (e.g., ECS field mapping) is incomplete or in progress.

---

## 🔎 Detection Queries

### 🚪 Failed SSH Authentication Attempts

Detects brute-force or unauthorized login attempts:

```kql
message:(*sshd* AND (*fail* OR *invalid* OR *disconnect* OR *refused*))
```

---

### 🚫 SSH Intrusion Filtering – Noisy Sessions Removed

Reduces noise by excluding common session management entries:

```kql
message:*sshd* AND 
(message:"Failed password" OR message:"authentication failure" OR message:"invalid user") AND 
NOT message:(*session closed* OR *session opened* OR *disconnected*)
```

---

### 🧍‍♂️ Failed Privilege Escalation

Looks for failed `sudo`, `su`, or `login` attempts while filtering out legitimate services:

```kql
message:(*sudo* OR *su* OR *login*) AND 
(message:*failed* OR message:"incorrect password" OR message:"authentication failure" OR message:"permission denied") AND 
NOT message:(*filebeat.service* OR *dockerd* OR *containerd* OR *wpa_supplicant* OR "no such file")
```

---

### 🧪 Suspicious Netcat or Port Scanning Activity

Flags common netcat, netstat, and nmap usage, excluding known system processes:

```kql
message:(*nc* OR *netcat* OR *nmap* OR *netstat*) AND 
NOT message:(*fields* OR *host_metadata* OR *filebeat* OR *containerd* OR *dockerd* OR *timesyncd* OR *rsyslogd* OR *rsyslog*)
```

---

### 🐚 Spawned Shells

Catches bash or sh shell invocations — useful for detecting breakout attempts from restricted environments:

```kql
message:(*bash* OR *sh*) AND message:(*spawned* OR *invoked* OR *started*)
```

---

### 👤 New User Account Creation

Detects new local account creation:

```kql
message:(*useradd* OR *adduser* OR "new user" OR "created user") AND 
NOT message:(*session* OR *sudo* OR *sshd* OR *USER=* OR *closed for user*)
```

---

### 🌐 Non-Local IP Login Attempts

Identifies external SSH brute-force attempts by filtering out local subnets:

```kql
message:*sshd* AND 
(message:"Failed password" OR message:"invalid user" OR message:"authentication failure") AND 
NOT message:(*192.168.50.* OR *192.168.52.* OR *session closed* OR *session opened* OR *disconnected*)
```

---

### 🌀 Reverse Shell & Unexpected Outbound Web Access

Flags outbound connections made using `curl`, `wget`, or `ftp`, excluding legitimate update activity:

```kql
message:(*curl* OR *wget* OR *ftp* OR "curl -s" OR "curl http" OR "wget http") AND 
NOT message:(*rsyslog* OR *apt* OR *update* OR *package* OR *ubuntu.com* OR *debian.org* OR *localhost* OR *192.168.*)
```

---

### ⏱️ Cron Job Manipulation

Detects creation or editing of cron jobs:

```kql
message:(*cron* OR *crontab*) AND message:(*edit* OR *new job* OR *created*)
```

---

### ⚙️ Unexpected Service Starts

Looks for services being unexpectedly enabled or started:

```kql
message:(*systemd* OR *service*) AND message:(*started* OR *enabled*) AND 
NOT message:(*filebeat* OR *ssh* OR *cron* OR *rsyslog*)
```

---

### ⚠️ Root Shell Access Outside Normal Context

Flags root shell activity that’s not part of expected system operations:

```kql
message:(*bash* OR *sh*) AND 
message:(*root* OR uid=0) AND 
NOT message:(*apt* OR *packagekit* OR *rsyslog* OR *snapd* OR *dockerd* OR *containerd* OR *systemd* OR *cron* OR *DEBIAN_FRONTEND*)
```

---

### 🔁 High Frequency SSH Failures

Use this as a base for frequency-based alerts (via Kibana rule or external detection logic):

```kql
message:"Failed password"
```

---

## 📌 Notes

- These queries are optimized for environments without full ECS field mapping.
- Assumes log ingestion through syslog (rsyslogd or journald) and parsing via Filebeat or Logstash.
- For production use, these queries should be adapted into **Kibana Detection Rules** or **SIEM rule templates**.
