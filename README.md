# 🛡️ Wazuh SIEM — Enterprise Configuration

> A production-ready Wazuh SIEM deployment featuring threat intelligence integrations (VirusTotal & MISP), network device monitoring (OPNsense & MikroTik), custom decoders and rules, automated active responses, Telegram SOC notifications, and a Dockerized syslog collector architecture.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Repository Structure](#repository-structure)
- [Manager Configuration (ossec.conf)](#manager-configuration)
- [Integrations](#integrations)
  - [VirusTotal](#virustotal-integration)
  - [MISP Threat Intelligence](#misp-threat-intelligence-integration)
  - [Telegram Notifications](#telegram-notifications)
- [Network Device Monitoring](#network-device-monitoring)
  - [OPNsense Firewall](#opnsense-firewall)
  - [MikroTik RouterOS](#mikrotik-routeros)
- [Custom Decoders & Rules](#custom-decoders--rules)
- [Active Responses](#active-responses)
- [Agent Configurations](#agent-configurations)
- [Docker Syslog Collector](#docker-syslog-collector)
- [Installation & Deployment](#installation--deployment)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Overview

This repository contains the full configuration set for a **Wazuh SIEM** deployment designed for an enterprise / MSSP environment. It covers:

| Capability | Description |
|---|---|
| **Threat Intelligence** | Automated IoC lookups against VirusTotal and MISP on every file integrity event |
| **Firewall Monitoring** | Real-time ingestion and alerting on OPNsense filterlog and Suricata events |
| **Router Auditing** | Comprehensive MikroTik RouterOS auditing (login, firewall, DNS, scripts, schedulers) |
| **Active Response** | Automated threat removal, IP blocking on OPNsense, and firewall-drop actions |
| **SOC Notifications** | Real-time Telegram alerts with MikroTik-aware formatting for instant SOC visibility |
| **File Integrity Monitoring (FIM)** | Syscheck across Linux and Windows endpoints with real-time monitoring |
| **Vulnerability Detection** | Native Wazuh vulnerability detection with 60-minute feed updates |
| **Compliance** | Rules tagged with MITRE ATT&CK, PCI DSS, and GDPR mappings |

---

## Architecture

```
                          ┌─────────────────────────────────┐
                          │       Wazuh Manager             │
                          │       WAZUH_MANAGER_IP              │
                          │                                 │
                          │  ┌───────────┐ ┌─────────────┐  │
                          │  │ VirusTotal│ │    MISP     │  │
                          │  │Integration│ │ Integration │  │
                          │  └───────────┘ └─────────────┘  │
                          │  ┌───────────┐ ┌─────────────┐  │
                          │  │  Telegram │ │  Wazuh      │  │
                          │  │  Alerts   │ │  Indexer    │  │
                          │  └───────────┘ └─────────────┘  │
                          └────────┬────────────┬───────────┘
                                   │            │
                 ┌─────────────────┼────────────┼──────────────────┐
                 │                 │            │                  │
        ┌────────▼──────┐  ┌──────▼──────┐  ┌──▼───────────┐  ┌──▼────────────┐
        │  Linux Agents │  │  Windows    │  │  OPNsense    │  │  Docker       │
        │  (FIM /tmp,   │  │  Agents     │  │  Agent       │  │  Collector    │
        │   /root)      │  │  (FIM C:\)  │  │  (Syslog +   │  │  (MikroTik   │
        │               │  │             │  │   Suricata)  │  │   Syslog)    │
        └───────────────┘  └─────────────┘  └──────────────┘  └──────────────┘
                                                                      ▲
                                                                      │ UDP 514
                                                               ┌──────┴──────┐
                                                               │  MikroTik   │
                                                               │  Routers    │
                                                               └─────────────┘
```

---

## Repository Structure

```
Wazuh_SIEM/
├── ossec.conf                          # Main Wazuh Manager configuration
├── Dashboards.ndjson                   # Wazuh/OpenSearch dashboard export (importable)
├── README.md
│
├── Agents/                             # Per-group agent.conf files (shared_agent_config)
│   ├── Linux/agent.conf                # Linux agents — FIM on /tmp, /root
│   ├── MISP/agent.conf                 # MISP server agent — FIM on /tmp
│   ├── MISP_WINDOWS/agent.conf         # Windows MISP agent — FIM on C:\Temp
│   ├── OPNSense/agent.conf             # OPNsense agent — filter, Suricata, auth, system logs
│   └── server-A/agent.conf             # MikroTik log collector — reads /var/log/mikrotik/
│
├── VirusTotal/                         # VirusTotal integration files
│   ├── virustotal                      # Shell wrapper (calls virustotal.py)
│   ├── virustotal.py                   # Python integration script
│   └── remove-threat.sh                # Active response: delete malicious files
│
├── MISP/                               # MISP integration files
│   ├── custom-misp_file_hashes.py      # Custom Python integration (multi-IoC)
│   └── Rules/
│       ├── misp.xml                    # MISP generic rules (100620–100622)
│       └── misp_files_hashes.xml       # MISP file-hash rules (100800–100805)
│
├── Telegram/                           # Telegram SOC notification integration
│   └── custom-telegram                 # Bash script — context-aware alert notifications
│
├── OPNSense/                           # OPNsense firewall integration
│   ├── Decoders/OPNsense_decoder.xml   # Filterlog decoder (pcre2)
│   ├── Rules/OPNsense_rule.xml         # Firewall rules (100900–100912)
│   └── active-response/opnsense-block.sh  # Active response: block IP via OPNsense API
│
├── MikroTik/                           # MikroTik RouterOS integration
│   ├── Decoders/
│   │   ├── MikroTik.xml                # v2 decoders (direct syslog)
│   │   └── mikrotik-decoders.xml       # Docker collector decoders (20+ event types)
│   ├── Rules/
│   │   ├── MikroTik.xml                # v2 rules: login fail/success, brute-force (110011–110013)
│   │   └── mikrotik-rules.xml          # Docker collector rules: full audit (101000–101023)
│   └── docker/wazuh-collector/         # Dockerized syslog collector for MikroTik
│       ├── docker-compose.yml          # Docker Compose with socat UDP listener
│       ├── ossec.conf                  # Minimal agent config for the container
│       └── logs_mikrotik/              # Persistent volume for MikroTik logs
│
└── local/                              # Wazuh local custom decoders & rules
    ├── Decoders/local_decoder.xml      # Squid proxy & DNS decoders
    └── Rules/local_rules.xml           # Squid, DNS, and SSH rules (100001, 100100–100101)
```

---

## Manager Configuration

The main [`ossec.conf`](ossec.conf) configures the Wazuh Manager with the following key sections:

### Global Settings
- JSON & plain text alert output enabled
- Full log archiving (`logall` / `logall_json`) for forensic analysis
- Agent disconnection alert time: **15 minutes**

### Remote Connections
| Port | Protocol | Purpose |
|------|----------|---------|
| 1514/tcp | Secure | Agent communication (primary) |
| 514/udp | Syslog | OPNsense firewall logs (`OPNSENSE_SUBNET/24`) |
| 514/udp | Syslog | MikroTik router logs (`MIKROTIK_ROUTER_IP_1`, `MIKROTIK_ROUTER_IP_2`) |

### Security Modules

| Module | Status | Configuration |
|--------|--------|---------------|
| **Rootcheck** | ✅ Enabled | Every 12h — checks files, trojans, devices, PIDs, ports |
| **Syscheck (FIM)** | ✅ Enabled | Every 12h — monitors `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/boot` |
| **Syscollector** | ✅ Enabled | Every 1h — hardware, OS, network, packages, ports, processes |
| **SCA** | ✅ Enabled | Every 12h — security configuration assessment |
| **Vulnerability Detection** | ✅ Enabled | Feed update every 60min |
| **Osquery** | ❌ Disabled | Pre-configured for `/var/log/osquery/` |
| **CIS-CAT** | ❌ Disabled | Pre-configured with Java/CIS-CAT paths |

### Authentication (wazuh-authd)
- Port **1515** with password-based enrollment
- Force re-registration after **1 hour** disconnect
- Strong cipher suite: `HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA`

### CDB Lists
The manager loads the following **CDB lookup lists** for IoC matching:
- `malicious-ioc/malware-hashes`
- `malicious-ioc/malicious-ip`
- `malicious-ioc/malicious-domains`

---

## Integrations

### VirusTotal Integration

**Purpose:** Automatically scan file hashes detected by Syscheck (FIM) against VirusTotal's database.

| Setting | Value |
|---------|-------|
| Trigger | `syscheck` group events |
| API Version | v2 (`/vtapi/v2/file/report`) |
| Alert Format | JSON |

#### Files

| File | Location on Manager | Description |
|------|---------------------|-------------|
| `virustotal` | `/var/ossec/integrations/virustotal` | Shell wrapper — resolves paths and launches the Python script |
| `virustotal.py` | `/var/ossec/integrations/virustotal.py` | Core logic — extracts MD5 from syscheck alerts, queries VT API, sends results to Wazuh socket |
| `remove-threat.sh` | `/var/ossec/active-response/bin/remove-threat.sh` | Active response — deletes files flagged as malicious (triggered by rule `87105`) |

#### How It Works
1. **Syscheck** detects a new/changed file and computes its MD5 hash
2. The **VirusTotal integration** queries the VT API with the hash
3. If **positives > 0**, Wazuh generates a high-level alert (rule `87105`)
4. The **active response** `remove-threat.sh` automatically **deletes** the malicious file from the endpoint

---

### MISP Threat Intelligence Integration

**Purpose:** Cross-reference multiple IoC types (file hashes, IPs, domains, registry keys, process names) against a self-hosted MISP instance.

| Setting | Value |
|---------|-------|
| Trigger | All alerts ≥ level 5 |
| MISP URL | `https://misp.local` |
| Alert Format | JSON |

#### File

| File | Location on Manager | Description |
|------|---------------------|-------------|
| `custom-misp_file_hashes.py` | `/var/ossec/integrations/custom-misp_file_hashes.py` | Multi-IoC MISP lookup script |

#### Supported IoC Extraction

The custom MISP script (`custom-misp_file_hashes.py`) extracts indicators from multiple alert types:

| # | IoC Type | Source | Extracted Fields |
|---|----------|--------|------------------|
| 1 | **File Hashes** | Syscheck (FIM) | `md5_after`, `sha1_after`, `sha256_after` |
| 2 | **Registry Keys** | Syscheck (Windows) | `syscheck.path` |
| 3 | **Domains** | Sysmon Event 22 (DNS) | `win.eventdata.queryName` |
| 4 | **IPs / Filenames** | Windows Event 4688 | Command-line IP regex or `newProcessName` |
| 5 | **IPs & Domains** | Network / MikroTik | `srcip`, `domain`, `srcaddr` |

#### Key Features
- **Enterprise whitelist** — Configurable via `options` JSON or hardcoded fallback (skips `127.0.0.1`, `svchost.exe`, etc.)
- **Case-insensitive** whitelist matching
- **MISP Sightings** — Optionally push sightings back to MISP for collaborative threat intel
- **Private IP filtering** — Built-in RFC 1918 filter (disabled for lab/testing)
- **Active Response injection** — Injects `srcip` or `syscheck.path` into the output message so active responses can act on it

#### MISP Rules

**`misp.xml`** (Generic):
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100620 | 10 | MISP Events (base rule) |
| 100621 | 5 | MISP: API Issues |
| 100622 | 12 | MISP: IoC found |

**`misp_files_hashes.xml`** (File Hash specific):
| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 100800 | 0 | Base grouping rule | — |
| 100801 | 0 | Hash not found in MISP | — |
| 100802 | **15** | **Threat confirmed** — IoC found in MISP! | T1068 |
| 100803 | 10 | Invalid MISP API credentials | — |
| 100804 | 10 | Rate limit exceeded | — |
| 100805 | 10 | MISP server error | — |

---

### Telegram Notifications

**Purpose:** Send real-time, context-aware alert notifications to a Telegram channel/group for instant SOC visibility.

| Setting | Value |
|---------|-------|
| Trigger | All alerts ≥ level 12 |
| Alert Format | JSON |
| Script | `Telegram/custom-telegram` |

#### ossec.conf Configuration

```xml
<integration>
  <name>custom-telegram</name>
  <level>12</level>
  <hook_url>http://localhost</hook_url>
  <alert_format>json</alert_format>
</integration>
```

> **Note:** The `hook_url` field is unused by the script (credentials are inside the script itself). Set your `TOKEN` and `CHAT_ID` directly in the `custom-telegram` script.

#### File

| File | Location on Manager | Description |
|------|---------------------|-------------|
| `custom-telegram` | `/var/ossec/integrations/custom-telegram` | Bash script — parses alert JSON and sends formatted HTML messages via Telegram Bot API |

#### How It Works

The script uses **two notification modes** based on the alert's rule group:

**🚨 MikroTik Mode** — When the alert belongs to the `mikrotik` group:
```
🚨 MIKROTIK ALERT 🚨
Level: 15
Threat: MikroTik log: Brute-force attack detected from IP 10.0.0.100
User: admin
Source IP: 10.0.0.100
Target (User/Rule): admin1
Method: winbox
🛡️
```
Extracts MikroTik-specific fields: `admin_user`, `target_user`, `srcaddr`, `method`.

**⚠️ Generic Mode** — For all other high-severity alerts:
```
⚠️ WAZUH SOC ALERT ⚠️
Level: 15
Agent: web-server-01
Threat: MISP Threat Intel: Confirmed Detection - Threat found on the system!
Source IP: 10.0.0.50
🛡️
```
Extracts standard fields: `agent.name`, `rule.description`, `data.srcip`.

#### Key Features
- **Context-aware formatting** — Automatically detects MikroTik alerts and renders router-specific fields
- **HTML parsing** — Uses Telegram's HTML mode for bold labels and clean formatting
- **Null-safe extraction** — All `jq` calls use `// empty` fallback to prevent crashes on missing fields
- **Minimal dependencies** — Only requires `bash`, `jq`, and `curl`

---

## Network Device Monitoring

### OPNsense Firewall

Custom decoders and rules parse OPNsense `filterlog` output forwarded via syslog.

#### Decoder (`OPNsense_decoder.xml`)

Extracts from OPNsense filterlog CSV format:
- `tracker` — rule tracker hash
- `action` — `pass` / `block`
- `protocol`, `srcip`, `dstip`, `srcport`, `dstport`

#### Rules (`OPNsense_rule.xml`)

| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 100900 | 0 | Base grouping rule | — |
| 100901 | 0 | Traffic allowed (silenced) | — |
| 100902 | 0 | Traffic blocked (silenced) | — |
| 100910 | 0 | False positive: broadcast drop | — |
| 100911 | 0 | False positive: IPv6 multicast drop | — |
| 100912 | 0 | Silence native rule 87702 for broadcast | — |
| 100903 | **10** | **Multiple blocks from same IP** (18 in 45s) — possible scan/flood | T1118 |
| 100905 | **12** | **Q-Feeds: Confirmed malicious IP blocked** | T1595 |

#### Agent Config (`Agents/OPNSense/agent.conf`)

The OPNsense agent monitors:
- `/var/log/filter/latest.log` — firewall filter logs
- `/var/log/suricata/eve.json` — Suricata IDS events (JSON)
- `/var/log/auth/latest.log` — authentication logs
- `/var/log/system/latest.log` — system logs
- `/conf` directory — FIM on configuration files

---

### MikroTik RouterOS

Two sets of decoders/rules handle MikroTik logs depending on the ingestion method:

#### Method 1: Direct Syslog (`MikroTik.xml`)

For MikroTik logs sent directly to the Wazuh Manager via syslog. Uses the `MikroTik::` prematch prefix.

| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 110011 | 12 | Login failure | — |
| 110012 | 3 | Successful login | — |
| 110013 | **15** | **Brute-force detected** (5 failures in 120s, same IP) | T1110 |

#### Method 2: Docker Collector (`mikrotik-decoders.xml` / `mikrotik-rules.xml`)

For MikroTik logs collected via the Dockerized syslog collector (prepends router IP).

**Decoders (20+ event types):**

| Decoder | Event Type |
|---------|------------|
| `mikrotik-identity-change` | System identity changed |
| `mikrotik-time-change` | System time modified |
| `mikrotik-timezone-change` | Timezone settings changed |
| `mikrotik-ppp-login` | PPP/VPN user logged in |
| `mikrotik-ppp-auth-failed` | PPP authentication failure |
| `mikrotik-ppp-logout` | PPP user logged out |
| `mikrotik-failed-user-login` | Admin login failure |
| `mikrotik-successful-user-login` | Admin login success |
| `mikrotik-user-logout` | Admin logout |
| `mikrotik-user-modify` | User added/changed/removed |
| `mikrotik-user-password-change` | Password changed |
| `mikrotik-ipv4-filter-rule-modify` | IPv4 firewall rule added/changed |
| `mikrotik-ipv4-filter-rule-removed` | IPv4 firewall rule removed |
| `mikrotik-ipv6-filter-rule-modify` | IPv6 firewall rule added/changed |
| `mikrotik-ipv6-filter-rule-removed` | IPv6 firewall rule removed |
| `mikrotik-ip-service-change` | IP service configuration changed |
| `mikrotik-dns-change-cli` | DNS settings changed (SSH/API) |
| `mikrotik-dns-change-web-winbox` | DNS settings changed (Web/WinBox) |
| `mikrotik-script-add-cli` | Script added (SSH/API) |
| `mikrotik-script-add-web-winbox` | Script added (Web/WinBox) |
| `mikrotik-scheduler-add-cli` | Scheduled task added (SSH/API) |
| `mikrotik-scheduler-add-web-winbox` | Scheduled task added (Web/WinBox) |
| `mikrotik-ppp-secret-add` | PPP secret added |

**Rules:**

| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 101000 | 0 | Base rule for Docker collector |  — |
| 101001 | 14 | System identity changed | — |
| 101002 | 12 | System time changed | — |
| 101003 | 8 | Timezone changed | — |
| 101004 | 10 | PPP user login  | — |
| 101005 | 10 | PPP authentication failed | — |
| 101006 | 10 | PPP user logout | — |
| 101007 | 12 | Admin login failure | — |
| 201007 | **14** | **Brute-force** (10 failures in 3 min) | T1110 |
| 101008 | 8 | Admin login success | — |
| 101009 | 6 | Admin logout | — |
| 101010 | 12 | User added/changed/removed | — |
| 101011 | 14 | Password changed | — |
| 101012 | 12 | Firewall rule added/changed | — |
| 101013 | 13 | Firewall rule removed | — |
| 101014 | 8 | IPv6 firewall rule added/changed | — |
| 101015 | 13 | IPv6 firewall rule removed | — |
| 101016 | 10 | IP service changed | — |
| 101017 | 7 | DNS configuration changed | — |
| 101020 | 13 | Script added | — |
| 101022 | 12 | Scheduled task added | — |
| 101023 | 10 | PPP secret added | — |

---

## Custom Decoders & Rules

### Local Decoders (`local/Decoders/local_decoder.xml`)

| Decoder | Purpose |
|---------|---------|
| `custom_squid` | Parses Squid proxy logs (program name match) |
| `custom_squid_domain` | Extracts domain from Squid `GET` requests |
| `custom-dns` | Parses custom DNS query logs |
| `custom-dns-domain` | Extracts queried domain from DNS logs |

### Local Rules (`local/Rules/local_rules.xml`)

| Rule ID | Level | Group | Description |
|---------|-------|-------|-------------|
| 100001 | 5 | `sshd` | SSH auth failure from specific IP (example) |
| 100100 | 5 | `squid` | Web traffic detected via Squid proxy |
| 100101 | 5 | `custom_dns` | Suspicious DNS query detected |

---

## Active Responses

| Name | Script | Trigger Rule | Action | Scope |
|------|--------|-------------|--------|-------|
| `remove-threat` | `remove-threat.sh` | `87105` (VirusTotal malicious) | Delete the malicious file | Local agent |
| `firewall-drop` | `firewall-drop` (built-in) | `100802` (MISP IoC found) | Block IP via iptables (5 min timeout) | Local agent |
| `opnsense-ban` | `opnsense-block.sh` | `110013` (MikroTik brute-force) | Add IP to OPNsense `Wazuh_Blacklist` alias via API | Local (manager) |

### OPNsense Active Response (`opnsense-block.sh`)

When a brute-force attack is detected on a MikroTik router, the script:
1. Extracts the `srcip` from the alert JSON
2. Calls the **OPNsense API** (`/api/firewall/alias_util/add/Wazuh_Blacklist`)
3. Adds the attacking IP to the `Wazuh_Blacklist` firewall alias
4. The OPNsense firewall rule referencing this alias blocks all traffic from that IP

---

## Agent Configurations

Group-based `agent.conf` files are deployed via centralized management (`/var/ossec/etc/shared/<group>/agent.conf`):

| Group | OS | FIM Directories | Extra Log Sources |
|-------|----|-----------------|-------------------|
| `Linux` | Linux | `/tmp`, `/root` (realtime) | — |
| `MISP` | Linux | `/tmp` (realtime) | — |
| `MISP_WINDOWS` | Windows | `C:\Temp` (realtime) | — |
| `OPNSense` | FreeBSD | `/conf` (realtime) | Suricata EVE, filter, auth, system logs |
| `server-A` | Linux (Docker) | — | `/var/log/mikrotik/mikrotik.log` |

---

## Docker Syslog Collector

The `docker/wazuh-collector/` directory contains a **Dockerized Wazuh agent** that acts as a syslog-to-Wazuh bridge for MikroTik routers.

### How It Works

```
MikroTik Router ──UDP 514──▶ Docker Container (socat) ──▶ /var/log/mikrotik/mikrotik.log
                                       │
                                       ▼
                              Wazuh Agent reads log ──▶ Wazuh Manager
```

1. The container runs `socat` to listen on **UDP 514**
2. Each syslog message is **prepended with the sender's IP** (`$SOCAT_PEERADDR`) for multi-router identification
3. Messages are appended to `/var/log/mikrotik/mikrotik.log`
4. The Wazuh agent (running inside the container) reads the log and forwards it to the manager
5. The manager applies the `mikrotik-collector` decoder + rules

### Deployment

```bash
cd docker/wazuh-collector/
docker-compose up -d
```

**Environment variables** (set in `docker-compose.yml`):
| Variable | Value |
|----------|-------|
| `WAZUH_MANAGER` | `WAZUH_MANAGER_IP` |
| `WAZUH_REGISTRATION_PASSWORD` | *(configured)* |
| `WAZUH_AGENT_GROUP` | `server-A` |

---

## Installation & Deployment

### Prerequisites
- **Wazuh Manager** 4.x installed on Ubuntu 24.04
- **Wazuh Indexer** running at `WAZUH_INDEXER_IP:9200` (HTTPS)
- **Docker** & **Docker Compose** on the collector host
- **MISP** instance accessible at `https://misp.local`
- **VirusTotal API key** (free or premium)
- **OPNsense** with API access enabled

### Step-by-Step

1. **Manager Configuration**
   ```bash
   # Copy the main config
   cp ossec.conf /var/ossec/etc/ossec.conf
   ```

2. **Custom Rules & Decoders**
   ```bash
   # Local rules and decoders
   cp local/Decoders/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml
   cp local/Rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml

   # MISP rules
   cp MISP/Rules/misp.xml /var/ossec/etc/rules/misp.xml
   cp MISP/Rules/misp_files_hashes.xml /var/ossec/etc/rules/misp_files_hashes.xml

   # OPNsense decoders & rules
   cp OPNSense/Decoders/OPNsense_decoder.xml /var/ossec/etc/decoders/
   cp OPNSense/Rules/OPNsense_rule.xml /var/ossec/etc/rules/

   # MikroTik decoders & rules
   cp MikroTik/Decoders/*.xml /var/ossec/etc/decoders/
   cp MikroTik/Rules/*.xml /var/ossec/etc/rules/
   ```

3. **Integrations**
   ```bash
   # VirusTotal
   cp VirusTotal/virustotal /var/ossec/integrations/virustotal
   cp VirusTotal/virustotal.py /var/ossec/integrations/virustotal.py
   chmod 750 /var/ossec/integrations/virustotal
   chown root:wazuh /var/ossec/integrations/virustotal*

   # MISP
   cp MISP/custom-misp_file_hashes.py /var/ossec/integrations/
   chmod 750 /var/ossec/integrations/custom-misp_file_hashes.py
   chown root:wazuh /var/ossec/integrations/custom-misp_file_hashes.py

   # Telegram
   cp Telegram/custom-telegram /var/ossec/integrations/custom-telegram
   chmod 750 /var/ossec/integrations/custom-telegram
   chown root:wazuh /var/ossec/integrations/custom-telegram
   ```

4. **Active Responses**
   ```bash
   # VirusTotal threat removal
   cp VirusTotal/remove-threat.sh /var/ossec/active-response/bin/
   chmod 750 /var/ossec/active-response/bin/remove-threat.sh
   chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh

   # OPNsense IP blocking
   cp OPNSense/active-response/opnsense-block.sh /var/ossec/active-response/bin/
   chmod 750 /var/ossec/active-response/bin/opnsense-block.sh
   chown root:wazuh /var/ossec/active-response/bin/opnsense-block.sh
   ```

5. **Agent Group Configs**
   ```bash
   # Create group directories and copy configs
   for group in Linux MISP MISP_WINDOWS OPNSense server-A; do
     mkdir -p /var/ossec/etc/shared/$group
     cp Agents/$group/agent.conf /var/ossec/etc/shared/$group/agent.conf
   done
   ```

6. **Restart the Manager**
   ```bash
   systemctl restart wazuh-manager
   ```

7. **Deploy the Docker Collector**
   ```bash
   cd docker/wazuh-collector/
   docker-compose up -d
   ```

---

## Security Considerations

> ⚠️ **Before pushing to a public repository, ensure you sanitize the following:**

| Item | File(s) | Action Required |
|------|---------|-----------------|
| VirusTotal API Key | `ossec.conf` | Replace with environment variable or vault reference |
| MISP API Key | `ossec.conf` | Replace with environment variable or vault reference |
| OPNsense API Key/Secret | `opnsense-block.sh` | Replace with environment variable or vault reference |
| Telegram Bot Token | `custom-telegram` | Replace `YOUR_TOKEN` and `YOUR_CHAT_ID` with your actual values |
| Wazuh Registration Password | `docker-compose.yml` | Replace with environment variable |
| Internal IP Addresses | Multiple files | Review and generalize if needed |
| SSL Certificates | `ossec.conf` (indexer section) | Ensure paths are correct for your environment |

---

## License

This project is provided as-is for educational and professional use.
- The **VirusTotal integration** (`virustotal.py`, `virustotal`) is based on the official Wazuh integration, licensed under **GPLv2**.
- The **MISP integration** (`custom-misp_file_hashes.py`) is a custom development licensed under **AGPL-3.0**.
- All custom decoders, rules, and active response scripts are original work.

---

**Pwned & Developed by [KnnnZzz](https://github.com/KnnnZzz)** 👾
---

<p align="center">
  <i>Built with 🛡️ Wazuh · 🔍 VirusTotal · 🧬 MISP · 🔥 OPNsense · 📡 MikroTik · 📲 Telegram</i>
</p>
