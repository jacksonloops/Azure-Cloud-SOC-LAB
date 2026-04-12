# ☁️ Azure Cloud SOC Lab — Live Honeypot with Microsoft Sentinel SIEM

## Objective

Built a cloud-based SOC environment in Microsoft Azure to ingest, analyze, and visualize real-world cyber attacks. Deployed a deliberately exposed Windows 10 VM as a honeypot, forwarded security logs to a Log Analytics Workspace, and connected Microsoft Sentinel (SIEM) to detect and map brute-force login attempts from across the globe — all using live attack data, not simulations.

---

## Architecture

```
Internet (Attackers)
        │
        ▼
┌──────────────────────────────────────────────────┐
│  Azure Resource Group                            │
│                                                  │
│  ┌─────────────────────────────────────────────┐ │
│  │  Virtual Network (VNet)                     │ │
│  │  ┌───────────────────────────────────────┐  │ │
│  │  │  Subnet                               │  │ │
│  │  │  ┌─────────────────────────────────┐  │  │ │
│  │  │  │  CORP-NET-WEST-1 (Honeypot VM)  │  │  │ │
│  │  │  │  Windows 10 Pro                 │  │  │ │
│  │  │  │  Host Firewall: Disabled        │  │  │ │
│  │  │  └─────────────────────────────────┘  │  │ │
│  │  └───────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────┘ │
│                                                  │
│  NSG (Network Security Group)                    │
│  Rule: Allow ALL inbound traffic                 │
│                                                  │
│  ┌──────────────────────┐   ┌─────────────────┐  │
│  │  Log Analytics       │──▶│  Microsoft      │  │
│  │  Workspace (LAW)     │   │  Sentinel       │  │
│  │                      │◀──│  (SIEM)         │  │
│  └──────────────────────┘   └─────────────────┘  │
│         ▲                                        │
│         │  Security Event Logs (via AMA)         │
│         └────────────────────────────────────────┘
```

---

## Technologies & Tools

- **Microsoft Azure** — Cloud platform (Free Tier, $200 credit)
- **Microsoft Sentinel** — Cloud-native SIEM for log ingestion, detection, and visualization
- **Log Analytics Workspace (LAW)** — Centralized log repository
- **Azure Virtual Machines** — Windows 10 honeypot (D2s size)
- **Network Security Groups (NSG)** — Cloud firewall configuration
- **KQL (Kusto Query Language)** — Log querying and threat hunting
- **Windows Event Viewer** — Local log analysis (Event ID 4625: Failed Logon)
- **Azure Monitor Agent (AMA)** — Log forwarding from VM to LAW

---

## Phase 1 — Infrastructure Deployment

### Resource Group & Networking
- Created a Resource Group to organize all cloud resources
- Deployed a Virtual Network (VNet) with a subnet for the honeypot VM
- Encountered a region availability issue with the desired VM size (D2s) — recreated the Resource Group and VNet in **US West** to resolve

### Honeypot VM Configuration
- Deployed a **Windows 10** VM named `CORP-NET-WEST-1` to appear as a legitimate corporate system to attackers
- Connected the VM to the existing VNet and subnet
- Disabled all Windows Firewall profiles on the VM to maximize attack surface

### NSG Firewall Rules
Replaced the default RDP-only inbound rule with a permissive rule to attract attackers:

| Setting | Value |
|---|---|
| Source | Any |
| Source Port Ranges | * |
| Destination | Any |
| Destination Port Ranges | * |
| Protocol | Any |
| Action | Allow |
| Priority | 100 |
| Name | DANGER_AllowAllTraffic |

> Verified connectivity by pinging the VM's public IP from an external machine.

---

## Phase 2 — Logging & SIEM Configuration

### Log Analytics Workspace
- Created a LAW inside the Resource Group to serve as the centralized log repository

### Microsoft Sentinel Deployment
- Deployed Sentinel and connected it to the LAW
- Installed **Windows Security Events** solution from the Content Hub
- Configured a **Data Collection Rule (DCR)** via the Windows Security Events via AMA connector to forward security logs from the VM to the LAW

### Validating Log Ingestion
Ran KQL queries in Sentinel to confirm SecurityEvent logs were flowing from the honeypot:

```kql
SecurityEvent
| where EventID == 4625
| order by TimeGenerated desc
```

> Within minutes of deployment, brute-force login attempts were detected from international IP addresses. The first observed attacker originated from **Hong Kong**, attempting to authenticate with the username `administrator` — the IP was already flagged on threat intelligence databases.

---

## Phase 3 — Threat Visualization

### GeoIP Watchlist
- Uploaded an IP-to-geolocation CSV as a Sentinel **Watchlist** to enrich log data with geographic information
- Search key: `network`

### KQL Geolocation Query
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

### Attack Map Workbook
- Created a custom **Sentinel Workbook** using a JSON configuration to visualize failed login attempts on a world map
- Each point represents a unique attacker source, plotted by geographic coordinates derived from the GeoIP watchlist

<!-- Add your attack map screenshot here -->
<!-- ![Attack Map](images/attack-map.png) -->

---

## Key Findings

- Automated brute-force bots began targeting the honeypot **within minutes** of deployment
- Attackers attempted common usernames such as `administrator`, `admin`, `user`
- Attack traffic originated from multiple countries including China, Russia, and various other regions
- All attempts were unsuccessful due to strong password policy (15+ characters, mixed complexity)

---

## Lessons Learned

- Any internet-exposed system will be discovered and attacked almost immediately
- NSG and host-level firewalls are critical layers of defense — disabling them (as done intentionally here) demonstrates the volume of background internet noise
- Centralized log management (LAW) combined with a SIEM (Sentinel) enables rapid detection and investigation
- GeoIP enrichment adds valuable context for threat analysis and visualization
- Strong passwords remain a fundamental and effective control against brute-force attacks

---

## Next Steps

- [ ] Install **Sysmon** on the honeypot for deeper telemetry (process creation, network connections, registry changes)
- [ ] Build custom **analytics rules** — brute force detection, impossible travel, successful login after failed attempts
- [ ] Create **automated playbooks** (Logic Apps) to auto-block attacker IPs via NSG
- [ ] Enable **Azure Activity Logs** connector for cloud resource monitoring
- [ ] Map detections to the **MITRE ATT&CK** framework

---

## Screenshots

<!-- Add your screenshots here -->
<!-- ![Architecture](images/architecture.png) -->
<!-- ![Sentinel Dashboard](images/sentinel-dashboard.png) -->
<!-- ![Attack Map](images/attack-map.png) -->
<!-- ![Failed Logins](images/failed-logins.png) -->
