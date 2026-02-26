# HG630 Router Firmware Reverse Engineering Task

## Goal
- Created a comprehensive API reference document at: `HG630_API_REFERENCE.md`
- Analyzed network traffic captures to confirm and refine authentication details.


## Firmware Location
Extracted squashfs root: `./hg630/HG630.bin.extracted/920000/squashfs-root/`

## Key Files
- **webidx**: `./hg630/HG630.bin.extracted/920000/squashfs-root/etc/webidx` — Maps ALL API endpoints with offsets/sizes
- **webimg**: `./hg630/HG630.bin.extracted/920000/squashfs-root/etc/webimg` — Packed Lua API files
- **Lua handlers**: `./hg630/HG630.bin.extracted/920000/squashfs-root/etc/lua/` — Core request handling

## How to Extract API Lua Files
The webidx lists files with format: `filename size offset`
Extract with: `dd if="./hg630/HG630.bin.extracted/920000/squashfs-root/etc/webimg" bs=1 skip=OFFSET count=SIZE 2>/dev/null`

## What to Document

### 1. Authentication System
- user_login.lua (offset 399562, size 2199)
- user_logout.lua (offset 401761, size 48)
- Password hash: Confirmed client-side SHA256 of plaintext password based on traffic capture. The complex hash (SHA256(Username + base64Encode(SHA256(Password)) + csrf_param + csrf_token)) is likely for internal server-side verification.
- CSRF token flow

### 2. ALL API Endpoints (from webidx)
Categorize by path:
- `/api/system/` — device info, reboot, config, user accounts, diagnostics, logs, firmware
- `/api/ntwk/` — WAN, LAN, WiFi, DHCP, DNS, firewall, port mapping, VPN
- `/api/app/` — QoS, USB, FTP, DMS
- `/api/service/` — TR-069/CWMP, STUN
- `/api/language/` — Language

### 3. Critical Endpoints to Extract and Analyze
Extract these from webimg and document their parameters, data model paths, request/response:
- deviceinfo.json.lua (352275, 961) — device info
- heartbeat.json.lua (376085, 52) — keepalive
- downloadcfg.json.lua (374451, 82) — config backup
- onlineupg.json.lua (381831, 470) + onlineupg.lua (382301, 506) — firmware update
- useraccount.json.lua (401809, 1653) + useraccount.lua (403462, 3414) — user management
- loginfo.json.lua (379436, 842) — system logs
- process.json.lua (382807, 566) — processes
- temperature.json.lua (397083, 450) — temperature
- wanstatus.json.lua (268125, 4220) — WAN status
- wifistatus.json.lua (274549, 2743) — WiFi status
- lan_info.json.lua (135137, 1979) — LAN info
- lan_host.json.lua (132495, 1078) — LAN hosts
- dslinfo.json.lua (96692, 1717) — DSL info
- WlanBasic.json.lua (46594, 7655) — WiFi config
- sntp.json.lua (200275, 786) — NTP/time
- wan.json.lua (225514, 10695) — WAN connections
- syslog.json.lua (395638, 1445) — syslog config

### 4. Reboot Discovery
- device_mngt.js (747220, 12914) — Check how reboot/restore/restart works

### 5. Request Format
Standard POST format:
```json
{"csrf":{"csrf_param":"...","csrf_token":"..."},"data":{...},"action":"..."}
```

### 6. Output
Create HG630_API_REFERENCE.md with:
- Full auth flow documentation
- Every endpoint categorized with URL, method, parameters, data model paths
- Summary table of all endpoints at the end

---

## Implementation Log

### 2024-02-26: New Features Added

**Analyzed from firmware:**
- `/api/ntwk/ddns` - DDNS configuration
- `/api/ntwk/portmapping` - Port forwarding (NAT)
- `/api/ntwk/upnp` - UPnP settings
- `/api/ntwk/firewall` - Firewall with DoS protection
- `/api/ntwk/macfilter` - MAC filtering

**Added to advanced_router.py:**
1. **WiFi Toggle** - Turn WiFi on/off via `/api/ntwk/wlanradio`
2. **DDNS** - Get/set DDNS settings
3. **Port Forwarding (NAT)** - List, add, delete port forwarding rules
4. **UPnP** - Enable/disable UPnP
5. **Firewall** - Configure firewall with DoS protection (ICMP, SYN, ARP)
6. **MAC Filter** - Add MAC address to filter

**CLI Commands Added:**
- `wifi on` / `wifi off`
- `wifi-status`
- `ddns`, `set-ddns`
- `nat`, `add-nat`, `del-nat`
- `upnp`, `set-upnp`
- `firewall`, `set-firewall`
- `mac-filter`, `set-mac-filter`

**Interactive Menu Updated:**
- Added options 15-19 for network features
- Added interactive functions for NAT, UPnP, Firewall
