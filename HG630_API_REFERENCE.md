# Huawei HG630 VDSL Router — API Reference

> Reverse-engineered from firmware `HG630.bin` (SquashFS extraction).
> For building custom management applications to control the router.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Authentication System](#2-authentication-system)
3. [Request/Response Format](#3-requestresponse-format)
4. [System API (`/api/system/`)](#4-system-api)
5. [Network API (`/api/ntwk/`)](#5-network-api)
6. [Application API (`/api/app/`)](#6-application-api)
7. [Service API (`/api/service/`)](#7-service-api)
8. [Language API (`/api/language/`)](#8-language-api)
9. [CGI Endpoints (Reboot/Restore)](#9-cgi-endpoints)
10. [Complete Endpoint Summary Table](#10-complete-endpoint-summary-table)

---

## 1. Architecture Overview

### Web Server Stack
- **Web Server:** Custom Huawei ATP web server (binary: `bin/cms`)
- **Backend Language:** Lua (via embedded interpreter)
- **Frontend:** Ember.js + jQuery
- **API Format:** JSON over HTTP POST
- **Authentication:** CSRF token + SHA256 password hashing
- **Data Model:** TR-069 / TR-098 (`InternetGatewayDevice.*`)

### File Structure
```
/etc/webimg      — Packed archive of all Lua API handlers + HTML/JS/CSS
/etc/webidx      — Index file mapping filenames to offsets/sizes in webimg
/etc/lua/        — Core Lua modules (request handling, utilities)
/bin/cms         — Main web server binary (~990KB)
```

### URL Routing
- **GET requests** (read data): `GET /api/{category}/{endpoint}.json` → executes `{endpoint}.json.lua`
- **POST requests** (write data): `POST /api/{category}/{endpoint}` → executes `{endpoint}.lua`
- **CGI actions** (reboot etc): `POST /api/service/{action}.cgi`

### POST Handler Flow
1. Client sends JSON POST to `/api/{category}/{endpoint}`
2. Server loads `do_post.lua` (with CSRF validation) or `do_smart_post.lua` (without CSRF)
3. Handler extracts `request.csrf`, `request.data`, `request.action` from JSON body
4. Lua handler reads/writes TR-069 data model via `dm.GetParameterValues()` / `dm.SetParameterValues()`
5. Response sent as JSON

---

## 2. Authentication System

### Login Flow

#### Step 1: Get CSRF Token
```
GET /
```
The initial page load returns HTML containing a CSRF parameter and token.

#### Step 2: Login Request
```
POST /api/system/user_login
Content-Type: application/json
```

**Request Body:**
```json
{
  "csrf": {
    "csrf_param": "<param_from_page>",
    "csrf_token": "<token_from_page>"
  },
  "data": {
    "UserName": "admin",
    "Password": "<hashed_password>"
  }
}
```

#### Password Hashing Algorithm

Based on traffic capture and new insights, the `Password` field in the `user_login` POST request is a complex SHA256 hash generated client-side.

**Formula:**
```
SHA256( username + base64(SHA256(plaintext_password)) + csrf_param + csrf_token )
```

**Step-by-Step:**
1.  **SHA256(plaintext_password)** → Returns hex string (64 chars)
    ```python
    pwd_hash = hashlib.sha256(plaintext_password.encode()).hexdigest()
    # Example: "2f759d0b35e2186629da1b33532670c43c32a8f4bd9c214347a2b9303f7cdf17"
    ```
2.  **Base64 encode the hex string** (ensure `str.encode()` is used before `base64.b64encode`)
    ```python
    pwd_hash_b64 = base64.b64encode(pwd_hash.encode()).decode()
    # Example: "MmY3NTlkMGIzNWUyMTg2NjI5ZGExYjMzNTMyNjcwYzQzYzMyYThmNGJkOWMyMTQzNDdhMmI5MzAzZjdjZGYxNw=="
    ```
3.  **Concatenate all components** (`username`, `pwd_hash_b64`, `csrf_param`, `csrf_token`)
    ```python
    concat_string = username + pwd_hash_b64 + csrf_param + csrf_token
    # Example: "admin" + base64_hash + "mk80GEzVfGNaAjlfsSzm18mF0tB2vCZ" + "I84bBamh0e0xqLFPOfJo858llNziP6D"
    ```
4.  **Final SHA256 hash**
    ```python
    final_password_hash = hashlib.sha256(concat_string.encode()).hexdigest()
    # This `final_password_hash` is the value sent in the `Password` field of the JSON payload.
    ```
#### Login Response
**Success:**
```json
{
  "csrf_param": "<new_param>",
  "csrf_token": "<new_token>",
  "errorCategory": "ok",
  "IsFirst": false,
  "level": 2,
  "IsWizard": false
}
```

**User Levels:**
| Level | Role |
|-------|------|
| 0 | Not logged in |
| 1 | User (limited access) |
| 2 | Admin (full access) |
| 4 | Support (ISP support) |

**Error Responses:**
| Error Code | errorCategory | Meaning |
|-----------|---------------|---------|
| 4784229 | `user_pass_err` | Invalid username |
| 4784230 | `user_pass_err` | Invalid password |
| 4784231 | `Three_time_err` | 3 failed attempts, locked |
| 4784232 | `Duplicate_login` | Already logged in elsewhere |
| 4784233 | `Too_Many_user` | Too many users logged in |

#### Step 3: Logout
```
POST /api/system/user_logout
Content-Type: application/json

{
  "csrf": {"csrf_param": "...", "csrf_token": "..."}
}
```

### Session Heartbeat
```
GET /api/system/heartbeat
```
**Response:**
```json
{"interval": "5000"}
```
Keep-alive ping. Interval is in milliseconds (5 seconds). Session expires without heartbeats.

---

## 3. Request/Response Format

### Standard GET Request (Read Data)
```
GET /api/{category}/{endpoint}.json
```
Returns JSON data. Some accept query parameters (e.g., `?ID=...`).

### Standard POST Request (Write Data)
```
POST /api/{category}/{endpoint}
Content-Type: application/json

{
  "csrf": {
    "csrf_param": "<param>",
    "csrf_token": "<token>"
  },
  "data": {
    "field1": "value1",
    "field2": "value2"
  },
  "action": "<action_name>"
}
```

### Standard POST Response
**Success:**
```json
{
  "errcode": 0,
  "csrf_param": "<new_param>",
  "csrf_token": "<new_token>"
}
```

**Error:**
```json
{
  "errcode": 9003,
  "csrf_param": "<new_param>",
  "csrf_token": "<new_token>",
  "fieldName": "error_message_key"
}
```

### Common Error Codes
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / CSRF error |
| 1001 | Conflict CSRF error |
| 9003 | Invalid parameter value |
| 9004 | Permission denied |
| 9006 | Invalid enum value |
| 9007 | CSRF validation failed |

### CSRF Token Flow
Every response includes new `csrf_param` and `csrf_token`. The client MUST use the latest tokens for the next request. Tokens are single-use.

---

## 4. System API

### 4.1 Device Info
**Endpoint:** `GET /api/system/deviceinfo.json`

**Response:**
```json
{
  "DeviceName": "HG630 V2",
  "SerialNumber": "T5D7SXXXXXXXXXXX",
  "ManufacturerOUI": "00E0FC",
  "UpTime": 3862,
  "SoftwareVersion": "V100R001C298B010",
  "HardwareVersion": "VER.B"
}
```

> [!NOTE]
> `UpTime` is the **system uptime** in seconds (time since last router reboot). This is the only source of system uptime; the WAN endpoint does not include an uptime field.

**Data Model:** `InternetGatewayDevice.DeviceInfo.{ProductClass, SerialNumber, HardwareVersion, SoftwareVersion, ManufacturerOUI, UpTime}`

---

### 4.2 User Accounts
**Read:** `GET /api/system/useraccount.json`

**Response:** Array of user objects:
```json
[
  {
    "ID": "InternetGatewayDevice.UserInterface.X_Web.UserInfo.1.",
    "username": "admin",
    "userlevel": "2",
    "enableprompt": false,
    "promptinfo": "",
    "FirstLogin": false
  }
]
```

**Write:** `POST /api/system/useraccount`
```json
{
  "csrf": {...},
  "data": {
    "ID": "InternetGatewayDevice.UserInterface.X_Web.UserInfo.1.",
    "Username": "admin",
    "Password": "newpassword",
    "OldPassword": "oldpassword"
  },
  "action": "set"
}
```

**Data Model:** `InternetGatewayDevice.UserInterface.X_Web.UserInfo.{i}.{Username, Userlevel, EnablePasswdPrompt, UserpasswdPrompt, X_IsFirst}`

---

### 4.3 Config Backup Download
**Endpoint:** `GET /api/system/downloadcfg.json`

Downloads the router configuration file as a binary stream. The response is the config file content (not JSON).

---

### 4.4 Firmware Update
**Read:** `GET /api/system/onlineupg.json`

**Response:**
```json
{
  "Url": "http://update.server/...",
  "AutoCheckEnable": true
}
```

**Write:** `POST /api/system/onlineupg`

**Check for updates:**
```json
{
  "csrf": {...},
  "data": {"UpdateAction": "1"},
  "action": "check"
}
```

**Toggle auto-check:**
```json
{
  "csrf": {...},
  "data": {"AutoCheckEnable": "1"},
  "action": "update"
}
```

**Data Model:** `InternetGatewayDevice.UserInterface.{AutoUpdateServer, X_AutoCheckEnable, X_AutoCheckPeriod, X_UpdateState}`

---

### 4.5 System Logs
**Read:** `GET /api/system/loginfo.json`

**Response:**
```json
{
  "DisplayType": "all",
  "DisplayLevel": "warning",
  "LogContent": "2024-01-01 00:00:00 System started\n..."
}
```

**Write:** `POST /api/system/loginfo`
```json
{
  "csrf": {...},
  "data": {"DisplayType": "all", "DisplayLevel": "warning"},
  "action": "set"
}
```

**Data Model:** `InternetGatewayDevice.X_SyslogConfig.{DisplayType, DisplayLevel}`

---

### 4.6 Syslog Download
**Endpoint:** `GET /api/system/syslog.json`

Downloads syslog as a text file attachment (`syslog.txt`). Includes device info header (Manufacturer, Product, Serial, HW/SW versions) followed by log content.

---

### 4.7 Memory/Process Status
**Endpoint:** `GET /api/system/process.json`

**Response:**
```json
{
  "Memtotal": "65536K",
  "Memfree": "12345K",
  "Memused": "53191K"
}
```

**Data Model:** `InternetGatewayDevice.DeviceInfo.X_MemoryStatus.{Total, Free}`

---

### 4.8 Temperature
**Endpoint:** `GET /api/system/temperature.json`

**Response:** Array of temperature sensors:
```json
[
  {
    "ID": "InternetGatewayDevice.DeviceInfo.TemperatureStatus.TemperatureSensor.1.",
    "TempName": "CPU",
    "Temperature": "55"
  }
]
```

**Data Model:** `InternetGatewayDevice.DeviceInfo.TemperatureStatus.TemperatureSensor.{i}.{Name, Value}`

---

### 4.9 Online State
**Endpoint:** `GET /api/system/onlinestate.json`

Shows internet connection status.

---

### 4.10 User Level
**Endpoint:** `GET /api/system/getuserlevel.json`

Returns current logged-in user's permission level.

---

### 4.11 Device Capacity
**Endpoint:** `GET /api/system/devcapacity.json`

Returns device hardware capabilities.

---

### 4.12 Connected Device Count
**Endpoint:** `GET /api/system/device_count.json`

Returns count of connected devices.

---

### 4.13 Login Device Count
**Endpoint:** `GET /api/system/logindevice_count.json`

Returns count of logged-in management sessions.

---

### 4.14 Host Info (Connected Clients)
**Endpoint:** `GET /api/system/HostInfo.json`

Returns detailed info about all connected LAN/WiFi clients.

**Write:** `POST /api/system/HostInfo`

Used to rename or delete devices from the known hosts list.

**Rename Device Payload (action="update"):**
```json
{
  "csrf": {"csrf_param": "...", "csrf_token": "..."},
  "action": "update",
  "data": {
    "ID": "InternetGatewayDevice.LANDevice.1.Hosts.Host.1.",
    "ActualName": "New Device Name",
    "isActiveItem": true,
    "...": "other properties from GET response should be included"
  }
}
```

> [!WARNING] Naming Constraints
> - **Invalid Characters**: Device names cannot contain spaces or the following special characters: `` ` ~ ! @ # $ % ^ & * ( ) = + _ [ ] { } | ; : . ' " , < > / ? `` (Hyphens `-` are allowed).
> - **Uniqueness**: A requested `ActualName` that already equals the name of another device on the network will be rejected with an `errcode`.

**Delete Offline Device Payload (action="delete"):**
```json
{
  "csrf": {"csrf_param": "...", "csrf_token": "..."},
  "action": "delete",
  "data": {
    "ID": "InternetGatewayDevice.LANDevice.1.Hosts.Host.1.",
    "MACAddress": "AA:BB:CC:DD:EE:FF"
  }
}
```

**Data Model:** `InternetGatewayDevice.LANDevice.1.Hosts.Host.{i}.*`

---

### 4.15 Diagnostics

#### Ping Test
**Read:** `GET /api/system/diagnose_ping.json`
**Write:** `POST /api/system/diagnose_ping`

#### Traceroute
**Read:** `GET /api/system/diagnose_traceroute.json`
**Write:** `POST /api/system/diagnose_traceroute`

#### Overview
**Read:** `GET /api/system/diagnose_overview.json`

#### Device Diagnostics
**Read:** `GET /api/system/diagnose_device.json`

#### Internet Diagnostics
**Read:** `GET /api/system/diagnose_internet.json`

#### LAN Diagnostics
**Read:** `GET /api/system/diagnose_lan.json`

#### WiFi Diagnostics
**Read:** `GET /api/system/diagnose_wlan.json`
**Read:** `GET /api/system/diagnose_wlan_basic.json`
**Read:** `GET /api/system/diagnose_wlan_advance.json`

#### WiFi Channel
**Read:** `GET /api/system/diagnose_wlan_channel.json`
**Write:** `POST /api/system/diagnose_wlan_channel`

#### USB Diagnostics
**Read:** `GET /api/system/diagnose_usb.json`

#### LED Control
**Read:** `GET /api/system/diagnose_led.json`
**Write:** `POST /api/system/diagnose_led`

#### Diagnostic Report
**Read:** `GET /api/system/diagnose_report.json`
**Write:** `POST /api/system/diagnose_report`

#### Diagnostic Button
**Read:** `GET /api/system/diagnose_button.json`
**Write:** `POST /api/system/diagnose_button`

---

### 4.16 USB Devices
**Endpoint:** `GET /api/system/usbdevice.json`

---

### 4.17 Wizard WiFi Setup
**Endpoint:** `GET /api/system/wizard_wifi.json`

---

### 4.18 WLAN Mode
**Endpoint:** `GET /api/system/wlanmode.json`

---

### 4.19 First WAN Up
**Endpoint:** `GET /api/system/firstupwan.json`

---

### 4.20 Self-Diagnose
**Endpoint:** `POST /api/system/selfdiagnose`

Full self-diagnostics routine (11,842 bytes of Lua code).

---

## 5. Network API

### 5.1 WAN Status
**Endpoint:** `GET /api/ntwk/wanstatus.json`

**Also available via:** `GET /api/ntwk/wan.json`

**Optional parameter:** `?ID=InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.`

**Response:** Array of WAN connections (or single if ID specified):
```json
[
  {
    "ID": "InternetGatewayDevice.WANDevice.2.WANConnectionDevice.1.WANPPPConnection.1.",
    "Name": "INTERNET_TR069_R_PTM2",
    "Alias": "INTERNET_TR069_R_PTM2",
    "AccessType": "VDSL",
    "AccessStatus": "Up",
    "ConnectionType": "PPP_Routed",
    "ConnectionStatus": "Connected",
    "IPv4Enable": true,
    "IPv4Addr": "1.2.3.4",
    "IPv4Mask": "",
    "IPv4Gateway": "1.2.3.1",
    "IPv4DnsServers": "8.8.8.8,8.8.4.4",
    "IPv4AddrType": "DHCP",
    "IPv6Enable": false,
    "IPv6ConnectionStatus": "PendingDisconnect",
    "IsDefault": 1,
    "Enable": true,
    "NATType": 1,
    "MTU": 1500,
    "MRU": 1492,
    "MSS": 0,
    "Username": "your_username@isp.net",
    "Password": "********",
    "PPPoEACName": "MAADI2-R36A-C-EG",
    "PPPoEServiceName": "",
    "PPPAuthMode": "AUTO",
    "PPPTrigger": "AlwaysOn",
    "PPPIdletime": 300,
    "PPPDialIpMode": "dynamic",
    "MACColone": "AA:BB:CC:DD:EE:FF",
    "MACColoneEnable": false,
    "ServiceList": "INTERNET_TR069",
    "LowerLayer": "InternetGatewayDevice.WANDevice.2.WANConnectionDevice.1."
  }
]
```

> [!WARNING]
> This endpoint does **not** contain an `UpTime` field. To get uptime, use `GET /api/system/deviceinfo.json` (system uptime) or `GET /api/ntwk/dslinfo.json` (`ShowtimeStart` for DSL link uptime).

---

### 5.2 WAN Configuration
**Read:** `GET /api/ntwk/wan.json`
**Write:** `POST /api/ntwk/wan`

Full WAN connection management (add/modify/delete). Supports:
- PPPoE, IPoE, Bridge modes
- VLAN tagging
- IPv4/IPv6 dual-stack
- NAT types (NAPT, Full Cone)
- DNS configuration
- MTU/MRU/MSS settings
- MAC cloning

**Actions:** `add`, `set`, `delete`

---

### 5.3 WAN List
**Endpoint:** `GET /api/ntwk/wanlist.json`

Returns all WAN connections with link info.

---

### 5.4 DSL Info
**Read:** `GET /api/ntwk/dslinfo.json`

**Response:**
```json
{
  "Modulation": "VDSL",
  "Status": "Up",
  "UpCurrRate": 4096,
  "DownCurrRate": 36863,
  "UpMargin": 17,
  "DownMargin": 8.5,
  "UpDepth": 1,
  "DownDepth": 3,
  "UpAttenuation": 4.9,
  "DownAttenuation": 14.3,
  "UpPower": 9.6,
  "DownPower": 14.3,
  "DataPath": "Interleaved",
  "ShowtimeStart": 956,
  "UpstreamMaxBitRate": 19144,
  "DownstreamMaxBitRate": 59252,
  "InterleaveDelayUs": 0,
  "InterleaveDelayDs": 6,
  "ImpulsoNoiseProUs": 4,
  "ImpulsoNoiseProDs": 8
}
```

> [!NOTE]
> `ShowtimeStart` is the **DSL link uptime** in seconds (time since DSL synced).

**Write (DSL Restart):** `POST /api/ntwk/dslinfo`

Triggers a DSL line restart (re-sync) without rebooting the router. The payload echoes back the current DSL data obtained from the GET endpoint, wrapped with CSRF tokens.

**Request Payload:**
```json
{
  "csrf": {"csrf_param": "...", "csrf_token": "..."},
  "data": {
    "DownPower": 14.3,
    "Modulation": "VDSL",
    "UpCurrRate": 4096,
    "ShowtimeStart": 1157,
    "DownstreamMaxBitRate": 59148,
    "DownAttenuation": 14.3,
    "Status": "Up",
    "DataPath": "Interleaved",
    "UpstreamMaxBitRate": 19248,
    "UpPower": 9.6,
    "ImpulsoNoiseProUs": 4,
    "ImpulsoNoiseProDs": 8,
    "InterleaveDelayDs": 6,
    "UpAttenuation": 4.9,
    "DownMargin": 8.5,
    "InterleaveDelayUs": 0,
    "UpMargin": 17.1,
    "DownCurrRate": 36863,
    "UpDepth": 1,
    "DownDepth": 3
  }
}
```

**Response:**
```json
{"csrf_token": "...", "csrf_param": "...", "errcode": 0}
```

> [!WARNING]
> This will temporarily disconnect internet for ~30-60 seconds while the DSL line re-syncs with the DSLAM. The router itself stays operational — only the physical DSL layer restarts.

**Data Model:** `InternetGatewayDevice.WANDevice.{1|2}.WANDSLInterfaceConfig.{ModulationType, Status, UpstreamCurrRate, DownstreamCurrRate, ...}`

---

### 5.5 WiFi Status
**Endpoint:** `GET /api/ntwk/wifistatus.json`

**Response:** Array of WiFi radio status:
```json
[
  {
    "ID": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1",
    "Channel": 6,
    "FrequencyBand": "2.4GHz",
    "Status": 0
  }
]
```

Status: 0=Excellent, 10=Medium, 20=Poor (based on surrounding AP interference analysis).

---

### 5.6 WiFi Basic Configuration
**Read:** `GET /api/ntwk/WlanBasic.json`
**Write:** `POST /api/ntwk/WlanBasic`

Full WiFi configuration including SSID, password, channel, security mode, bandwidth.

**Data Model:** `InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.{SSID, Enable, Channel, BeaconType, WPAEncryptionModes, ...}`

---

### 5.7 WiFi Info
**Endpoint:** `GET /api/ntwk/wlanInfo.json`

---

### 5.8 WiFi Common Settings
**Endpoint:** `GET /api/ntwk/wlan_common.json`

---

### 5.9 WiFi SSIDs
**Read:** `GET /api/ntwk/wlan_ssids.json`
**Write:** `POST /api/ntwk/wlan_ssids`

---

### 5.10 WiFi Radio
**Read:** `GET /api/ntwk/wlanradio.json`
**Write:** `POST /api/ntwk/wlanradio`

---

### 5.11 WiFi MAC Filter
**Read:** `GET /api/ntwk/wlanfilter.json`
**Write:** `POST /api/ntwk/wlanfilter`

---

### 5.12 WiFi WPS
**Read:** `GET /api/ntwk/wlanwps.json`
**Write:** `POST /api/ntwk/wlanwps`

Start WPS: `POST /api/ntwk/wlanWpsStart`

---

### 5.13 WiFi Repeater
**Read:** `GET /api/ntwk/wlanrepeater.json`
**Write:** `POST /api/ntwk/repeaterconnect`

Additional: `GET /api/ntwk/repeaterinfo.json`, `GET /api/ntwk/repeaterdiag.json`, `GET /api/ntwk/repeaterstate.json`

---

### 5.14 WiFi Intelligent
**Read:** `GET /api/ntwk/wlanintelligent.json`
**Write:** `POST /api/ntwk/wlanintelligent`

---

### 5.15 WiFi Touch (WPS Button)
**Read:** `GET /api/ntwk/wlantouch.json`
**Write:** `POST /api/ntwk/wlantouch`

---

### 5.16 WiFi Effect
**Endpoint:** `GET /api/ntwk/wlaneffect.json`

---

### 5.17 WiFi Environment AP
**Endpoint:** `GET /api/ntwk/wlanenvironmentap.json`

Scans surrounding WiFi access points.

---

### 5.18 WiFi SSID Sync
**Read:** `GET /api/ntwk/wlanwifisync.json`
**Write:** `POST /api/ntwk/wlanwifisync`

---

### 5.19 WiFi Synced SSID
**Read:** `GET /api/ntwk/synssid.json`
**Write:** `POST /api/ntwk/synssid`

---

### 5.20 WiFi Safelock
**Read:** `GET /api/ntwk/safelock.json`
**Write:** `POST /api/ntwk/safelock`

**State:** `GET /api/ntwk/safelockstate.json`

---

### 5.21 WiFi Guest Network
**Read:** `GET /api/ntwk/guest_network_info.json`

**Time Control:**
**Read:** `GET /api/ntwk/wlan_guestnetwork_timecontrol.json`
**Write:** `POST /api/ntwk/wlan_guestnetwork_timecontrol`

---

### 5.22 WiFi PIN
**Write:** `POST /api/ntwk/wlanpin`

---

### 5.23 WiFi Repeater SSID Sync
**Read:** `GET /api/ntwk/repeaterssidsync.json`
**Write:** `POST /api/ntwk/repeaterssidsync`

---

### 5.24 LAN Info (Port Statistics)
**Endpoint:** `GET /api/ntwk/lan_info.json`

**Response:** Array of LAN port statistics:
```json
[
  {
    "ID": "LAN1",
    "sendbytes": 123456,
    "sendpacket": 1000,
    "receivebytes": 654321,
    "receivepacket": 2000,
    "senderror": 0,
    "senddiscard": 0,
    "receiveerror": 0,
    "receivediscard": 0
  }
]
```

---

### 5.25 LAN Host Configuration
**Endpoint:** `GET /api/ntwk/lan_host.json`

**Response:**
```json
{
  "ID": "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1.",
  "FirstEnable": true,
  "FristIP": "192.168.1.1",
  "FirstMac": "255.255.255.0",
  "MACAddress": "AA:BB:CC:DD:EE:FF",
  "DevName": "HG630",
  "DomainName": "home"
}
```

---

### 5.26 LAN Server (DHCP)
**Read:** `GET /api/ntwk/lan_server.json`
**Write:** `POST /api/ntwk/lan_server`

---

### 5.27 LAN IP Address Reserve
**Read:** `GET /api/ntwk/lan_ipaddressreserve.json`
**Write:** `POST /api/ntwk/lan_ipaddressreserve`

---

### 5.28 LAN IP Interfaces
**Endpoint:** `GET /api/ntwk/lan_ipifs.json`

---

### 5.29 LAN UPnP
**Read:** `GET /api/ntwk/lan_upnp.json`
**Write:** `POST /api/ntwk/lan_upnp`

---

### 5.30 LAN DHCPv6
**Read:** `GET /api/ntwk/lan_dhcp6s.json`
**Write:** `POST /api/ntwk/lan_dhcp6s`

---

### 5.31 LAN RADVD (Router Advertisement)
**Read:** `GET /api/ntwk/lan_radvd.json`
**Write:** `POST /api/ntwk/lan_radvd`

---

### 5.32 LAN WAN Type
**Endpoint:** `GET /api/ntwk/lan_wantype.json`

---

### 5.33 LAN Available Interfaces
**Endpoint:** `GET /api/ntwk/lan_availableif.json`

---

### 5.34 NTP / Time
**Read:** `GET /api/ntwk/sntp.json`

**Response:**
```json
{
  "Enable": true,
  "Status": "Synchronized",
  "NTPServer1": "pool.ntp.org",
  "NTPServer2": "None",
  "CurrentLocalTime": "2024-01-01T12:00:00",
  "LocalTimeZoneName": "GMT+02:00",
  "TimeZoneIdx": "35"
}
```

**Write:** `POST /api/ntwk/sntp`

**Data Model:** `InternetGatewayDevice.Time.{Enable, Status, NTPServer1, NTPServer2, CurrentLocalTime, LocalTimeZoneName, X_Label}`

---

### 5.35 Port Mapping
**Read:** `GET /api/ntwk/portmapping.json`
**Write:** `POST /api/ntwk/portmapping`

---

### 5.36 WAN Port Mapping
**Read:** `GET /api/ntwk/wanportmapping.json`
**Write:** `POST /api/ntwk/wanportmapping`

---

### 5.37 Port Triggering
**Read:** `GET /api/ntwk/porttrigger.json`
**Write:** `POST /api/ntwk/porttrigger`

---

### 5.38 WAN Port Triggering
**Read:** `GET /api/ntwk/wanporttrigger.json`
**Write:** `POST /api/ntwk/wanporttrigger`

---

### 5.39 DMZ
**Read:** `GET /api/ntwk/dmz.json`
**Write:** `POST /api/ntwk/dmz`

---

### 5.40 WAN DMZ
**Read:** `GET /api/ntwk/wandmz.json`
**Write:** `POST /api/ntwk/wandmz`

---

### 5.41 Multi-NAT
**Read:** `GET /api/ntwk/multinat.json`
**Write:** `POST /api/ntwk/multinat`

---

### 5.42 ALG (Application Layer Gateway)
**Read:** `GET /api/ntwk/alg.json`
**Write:** `POST /api/ntwk/alg`

---

### 5.43 Firewall
**Read:** `GET /api/ntwk/firewall.json`
**Write:** `POST /api/ntwk/firewall`

---

### 5.44 MAC Filter (Firewall)
**Read:** `GET /api/ntwk/fwmacfilter.json`
**Write:** `POST /api/ntwk/fwmacfilter`

---

### 5.45 IP Filter
**Read:** `GET /api/ntwk/ipfilter.json`
**Write:** `POST /api/ntwk/ipfilter`

**Interfaces:** `GET /api/ntwk/ipfilterintf.json`

---

### 5.46 URL Filter
**Read:** `GET /api/ntwk/urlfilter.json`
**Write:** `POST /api/ntwk/urlfilter`

---

### 5.47 MAC Filter
**Read:** `GET /api/ntwk/macfilter.json`
**Write:** `POST /api/ntwk/macfilter`

**Host list:** `POST /api/ntwk/macfilter_host`

---

### 5.48 Filter Mode
**Endpoint:** `GET /api/ntwk/filtermode.json`

---

### 5.49 Application Filter
**Read:** `GET /api/ntwk/appfilter.json`
**Write:** `POST /api/ntwk/appfilter`

---

### 5.50 ACL (Access Control)
**Read:** `GET /api/ntwk/acl.json`
**Write:** `POST /api/ntwk/acl`

---

### 5.51 Access
**Endpoint:** `GET /api/ntwk/access.json`

---

### 5.52 DDNS
**Read:** `GET /api/ntwk/ddns.json`
**Write:** `POST /api/ntwk/ddns`

---

### 5.53 Static Routes
**Read:** `GET /api/ntwk/staticroute.json`
**Write:** `POST /api/ntwk/staticroute`

---

### 5.54 RIP (Routing)
**Read:** `GET /api/ntwk/rip.json`
**Write:** `POST /api/ntwk/rip`

---

### 5.55 Bridge
**Read:** `GET /api/ntwk/bridge.json`
**Write:** `POST /api/ntwk/bridge`

**LAN:** `GET /api/ntwk/bridgelan.json`
**WAN:** `GET /api/ntwk/bridgewan.json`

---

### 5.56 Link Info
**Endpoint:** `GET /api/ntwk/link.json`

---

### 5.57 Multicast
**Read:** `GET /api/ntwk/mcast.json`
**Write:** `POST /api/ntwk/mcast`

---

### 5.58 Mirror
**Read:** `GET /api/ntwk/mirror.json`
**Write:** `POST /api/ntwk/mirror`

---

### 5.59 IPSec VPN
**Read:** `GET /api/ntwk/ipsec.json`
**Write:** `POST /api/ntwk/ipsec`

---

### 5.60 L2TP VPN
**Read:** `GET /api/ntwk/l2tp.json`
**Write:** `POST /api/ntwk/l2tp`

**Connect:** `POST /api/ntwk/l2tp_connect`

---

### 5.61 PPTP VPN
**Read:** `GET /api/ntwk/pptp.json`
**Write:** `POST /api/ntwk/pptp`

---

### 5.62 Tunnel (IPv6)
**Read:** `GET /api/ntwk/tunnel.json`
**Write:** `POST /api/ntwk/tunnel`

---

### 5.63 PIN Management (SIM)
**Read:** `GET /api/ntwk/pin.json`
**Write:** `POST /api/ntwk/pin`

---

### 5.64 UMTS/3G Info
**Read:** `GET /api/ntwk/umtsinfo.json`
**Read:** `GET /api/ntwk/umts_info_st.json`

---

### 5.65 PVC Scan (DSL)
**Read:** `GET /api/ntwk/pvcscan.json`
**Write:** `POST /api/ntwk/pvcscan`

---

### 5.66 WAN Detect
**Read:** `GET /api/ntwk/wandetect.json`
**Write:** `POST /api/ntwk/wandetect`

---

### 5.67 WAN Backup
**Read:** `GET /api/ntwk/wanbackup.json`
**Write:** `POST /api/ntwk/wanbackup`

---

### 5.68 WAN Status (Single)
**Endpoint:** `GET /api/ntwk/wan_st.json`

---

### 5.69 WiFi Info (Network)
**Endpoint:** `GET /api/ntwk/wifi_info.json`

---

### 5.70 Ethernet WAN Info
**Endpoint:** `GET /api/ntwk/ethwaninfo.json`

---

### 5.71 FON Info
**Endpoint:** `GET /api/ntwk/foninfo.json`

---

### 5.72 Parental Control (Time-based MAC Filter)
**Read:** `GET /api/ntwk/macfilter.json`
**Write:** `POST /api/ntwk/macfilter`

Allows scheduling internet access for specific devices (MAC addresses).

**GET Response Example:**
```json
[
  {
    "ID": "InternetGatewayDevice.X_FireWall.TimeRule.1.",
    "RuleName": "NightLock",
    "Enable": true,
    "TimeMode": 0,
    "Devices": [{"MACAddress": "AA:BB:CC:DD:EE:FF"}],
    "DailyFrom": "22:00", "DailyTo": "07:00",
    "Mondayenable": true, "MondayFrom": "22:00", "MondayTo": "07:00",
    "Tuesdayenable": true, "TuesdayFrom": "22:00", "TuesdayTo": "07:00",
    "Wednesdayenable": true, "WednesdayFrom": "22:00", "WednesdayTo": "07:00",
    "Thursdayenable": true, "ThursdayFrom": "22:00", "ThursdayTo": "07:00",
    "Fridayenable": true, "FridayFrom": "22:00", "FridayTo": "07:00",
    "Saturdayenable": true, "SaturdayFrom": "22:00", "SaturdayTo": "07:00",
    "Sundayenable": true, "SundayFrom": "22:00", "SundayTo": "07:00"
  }
]
```

**Write Actions:** `create`, `update`, `delete`
When creating a rule, `"ID"` should be `""`. When updating, `"ID"` must be the specific TimeRule ID.
Requires `"isActiveItem": true` in the data payload.

---

### 5.73 SWAN
**Endpoint:** `GET /api/ntwk/swan.json`

---

### 5.74 WAN Type
**Write:** `POST /api/ntwk/wantype`

---

---

## 6. Application API

### 6.1 Application Management
**Read:** `GET /api/app/application.json`
**Write:** `POST /api/app/application`

### 6.2 Application Items
**Read:** `GET /api/app/applicationitems.json`
**Write:** `POST /api/app/applicationitems`

### 6.3 QoS
**Read:** `GET /api/app/qos.json`
**Write:** `POST /api/app/qos`

### 6.4 QoS Classification
**Read:** `GET /api/app/qosclass.json`
**Write:** `POST /api/app/qosclass`

**Host:** `GET /api/app/qosclass_host.json`
**Write:** `POST /api/app/qosclass_host`

### 6.5 DMS (Media Server)
**Read:** `GET /api/app/dms.json`
**Write:** `POST /api/app/dms`

### 6.6 File System Status
**Read:** `GET /api/app/fsstatus.json`
**Write:** `POST /api/app/fsstatus`

### 6.7 FTP Anonymous
**Read:** `GET /api/app/ftpanonymous.json`
**Write:** `POST /api/app/ftpanonymous`

### 6.8 USB Account
**Read:** `GET /api/app/usbaccount.json`
**Write:** `POST /api/app/usbaccount`

### 6.9 USB Directory
**Read:** `GET /api/app/usbdir.json`
**Write:** `POST /api/app/usbdir`

### 6.10 Print Server Status
**Read:** `GET /api/app/psstatus.json`
**Write:** `POST /api/app/psstatus`

### 6.11 Speed Test Result
**Read:** `GET /api/app/speedtestresult.json`
**Write:** `POST /api/app/speedtestresult`

### 6.12 LAN Available Interfaces
**Endpoint:** `GET /api/app/lan_availableif.json`

---

## 7. Service API

### 7.1 TR-069 / CWMP
**Read:** `GET /api/service/cwmp.json`
**Write:** `POST /api/service/cwmp`

**Data Model:** TR-069 management parameters.

### 7.2 STUN
**Read:** `GET /api/service/stun.json`
**Write:** `POST /api/service/stun`

---

## 8. Language API

### 8.1 Language
**Write:** `POST /api/language/lang`

---

## 9. CGI Endpoints (Reboot / Restore)

These are special CGI endpoints that don't follow the standard JSON API pattern.

### 9.1 Reboot Router

**Endpoint:** `POST /api/service/reboot.cgi`

**Expected Behavior (Critical Details):**
-   The router expects a raw JSON payload (e.g., `{"csrf":{"csrf_param":"...","csrf_token":"..."}}`) as the request body.
-   **Crucially, the HTTP `Content-Type` header MUST be `application/x-www-form-urlencoded`, despite the JSON body.** This is a non-standard but required behavior.
-   **CSRF Token Refresh:** New CSRF tokens specific to the reboot action must be obtained immediately prior to the reboot request. These are typically acquired by making a GET request to `/html/advance.html` and extracting them from its HTML meta tags.
-   **UI State Emulation:** To ensure successful execution, the request often needs to emulate browser behavior by including specific HTTP headers (`Origin`, `Accept`, `Accept-Language`, `User-Agent`) and UI-state cookies (`activeMenuID`, `activeSubmenuID`).
-   **Compact JSON Payload:** The JSON payload must be compact, with no extra whitespace, to match the `Content-Length` expected by the router.

**Request Body Example:**
```
{"csrf":{"csrf_param":"<param>","csrf_token":"<token>"}}
```
*(This payload should be sent as a raw string in the request body, not as a form-encoded field.)*

**Response:**
```json
{
  "errcode": 0,
  "csrf_param": "...",
  "csrf_token": "..."
}
```

**Behavior:** If the request is correctly formed, the router reboots. The client should then expect a connection timeout, followed by the router coming back online after a period.

### 9.2 Factory Reset
```
POST /api/service/restoredefcfg.cgi
Content-Type: application/json

{
  "csrf": {
    "csrf_param": "<param>",
    "csrf_token": "<token>"
  }
}
```

**⚠️ WARNING:** Restores ALL settings to factory defaults!

---

## 10. Complete Endpoint Summary Table

### System Endpoints (`/api/system/`)

| Endpoint | GET | POST | Description |
|----------|-----|------|-------------|
| `deviceinfo.json` | ✅ | — | Device info (model, serial, uptime) |
| `heartbeat.json` | ✅ | — | Session keepalive (5s interval) |
| `useraccount.json` / `useraccount` | ✅ | ✅ | User account management |
| `user_login` | — | ✅ | Login (auth) |
| `user_logout` | — | ✅ | Logout |
| `getuserlevel.json` | ✅ | — | Current user permission level |
| `downloadcfg.json` | ✅ | — | Download config backup |
| `onlineupg.json` / `onlineupg` | ✅ | ✅ | Firmware update |
| `onlinestate.json` | ✅ | — | Internet connection state |
| `loginfo.json` / `loginfo` | ✅ | ✅ | System logs |
| `syslog.json` | ✅ | — | Download syslog file |
| `process.json` | ✅ | — | Memory status |
| `temperature.json` | ✅ | — | Temperature sensors |
| `HostInfo.json` / `HostInfo` | ✅ | ✅ | Connected clients |
| `SpecHostInfo.json` | ✅ | — | Specific host info |
| `devcapacity.json` | ✅ | — | Device capabilities |
| `device_count.json` | ✅ | — | Connected device count |
| `logindevice_count.json` | ✅ | — | Login session count |
| `firstupwan.json` | ✅ | — | First active WAN |
| `wizard_wifi.json` | ✅ | — | WiFi wizard data |
| `wlanmode.json` | ✅ | — | WLAN operating mode |
| `usbdevice.json` | ✅ | — | USB device info |
| `diagnose_overview.json` | ✅ | — | Diagnostic overview |
| `diagnose_device.json` | ✅ | — | Device diagnostics |
| `diagnose_internet.json` | ✅ | — | Internet diagnostics |
| `diagnose_lan.json` | ✅ | — | LAN diagnostics |
| `diagnose_wlan.json` | ✅ | — | WiFi diagnostics |
| `diagnose_wlan_basic.json` | ✅ | — | WiFi basic diag |
| `diagnose_wlan_advance.json` | ✅ | — | WiFi advanced diag |
| `diagnose_wlan_channel.json` / `diagnose_wlan_channel` | ✅ | ✅ | WiFi channel diag |
| `diagnose_usb.json` | ✅ | — | USB diagnostics |
| `diagnose_ping.json` / `diagnose_ping` | ✅ | ✅ | Ping test |
| `diagnose_traceroute.json` / `diagnose_traceroute` | ✅ | ✅ | Traceroute test |
| `diagnose_led.json` / `diagnose_led` | ✅ | ✅ | LED control |
| `diagnose_button.json` / `diagnose_button` | ✅ | ✅ | Button diagnostics |
| `diagnose_report.json` / `diagnose_report` | ✅ | ✅ | Diagnostic report |
| `selfdiagnose` | — | ✅ | Full self-diagnostics |
| `setfirst` | — | ✅ | Set first-run flag |

### Network Endpoints (`/api/ntwk/`)

| Endpoint | GET | POST | Description |
|----------|-----|------|-------------|
| `wanstatus.json` | ✅ | — | WAN connection status |
| `wan.json` / `wan` | ✅ | ✅ | WAN configuration |
| `wanlist.json` | ✅ | — | All WAN connections |
| `wan_st.json` | ✅ | — | WAN state |
| `wandetect.json` / `wandetect` | ✅ | ✅ | WAN auto-detect |
| `wanbackup.json` / `wanbackup` | ✅ | ✅ | WAN backup |
| `wandmz.json` / `wandmz` | ✅ | ✅ | WAN DMZ |
| `wanportmapping.json` / `wanportmapping` | ✅ | ✅ | WAN port mapping |
| `wanporttrigger.json` / `wanporttrigger` | ✅ | ✅ | WAN port triggering |
| `wantype` | — | ✅ | Set WAN type |
| `swan.json` | ✅ | — | SWAN info |
| `dslinfo.json` / `dslinfo` | ✅ | ✅ | DSL line statistics |
| `ethwaninfo.json` | ✅ | — | Ethernet WAN info |
| `link.json` | ✅ | — | Link layer info |
| `pvcscan.json` / `pvcscan` | ✅ | ✅ | PVC scan (DSL) |
| `lan_info.json` | ✅ | — | LAN port statistics |
| `lan_host.json` / `lan_host` | ✅ | ✅ | LAN host config |
| `lan_server.json` / `lan_server` | ✅ | ✅ | DHCP server |
| `lan_ipaddressreserve.json` / `lan_ipaddressreserve` | ✅ | ✅ | DHCP reservations |
| `lan_ipifs.json` | ✅ | — | LAN IP interfaces |
| `lan_upnp.json` / `lan_upnp` | ✅ | ✅ | UPnP |
| `lan_dhcp6s.json` / `lan_dhcp6s` | ✅ | ✅ | DHCPv6 |
| `lan_radvd.json` / `lan_radvd` | ✅ | ✅ | Router advertisement |
| `lan_wantype.json` | ✅ | — | LAN WAN type |
| `lan_availableif.json` | ✅ | — | Available interfaces |
| `WlanBasic.json` / `WlanBasic` | ✅ | ✅ | WiFi basic config |
| `wlanInfo.json` | ✅ | — | WiFi information |
| `wlan_common.json` | ✅ | — | WiFi common settings |
| `wlan_ssids.json` / `wlan_ssids` | ✅ | ✅ | WiFi SSIDs |
| `wlanradio.json` / `wlanradio` | ✅ | ✅ | WiFi radio |
| `wlanfilter.json` / `wlanfilter` | ✅ | ✅ | WiFi MAC filter |
| `wlanwps.json` / `wlanwps` | ✅ | ✅ | WPS configuration |
| `wlanWpsStart` | — | ✅ | Start WPS |
| `wlanpin` | — | ✅ | WiFi PIN |
| `wlantouch.json` / `wlantouch` | ✅ | ✅ | WiFi Touch/WPS button |
| `wlanrepeater.json` | ✅ | — | WiFi repeater config |
| `repeaterconnect.json` / `repeaterconnect` | ✅ | ✅ | Connect repeater |
| `repeaterinfo.json` / `repeaterinfo` | ✅ | ✅ | Repeater info |
| `repeaterdiag.json` | ✅ | — | Repeater diagnostics |
| `repeaterstate.json` | ✅ | — | Repeater state |
| `repeaterssidsync.json` / `repeaterssidsync` | ✅ | ✅ | Repeater SSID sync |
| `wlanintelligent.json` / `wlanintelligent` | ✅ | ✅ | WiFi intelligent |
| `wlaneffect.json` | ✅ | — | WiFi effect |
| `wlanenvironmentap.json` | ✅ | — | Scan surrounding APs |
| `wlanwifisync.json` / `wlanwifisync` | ✅ | ✅ | WiFi sync |
| `synssid.json` / `synssid` | ✅ | ✅ | Synced SSID |
| `safelock.json` / `safelock` | ✅ | ✅ | WiFi safelock |
| `safelockstate.json` | ✅ | — | Safelock state |
| `guest_network_info.json` | ✅ | — | Guest network |
| `wlan_guestnetwork_timecontrol.json` / `wlan_guestnetwork_timecontrol` | ✅ | ✅ | Guest network timer |
| `wifi_info.json` | ✅ | — | WiFi info |
| `wifistatus.json` / `wifistatus` | ✅ | ✅ | WiFi channel status |
| `wlanmode.json` | ✅ | — | WLAN mode |
| `sntp.json` / `sntp` | ✅ | ✅ | NTP/Time settings |
| `ddns.json` / `ddns` | ✅ | ✅ | Dynamic DNS |
| `portmapping.json` / `portmapping` | ✅ | ✅ | Port mapping |
| `porttrigger.json` / `porttrigger` | ✅ | ✅ | Port triggering |
| `dmz.json` / `dmz` | ✅ | ✅ | DMZ |
| `multinat.json` / `multinat` | ✅ | ✅ | Multi-NAT |
| `alg.json` / `alg` | ✅ | ✅ | ALG |
| `firewall.json` / `firewall` | ✅ | ✅ | Firewall |
| `fwmacfilter.json` / `fwmacfilter` | ✅ | ✅ | Firewall MAC filter |
| `ipfilter.json` / `ipfilter` | ✅ | ✅ | IP filter |
| `ipfilterintf.json` | ✅ | — | IP filter interfaces |
| `urlfilter.json` / `urlfilter` | ✅ | ✅ | URL filter |
| `macfilter.json` / `macfilter` | ✅ | ✅ | MAC filter |
| `macfilter_host` | — | ✅ | MAC filter host |
| `filtermode.json` | ✅ | — | Filter mode |
| `appfilter.json` / `appfilter` | ✅ | ✅ | Application filter |
| `acl.json` / `acl` | ✅ | ✅ | Access control |
| `access.json` | ✅ | — | Access info |
| `staticroute.json` / `staticroute` | ✅ | ✅ | Static routes |
| `rip.json` / `rip` | ✅ | ✅ | RIP routing |
| `bridge.json` / `bridge` | ✅ | ✅ | Bridge config |
| `bridgelan.json` | ✅ | — | Bridge LAN |
| `bridgewan.json` | ✅ | — | Bridge WAN |
| `mcast.json` / `mcast` | ✅ | ✅ | Multicast |
| `mirror.json` / `mirror` | ✅ | ✅ | Port mirror |
| `ipsec.json` / `ipsec` | ✅ | ✅ | IPSec VPN |
| `l2tp.json` / `l2tp` | ✅ | ✅ | L2TP VPN |
| `l2tp_connect` | — | ✅ | L2TP connect |
| `pptp.json` / `pptp` | ✅ | ✅ | PPTP VPN |
| `tunnel.json` / `tunnel` | ✅ | ✅ | IPv6 tunnel |
| `pin.json` / `pin` | ✅ | ✅ | SIM PIN |
| `umtsinfo.json` | ✅ | — | 3G/UMTS info |
| `umts_info_st.json` | ✅ | — | 3G/UMTS state |
| `foninfo.json` | ✅ | — | FON info |
| `parentControl` | — | ✅ | Parental controls |

### Application Endpoints (`/api/app/`)

| Endpoint | GET | POST | Description |
|----------|-----|------|-------------|
| `application.json` / `application` | ✅ | ✅ | Application management |
| `applicationitems.json` / `applicationitems` | ✅ | ✅ | Application items |
| `qos.json` / `qos` | ✅ | ✅ | QoS settings |
| `qosclass.json` / `qosclass` | ✅ | ✅ | QoS classification |
| `qosclass_host.json` / `qosclass_host` | ✅ | ✅ | QoS host class |
| `dms.json` / `dms` | ✅ | ✅ | Media server (DLNA) |
| `fsstatus.json` / `fsstatus` | ✅ | ✅ | File system status |
| `ftpanonymous.json` / `ftpanonymous` | ✅ | ✅ | FTP anonymous access |
| `usbaccount.json` / `usbaccount` | ✅ | ✅ | USB user accounts |
| `usbdir.json` / `usbdir` | ✅ | ✅ | USB directories |
| `psstatus.json` / `psstatus` | ✅ | ✅ | Print server status |
| `speedtestresult.json` / `speedtestresult` | ✅ | ✅ | Speed test |
| `lan_availableif.json` | ✅ | — | Available interfaces |

### Service Endpoints (`/api/service/`)

| Endpoint | GET | POST | Description |
|----------|-----|------|-------------|
| `cwmp.json` / `cwmp` | ✅ | ✅ | TR-069 CWMP |
| `stun.json` / `stun` | ✅ | ✅ | STUN configuration |
| `reboot.cgi` | — | ✅ | **Reboot router** |
| `restoredefcfg.cgi` | — | ✅ | **Factory reset** |

### Language Endpoint (`/api/language/`)

| Endpoint | GET | POST | Description |
|----------|-----|------|-------------|
| `lang` | — | ✅ | Set language |

---

## Quick Start: Reboot Example (Python) - *Updated 2026-02-19*

```python
import hashlib
import base64
import json
import requests
import re
import time
from http.cookies import SimpleCookie

ROUTER_IP = "192.168.1.1"
BASE_URL = f"http://{ROUTER_IP}"
USERNAME = "admin"
PASSWORD = "admin" # Plaintext password

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
    "Origin": BASE_URL,
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.5",
    "X-Requested-With": "XMLHttpRequest",
    "Sec-GPC": "1", # Added based on pcap
    "Accept-Encoding": "gzip, deflate", # Added based on pcap
})

csrf_param = None
csrf_token = None

def _extract_csrf(html_content):
    global csrf_param, csrf_token
    patterns = [
        (r'<meta[^>]*name=["\']csrf_param["\'][^>]*content=["\']([^"\']+)["\']', 
         r'<meta[^>]*name=["\']csrf_token["\'][^>]*content=["\']([^"\']+)["\']'),
        (r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf_param["\']', 
         r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']'),
        (r'csrf_param["\']?\s*[:=]\s*["\']([^"\']+)', 
         r'csrf_token["\']?\s*[:=]\s*["\']([^"\']+)')
    ]
    for param_pattern, token_pattern in patterns:
        param_match = re.search(param_pattern, html_content, re.IGNORECASE)
        token_match = re.search(token_pattern, html_content, re.IGNORECASE)
        if param_match and token_match:
            csrf_param = param_match.group(1)
            csrf_token = token_match.group(1)
            return True
    return False

def _update_csrf_from_response(response_data):
    global csrf_param, csrf_token
    if isinstance(response_data, dict):
        if 'csrf_param' in response_data and 'csrf_token' in response_data:
            csrf_param = response_data['csrf_param']
            csrf_token = response_data['csrf_token']
        elif 'params' in response_data: # Handle nested params
            p = response_data['params']
            if 'csrf_param' in p and 'csrf_token' in p:
                csrf_param = p['csrf_param']
                csrf_token = p['csrf_token']

def refresh_csrf():
    """Fetches fresh CSRF tokens, typically from /html/advance.html"""
    try:
        r_advance = session.get(f"{BASE_URL}/html/advance.html", timeout=5)
        if r_advance.status_code == 200:
            if _extract_csrf(r_advance.text):
                return True
    except requests.exceptions.RequestException:
        pass
    return False

# Step 1: Get initial page (extract CSRF from response HTML)
print("Fetching initial CSRF tokens...")
try:
    resp_root = session.get(BASE_URL, timeout=5)
    _extract_csrf(resp_root.text)
except requests.exceptions.RequestException as e:
    print(f"Error fetching root: {e}")
    exit(1)

if not csrf_param or not csrf_token:
    print("Initial CSRF tokens not found. Exiting.")
    exit(1)
print(f"Initial CSRF: Param={csrf_param[:10]}... Token={csrf_token[:10]}...")

# Step 2: Login
print("Attempting login...")
sha256_pass = hashlib.sha256(PASSWORD.encode()).hexdigest()
b64_sha256 = base64.b64encode(sha256_pass.encode()).decode()
plain_pwd = USERNAME + b64_sha256 + csrf_param + csrf_token
hashed_pwd = hashlib.sha256(plain_pwd.encode()).hexdigest()

login_data = {
    "csrf": {"csrf_param": csrf_param, "csrf_token": csrf_token},
    "data": {"UserName": USERNAME, "Password": hashed_pwd}
}

try:
    resp_login = session.post(f"{BASE_URL}/api/system/user_login", json=login_data, timeout=10)
    resp_login.raise_for_status()
    result = resp_login.json()
    
    if result.get("errorCategory") == "ok":
        _update_csrf_from_response(result)
        print(f"Login successful! New CSRF: Param={csrf_param[:10]}... Token={csrf_token[:10]}...")
    else:
        print(f"Login failed: {result.get('errorCategory', 'Unknown error')}")
        exit(1)

except requests.exceptions.RequestException as e:
    print(f"Error during login: {e}")
    exit(1)

# Step 2.5: Emulate UI state (as seen in pcap)
print("Emulating UI state...")
session.cookies.set("activeMenuID", "maintain_settings", domain=ROUTER_IP, path="/")
session.cookies.set("activeSubmenuID", "device_mngt", domain=ROUTER_IP, path="/")
# It might be necessary to manually set the domain if it's not the same as the base_url.split("//")[-1]

# Step 3: Refresh CSRF from advance.html (critical for reboot)
print("Refreshing CSRF from advance.html for reboot...")
if not refresh_csrf():
    print("Failed to refresh CSRF from advance.html. Exiting.")
    exit(1)
print(f"Reboot CSRF: Param={csrf_param[:10]}... Token={csrf_token[:10]}...")

# Step 3.5: Fetch device info (pcap shows this in sequence)
print("Fetching device info (pre-reboot sequence)...")
try:
    session.get(f"{BASE_URL}/api/system/deviceinfo.json", timeout=5).raise_for_status()
except requests.exceptions.RequestException as e:
    print(f"Warning: Failed to fetch device info as part of sequence: {e}")


# Step 4: Reboot
print("Sending reboot command...")
reboot_payload_dict = {
    "csrf": {"csrf_param": csrf_param, "csrf_token": csrf_token}
}
reboot_payload_str = json.dumps(reboot_payload_dict, separators=(',', ':'))

reboot_headers = {
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Referer": f"{BASE_URL}/html/advance.html",
}
# The 'requests' library automatically merges session headers and explicit headers,
# but we need to ensure the Content-Type is exactly as required.

try:
    resp_reboot = session.post(f"{BASE_URL}/api/service/reboot.cgi", 
                               data=reboot_payload_str, # Send as raw string
                               headers=reboot_headers, 
                               timeout=5)
    resp_reboot.raise_for_status()
    reboot_result = resp_reboot.json()
    if reboot_result.get("errcode") == 0:
        print("Reboot command successfully sent to router (response errcode 0).")
    else:
        print(f"Reboot command failed with router response: {reboot_result}")
        exit(1)
except requests.exceptions.Timeout:
    print("Reboot command sent. Connection timed out (expected due to router reboot).")
except requests.exceptions.RequestException as e:
    print(f"Error during reboot command (might be expected timeout): {e}")

# Step 5: Wait for router to come back online
print("Waiting for router to come back online...")
time.sleep(10) # Give router some time to start rebooting
while True:
    try:
        r_heartbeat = session.get(f"{BASE_URL}/api/system/heartbeat", timeout=2)
        if r_heartbeat.status_code == 200:
            print("Router is back online!")
            break
    except requests.exceptions.RequestException:
        pass # Expected during reboot
    time.sleep(2)

---

## Notes

- **CSRF tokens are single-use.** Always use the latest `csrf_param` and `csrf_token` from the previous response.
- **Session timeout:** Without heartbeat pings (every 5s), the session expires.
- **User level 2 (admin) required** for most write operations.
- **Config download** (`downloadcfg.json`) returns binary config, not JSON.
- **Syslog download** (`syslog.json`) returns text file with custom headers.
- **The router uses TR-098 data model** (`InternetGatewayDevice.*`), common in DSL CPE devices.

---

*Generated by reverse-engineering HG630 firmware. Last updated: 2026-02-16.*
