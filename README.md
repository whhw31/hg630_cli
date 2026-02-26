# 🚀 HG630 VDSL Router Manager (Advanced CLI)

A powerful, secure, and feature-rich command-line interface for managing **Huawei HG630 VDSL routers**. This tool allows you to monitor DSL statistics, manage connected devices, control bandwidth, and more—all without using the slow web interface.

---

## ✨ Key Features

- **🔐 Secure Credential Storage**: Stored credentials are encoded in a local `.env` file for quick, autonomous operations.
- **🎮 Multiple Modes**: Choose between a full **Interactive Menu** or fast **Direct Commands**.
- **📡 Extensive Monitoring**: Real-time DSL stats, WAN status, and device lists.
- **⚙️ Advanced Controls**: 
    - Rename or delete connected devices.
    - Set upload bandwidth limits.
    - Configure Parental Control rules (MAC-based filtering with schedules).
- **🌐 Network Features**:
    - **DDNS**: Configure Dynamic DNS (DynDNS, No-IP, Oray, etc.)
    - **Port Forwarding (NAT)**: Add, list, and delete port forwarding rules
    - **UPnP**: Enable/disable Universal Plug and Play
    - **Firewall**: Configure firewall with DoS protection (ICMP, SYN, ARP)
    - **MAC Filter**: Block/allow devices by MAC address
- **📶 WiFi Controls**:
    - View WiFi settings and passwords
    - Toggle WiFi on/off
- **🔄 Session Management**: Automatic heartbeat keeps your session alive while the app is running.
- **🛠️ System Actions**: Reboot the router or restart the DSL connection remotely.

---

## 🚀 Getting Started

### 1. Installation

Clone the repository and install the minimal dependencies:

```bash
git clone https://github.com/yourusername/hg630-manager.git
cd hg630-manager
pip install -r requirements.txt
```

### 2. Initial Setup

Run the setup command to securely store your router's IP, username, and password:

```bash
python advanced_router.py setup
```

---

## 📖 Usage Examples

### 🎮 Interactive Mode (Recommended)
Launch a user-friendly menu to access all features:

```bash
python advanced_router.py interactive
# OR simply
python advanced_router.py -i
```

### ⚡ Direct Commands
Perform quick actions directly from the terminal:

| Feature | Command |
|---------|---------|
| **DSL Stats** | `python advanced_router.py dsl` |
| **Device List**| `python advanced_router.py devices` |
| **WiFi Status**| `python advanced_router.py wifi-status` |
| **WiFi On/Off**| `python advanced_router.py wifi on` / `wifi off` |
| **WiFi Password** | `python advanced_router.py wifi-password` |
| **Bandwidth** | `python advanced_router.py bandwidth` |
| **DDNS** | `python advanced_router.py ddns` |
| **Port Forwarding** | `python advanced_router.py nat` |
| **UPnP** | `python advanced_router.py upnp` |
| **Firewall** | `python advanced_router.py firewall` |
| **MAC Filter** | `python advanced_router.py mac-filter` |
| **Reboot** | `python advanced_router.py reboot` |

### 🛠️ Advanced Command Examples

**Set a Bandwidth Limit:**
```bash
# Set upload limit to 500kbps
python advanced_router.py set-bandwidth --limit 500
```

**Configure Parental Control:**
```bash
# Create a rule to block specific MACs from 10 PM to 8 AM
python advanced_router.py set-parental "Night-Block" "AA:BB:CC:DD:EE:FF" --start 22:00 --end 08:00
```

**Configure DDNS:**
```bash
python advanced_router.py set-ddns --hostname myhost.ddns.net --username user --password pass --provider DynDNS
```

**Port Forwarding:**
```bash
# Add a port forward rule
python advanced_router.py add-nat "Web Server" 80 80 TCP 192.168.1.100

# Delete a rule
python advanced_router.py del-nat "rule_id_here"
```

**UPnP:**
```bash
python advanced_router.py set-upnp on
python advanced advanced_router.py set-upnp off
```

**Firewall:**
```bash
# Enable with DoS protection
python advanced_router.py set-firewall on --icmp-flood --syn-flood --arp-attack

# Disable firewall
python advanced_router.py set-firewall off
```

**MAC Filter:**
```bash
# Block a MAC address
python advanced_router.py set-mac-filter "AA:BB:CC:DD:EE:FF"

---

## 🔐 Security & Configuration

The app uses a `.env` file in the script directory to store your settings. 
- **Passwords**: Currently stored using **Base64 encoding** in the `.env` file. This is necessary because the router's authentication flow requires a dynamic hash generated from the original password and a per-session CSRF token.
- **Environment Variables**:
    - `ROUTER_IP`: IP of your router (default: `192.168.1.1`).
    - `STORED_USER`: Your router username.
    - `CRED_PASSWORD`: The base64 encoded router password.


---

## 👩‍💻 For Developers: Python Client Library

If you want to build your own tools, you can use the `HG630Router` class from `advanced_router.py`:

```python
from advanced_router import HG630Router

with HG630Router("192.168.1.1") as router:
    if router.login("admin", "your_password"):
        devices = router.get_connected_devices()
        print(f"Connected: {len(devices)} devices")
```

---

## 📜 Technical Background

This client reverse-engineers the **Huawei ATP web server** (found in `bin/cms`) and its **Lua-based API**.

- **Firmware Path**: Based on HG630 V2 firmware analysis.
- **API Model**: TR-069 / TR-098 standard (`InternetGatewayDevice`).
- **Data Format**: Handled with `while(1);` security wrappers and custom JSON parsing.

---

## 📄 References

- [HG630 API Reference](HG630_API_REFERENCE.md) - Deep dive into available endpoints.
- [Task Log](TASK.md) - History of the reverse engineering process.

---

**Author:** Wael Adel (whhw31)  
**License:** MIT

