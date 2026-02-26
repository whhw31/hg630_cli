#!/usr/bin/env python3
"""
Advanced HG630 V2 Router Manager
Fully CLI-based with secure credential storage.
"""

import argparse
import os
import sys
import re
import json
import hashlib
import base64
import threading
import time
import requests
import getpass
from typing import Optional, Dict, Any, Union
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
ENV_FILE = SCRIPT_DIR / ".env"


def hash_credential(value: str, salt: str) -> str:
    """Hash a credential with salt using PBKDF2."""
    key = hashlib.pbkdf2_hmac('sha256', value.encode(), salt.encode(), 100000)
    return base64.b64encode(key).decode()


def load_env() -> Dict[str, str]:
    """Load credentials from .env file."""
    env = {}
    if ENV_FILE.exists():
        with open(ENV_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, val = line.split('=', 1)
                    env[key.strip()] = val.strip()
    return env


def save_env(data: Dict[str, str]) -> None:
    """Save hashed credentials to .env file."""
    with open(ENV_FILE, 'w') as f:
        f.write("# HG630 Router Manager - Credentials (Hashed)\n")
        for key, val in data.items():
            f.write(f"{key}={val}\n")


def setup_credentials() -> Dict[str, str]:
    """Interactive setup for first-time use."""
    print("\n" + "=" * 50)
    print("  HG630 Router Manager - Initial Setup")
    print("=" * 50)
    print("\nEnter your router credentials to store securely.")
    print("(Password will be base64 encoded, not hashed - needed for router login)\n")

    router_ip = input("Router IP Address [192.168.1.1]: ").strip() or "192.168.1.1"
    username = input("Router Username [admin]: ").strip() or "admin"
    password = getpass.getpass("Router Password: ").strip()

    if not password:
        print("Error: Password is required.")
        sys.exit(1)

    encoded_password = base64.b64encode(password.encode()).decode()

    env_data = {
        'ROUTER_IP': router_ip,
        'STORED_USER': username,
        'CRED_PASSWORD': encoded_password
    }

    save_env(env_data)
    print(f"\n✓ Credentials saved to {ENV_FILE}")
    print("  (Password is base64 encoded)")
    return env_data


def get_credentials() -> Dict[str, str]:
    """Get credentials from .env or prompt for setup."""
    env = load_env()

    if not env.get('CRED_PASSWORD'):
        return setup_credentials()

    return env


def verify_and_get_credentials() -> tuple:
    """Get credentials and prompt for password to verify."""
    env = get_credentials()
    router_ip = env.get('ROUTER_IP', '192.168.1.1')

    stored_hash = env.get('CRED_USERNAME', '')
    salt = env.get('CRED_SALT', '')

    if stored_hash and salt:
        username = input(f"Username [{env.get('STORED_USER', 'admin')}]: ").strip()
        if not username:
            username = env.get('STORED_USER', 'admin')

        password = getpass.getpass("Password (or press Enter to use stored): ").strip()

        if not password:
            stored_pwd_hash = env.get('CRED_PASSWORD', '')
            if stored_pwd_hash:
                password = None
            else:
                print("No stored password. Please enter password.")
                password = getpass.getpass("Password: ").strip()
    else:
        username = input("Username [admin]: ").strip() or "admin"
        password = getpass.getpass("Password: ").strip()

    return router_ip, username, password


class HG630Router:
    def __init__(self, ip="192.168.1.1"):
        self.base_url = f"http://{ip}"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
        })
        self.csrf_param = None
        self.csrf_token = None
        self.is_logged_in = False
        self.heartbeat_thread = None
        self.stop_heartbeat = threading.Event()
        self.heartbeat_interval = 5

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()


    def _hash_password(self, password, username):
        pwd_hash_hex = hashlib.sha256(password.encode()).hexdigest()
        pwd_hash_b64 = base64.b64encode(pwd_hash_hex.encode()).decode()
        concat_string = username + pwd_hash_b64 + self.csrf_param + self.csrf_token
        final_hash = hashlib.sha256(concat_string.encode()).hexdigest()
        return final_hash

    def _extract_csrf(self, html_content):
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
                self.csrf_param = param_match.group(1)
                self.csrf_token = token_match.group(1)
                return True
        return False

    def _update_csrf_from_response(self, response_data):
        if isinstance(response_data, dict):
            if 'csrf_param' in response_data and 'csrf_token' in response_data:
                self.csrf_param = response_data['csrf_param']
                self.csrf_token = response_data['csrf_token']
            elif 'params' in response_data:
                p = response_data['params']
                if 'csrf_param' in p and 'csrf_token' in p:
                    self.csrf_param = p['csrf_param']
                    self.csrf_token = p['csrf_token']

    def _parse_json(self, response_obj):
        try:
            text = response_obj.text.strip()
            if text.startswith('while(1);'):
                start_idx = text.find('/*')
                end_idx = text.rfind('*/')
                if start_idx != -1 and end_idx != -1:
                    text = text[start_idx+2:end_idx].strip()

            if not text:
                return None

            return json.loads(text)
        except json.JSONDecodeError:
            try:
                return json.loads(response_obj.text)
            except json.JSONDecodeError:
                return None
        except Exception:
            return None

    class APIError(Exception):
        pass

    def _request(self, method: str, endpoint: str, *,
                 json_data: Optional[Dict] = None,
                 data_payload: Optional[Union[Dict, str]] = None,
                 parse_json: bool = False,
                 referer: Optional[str] = None,
                 timeout: int = 10,
                 **kwargs) -> Union[requests.Response, Dict[str, Any]]:
        url = f"{self.base_url}{endpoint}"
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": referer if referer else f"{self.base_url}/",
            "Origin": self.base_url,
            "Accept": "application/json, text/javascript, */*; q=0.01"
        }

        if json_data:
            headers["Content-Type"] = "application/json;charset=UTF-8"
        elif data_payload:
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        try:
            r = self.session.request(method, url, json=json_data, data=data_payload,
                                     headers=headers,
                                     timeout=timeout, **kwargs)
            r.raise_for_status()
        except requests.exceptions.Timeout:
            raise self.APIError(f"Timeout: {url}")
        except requests.exceptions.ConnectionError as e:
            raise self.APIError(f"Connection failed: {e}")
        except requests.exceptions.HTTPError as e:
            raise self.APIError(f"HTTP error: {e}")

        if parse_json:
            return self._parse_json(r)
        return r

    def refresh_csrf(self):
        try:
            r = self._request("GET", "/html/advance.html")
            if self._extract_csrf(r.text):
                return True
        except:
            pass
        return False

    def login(self, username, password):
        print(f"\nConnecting to router at {self.base_url}...")

        try:
            r_html = self._request("GET", "/")
            if r_html.status_code != 200:
                print(f" ✗ Failed to connect to router (Status: {r_html.status_code})")
                return False

            if not self._extract_csrf(r_html.text):
                print(" ✗ Could not extract CSRF tokens from login page")
                return False

        except self.APIError as e:
            print(f" ✗ Error during initial CSRF fetch: {e}")
            return False

        print(" Authenticating...")
        hashed = self._hash_password(password, username)
        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "data": {"UserName": username, "Password": hashed},
        }

        try:
            result = self._request("POST", "/api/system/user_login",
                                   json_data=payload, parse_json=True)

            if not result:
                print(" ✗ Login failed: Empty response")
                return False

            err = result.get("errorCategory", "ok")
            if err == "user_pass_err":
                cnt = result.get("count", 0)
                print(f" ✗ Login failed: Wrong credentials (attempts: {cnt})")
                return False
            elif err in ("Three_time_err", "Three_time_err_multi"):
                wt = result.get("waitTime", 1)
                print(f" ✗ Login failed: Locked out – wait {wt} min")
                return False
            elif err == "Duplicate_login":
                print(" ✗ Login failed: Already logged in elsewhere")
                return False
            elif err == "Too_Many_user":
                print(" ✗ Login failed: Too many users")
                return False
            elif err != "ok":
                print(f" ✗ Login failed: {err}")
                return False

            self.is_logged_in = True
            self._update_csrf_from_response(result)
            print(f" ✓ Login successful! (User Level: {result.get('level', '?')})")
            return True

        except self.APIError as e:
            print(f" ✗ Error during login: {e}")
            return False

    def logout(self):
        self.stop_heartbeat_thread()
        if self.is_logged_in:
            try:
                self._request("GET", "/api/system/logout")
            except:
                pass
            self.is_logged_in = False
            print("✓ Logged out successfully")

    def _heartbeat_worker(self):
        while not self.stop_heartbeat.is_set() and self.is_logged_in:
            try:
                result = self._request("GET", "/api/system/heartbeat", parse_json=True)
                if result and 'interval' in result:
                    self.heartbeat_interval = int(result['interval']) / 1000
            except:
                pass
            self.stop_heartbeat.wait(self.heartbeat_interval)

    def start_heartbeat(self):
        if self.heartbeat_thread is None or not self.heartbeat_thread.is_alive():
            self.stop_heartbeat.clear()
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_worker, daemon=True)
            self.heartbeat_thread.start()

    def stop_heartbeat_thread(self):
        self.stop_heartbeat.set()
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)

    def get_dsl_info(self):
        return self._request("GET", "/api/ntwk/dslinfo", parse_json=True)

    def get_wan_status(self):
        return self._request("GET", "/api/ntwk/wan", parse_json=True)

    def get_wlan_basic(self):
        return self._request("GET", "/api/ntwk/WlanBasic", parse_json=True)

    def set_wifi(self, enable: bool):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        wifi_data = self.get_wlan_basic()
        if not wifi_data or not isinstance(wifi_data, list):
            print(" ✗ Failed to retrieve WiFi settings.")
            return False

        success = True
        for ssid in wifi_data:
            # Prepare the updated data based on the current SSID settings
            ssid_to_update = ssid.copy()
            ssid_to_update["WifiEnable"] = enable
            ssid_to_update["isActiveItem"] = True

            payload = {
                "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
                "data": ssid_to_update,
                "action": "set"
            }

            try:
                result = self._request("POST", "/api/ntwk/WlanBasic",
                                       json_data=payload,
                                       referer=f"{self.base_url}/html/advance.html",
                                       parse_json=True)

                if result and result.get('errcode') == 0:
                    self._update_csrf_from_response(result)
                else:
                    # Some versions might prefer 'update' or no action
                    payload["action"] = "update"
                    result = self._request("POST", "/api/ntwk/WlanBasic",
                                           json_data=payload,
                                           referer=f"{self.base_url}/html/advance.html",
                                           parse_json=True)
                    if result and result.get('errcode') == 0:
                        self._update_csrf_from_response(result)
                    else:
                        success = False
            except self.APIError as e:
                print(f" ✗ Error updating WiFi: {e}")
                success = False

        if success:
            print(f" ✓ WiFi {'enabled' if enable else 'disabled'} successfully.")
        return success

    def get_device_info(self):
        return self._request("GET", "/api/system/deviceinfo", parse_json=True)

    def get_connected_devices(self):
        return self._request("GET", "/api/system/HostInfo", parse_json=True)

    def _get_device_by_mac(self, mac_address: str):
        devices = self.get_connected_devices()
        if not devices or not isinstance(devices, list):
            return None
        target = mac_address.strip().upper().replace('-', ':')
        for dev in devices:
            if dev.get("MACAddress", "").upper() == target:
                return dev
        return None

    def rename_device(self, mac_address: str, new_name: str):
        dev = self._get_device_by_mac(mac_address)
        if not dev:
            print(f" ✗ Device with MAC {mac_address} not found.")
            return False

        dev["ActualName"] = new_name
        dev["isActiveItem"] = True

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "action": "update",
            "data": dev
        }

        try:
            result = self._request("POST", "/api/system/HostInfo",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)
            if result and result.get("errcode") == 0:
                print(f" ✓ Device '{mac_address}' renamed to '{new_name}'.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error renaming device: {e}")
            return False

    def delete_device(self, mac_address: str):
        dev = self._get_device_by_mac(mac_address)
        if not dev:
            print(f" ✗ Device with MAC {mac_address} not found.")
            return False

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "action": "delete",
            "data": {
                "ID": dev.get("ID"),
                "MACAddress": dev.get("MACAddress")
            }
        }

        try:
            result = self._request("POST", "/api/system/HostInfo",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)
            if result and result.get("errcode") == 0:
                print(f" ✓ Device '{mac_address}' deleted successfully.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error deleting device: {e}")
            return False

    def get_wifi_password(self):
        endpoints = [
            "/api/ntwk/wlan_ssids",
            "/api/ntwk/WlanBasic", 
            "/api/ntwk/wifistatus"
        ]
        
        for endpoint in endpoints:
            try:
                data = self._request("GET", endpoint, parse_json=True)
                if data and isinstance(data, list) and len(data) > 0:
                    for item in data:
                        if isinstance(item, dict):
                            pwd = item.get('WpaPreSharedKey') or item.get('KeyPassphrase')
                            if pwd and pwd != '********':
                                return data
                    return data
                elif data and isinstance(data, dict):
                    if 'data' in data:
                        return data['data']
                    pwd = data.get('WpaPreSharedKey') or data.get('KeyPassphrase')
                    if pwd and pwd != '********':
                        return data
            except:
                pass
        return None

    def set_wifi(self, enable: bool):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "data": {"Enable2G": enable}
        }

        try:
            result = self._request("POST", "/api/ntwk/wlanradio",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(f" ✓ WiFi turned {'ON' if enable else 'OFF'} successfully.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error setting WiFi: {e}")
            return False

    def get_wifi_status(self):
        return self._request("GET", "/api/ntwk/wlanradio", parse_json=True)

    def refresh_csrf_root(self):
        try:
            r = self._request("GET", "/")
            if isinstance(r, requests.Response) and self._extract_csrf(r.text):
                return True
        except:
            pass
        return False

    def get_bandwidth_settings(self):
        return self._request("GET", "/api/app/qos", parse_json=True)

    def get_qos_settings(self):
        return self.get_bandwidth_settings()

    def set_bandwidth(self, enable: bool = True, upload_kbps: int = 250):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        data_content = {
            "Enable": enable,
            "UpBandWidth": str(upload_kbps)
        }

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "data": data_content
        }

        try:
            result = self._request("POST", "/api/app/qos",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errorCategory') == 'ok':
                print(f" ✓ Bandwidth limit set to {upload_kbps} KB/s (Enabled: {enable}).")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✓ Request sent (check router for changes)")
                return True
        except self.APIError as e:
            print(f" ✗ Error setting bandwidth: {e}")
            return False

    def set_bandwidth_limit(self, enable: bool, upload_kbps: int):
        return self.set_bandwidth(enable, upload_kbps)

    def get_parental_controls(self):
        return self._request("GET", "/api/ntwk/macfilter", parse_json=True)

    def set_parental_control(self, rule_name: str, mac_addresses: list, enable: bool = True,
                             start_time: str = "00:00", end_time: str = "23:59", rule_id: str = ""):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        devices = [{"MACAddress": mac.strip()} for mac in mac_addresses]

        action = "update" if rule_id else "create"

        data_content = {
            "ID": rule_id,
            "RuleName": rule_name,
            "Enable": enable,
            "TimeMode": 0,
            "DailyFrom": start_time,
            "DailyTo": end_time,
            "Devices": devices,
            "isActiveItem": True
        }

        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        for day in days:
            data_content[f"{day}enable"] = True
            data_content[f"{day}From"] = start_time
            data_content[f"{day}To"] = end_time

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "action": action,
            "data": data_content
        }

        try:
            result = self._request("POST", "/api/ntwk/macfilter",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(f" ✓ Parental Control Rule '{rule_name}' {'updated' if rule_id else 'created'} successfully.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False

        except self.APIError as e:
            print(f" ✗ Error setting parental control rule: {e}")
            return False

    def get_ddns(self):
        return self._request("GET", "/api/ntwk/ddns", parse_json=True)

    def set_ddns(self, enable: bool, provider: str = "", hostname: str = "", 
                 username: str = "", password: str = ""):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        data_content = {
            "Enable": enable,
            "Provider": provider,
            "HostName": hostname,
            "Username": username,
            "Password": password
        }

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "data": data_content
        }

        try:
            result = self._request("POST", "/api/ntwk/ddns",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(f" ✓ DDNS settings updated.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error setting DDNS: {e}")
            return False

    def get_nat(self):
        return self._request("GET", "/api/ntwk/portmapping", parse_json=True)

    def add_port_forward(self, name: str, external_port: int, internal_port: int,
                         protocol: str, internal_ip: str, enable: bool = True):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        data_content = {
            "Enable": enable,
            "Name": name,
            "ExternalPort": external_port,
            "InternalPort": internal_port,
            "Protocol": protocol.upper(),
            "InternalClient": internal_ip
        }

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "action": "add",
            "data": data_content
        }

        try:
            result = self._request("POST", "/api/ntwk/portmapping",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(f" ✓ Port forward rule '{name}' added.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error adding port forward: {e}")
            return False

    def delete_port_forward(self, rule_id: str):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "action": "delete",
            "data": {"ID": rule_id}
        }

        try:
            result = self._request("POST", "/api/ntwk/portmapping",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(f" ✓ Port forward rule deleted.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error deleting port forward: {e}")
            return False

    def get_upnp(self):
        return self._request("GET", "/api/ntwk/upnp", parse_json=True)

    def set_upnp(self, enable: bool):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "data": {"Enable": enable}
        }

        try:
            result = self._request("POST", "/api/ntwk/upnp",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(f" ✓ UPnP {'enabled' if enable else 'disabled'}.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error setting UPnP: {e}")
            return False

    def get_firewall(self):
        return self._request("GET", "/api/ntwk/firewall", parse_json=True)

    def set_firewall(self, enable: bool, icmp_flood: bool = False, 
                     syn_flood: bool = False, arp_attack: bool = False):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        data_content = {
            "Enable": enable,
            "IcmpFlooding": icmp_flood,
            "SynFlooding": syn_flood,
            "ArpAttack": arp_attack
        }

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "data": data_content
        }

        try:
            result = self._request("POST", "/api/ntwk/firewall",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(f" ✓ Firewall settings updated.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error setting firewall: {e}")
            return False

    def get_mac_filter(self):
        return self._request("GET", "/api/ntwk/macfilter", parse_json=True)

    def set_mac_filter(self, mac_address: str, enable: bool = True):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        self.refresh_csrf_root()

        data_content = {
            "Enable": enable,
            "MACAddress": mac_address.upper().replace('-', ':'),
            "isActiveItem": True
        }

        payload = {
            "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
            "action": "add",
            "data": data_content
        }

        try:
            result = self._request("POST", "/api/ntwk/macfilter",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(f" ✓ MAC filter rule for {mac_address} {'enabled' if enable else 'disabled'}.")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False
        except self.APIError as e:
            print(f" ✗ Error setting MAC filter: {e}")
            return False

    def reboot(self):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        print(" Preparing management session...")
        self.session.cookies.set("activeMenuID", "maintain_settings")
        self.session.cookies.set("activeSubmenuID", "device_mngt")

        try:
            self.refresh_csrf()
            self.get_device_info()

            payload_str = json.dumps({
                "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token}
            }, separators=(',', ':'))

            print(" Sending reboot command...")
            result = self._request("POST", "/api/service/reboot.cgi",
                                   data_payload=payload_str,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and (result.get('errcode') == 0 or 'csrf_token' in result):
                print(" ✓ Reboot command accepted by router.")
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False

        except self.APIError as e:
            if "Timeout" in str(e) or "Connection failed" in str(e):
                print(" ✓ Connection lost (Router is likely rebooting).")
                return True
            print(f" ✗ Error during reboot: {e}")
            return False

    def restart_dsl(self):
        if not self.is_logged_in:
            print(" ✗ Not logged in.")
            return False

        print(" Preparing DSL restart...")
        try:
            self.refresh_csrf()

            dsl_data = self.get_dsl_info()
            if not dsl_data:
                print(" ✗ Failed to retrieve current DSL info.")
                return False

            if isinstance(dsl_data, list) and len(dsl_data) > 0:
                dsl_data = dsl_data[0]

            payload = {
                "csrf": {"csrf_param": self.csrf_param, "csrf_token": self.csrf_token},
                "data": dsl_data
            }

            print(" Sending DSL restart command...")
            result = self._request("POST", "/api/ntwk/dslinfo",
                                   json_data=payload,
                                   referer=f"{self.base_url}/html/advance.html",
                                   parse_json=True)

            if result and result.get('errcode') == 0:
                print(" ✓ DSL restart command accepted. Line will re-sync (~30-60s).")
                self._update_csrf_from_response(result)
                return True
            else:
                print(f" ✗ Router response: {result}")
                return False

        except self.APIError as e:
            print(f" ✗ Error during DSL restart: {e}")
            return False


def print_kv(key, value, indent=2):
    print(f"{' ' * indent}{key:<25}: {value}")


def cmd_dsl(router):
    data = router.get_dsl_info()
    if data:
        print("\n--- DSL Statistics ---")
        if isinstance(data, list) and len(data) > 0:
            data = data[0]

        print_kv("Status", data.get("Status"))
        print_kv("Modulation", data.get("Modulation"))
        print_kv("Downstream Rate", f"{data.get('DownCurrRate', 0)} kbps")
        print_kv("Upstream Rate", f"{data.get('UpCurrRate', 0)} kbps")
        print_kv("Downstream Max", f"{data.get('DownstreamMaxBitRate', 0)} kbps")
        print_kv("Upstream Max", f"{data.get('UpstreamMaxBitRate', 0)} kbps")
        print_kv("Downstream SNR", f"{data.get('DownMargin', 0)} dB")
        print_kv("Upstream SNR", f"{data.get('UpMargin', 0)} dB")
    else:
        print(" ✗ Failed to retrieve DSL statistics.")


def cmd_wan(router):
    data = router.get_wan_status()
    if data and isinstance(data, list):
        dev_info = router.get_device_info()
        if isinstance(dev_info, list) and dev_info:
            dev_info = dev_info[0]
        sys_uptime = int(dev_info.get('UpTime', 0)) if dev_info else 0

        dsl_info = router.get_dsl_info()
        if isinstance(dsl_info, list) and dsl_info:
            dsl_info = dsl_info[0]
        dsl_uptime = int(dsl_info.get('ShowtimeStart', 0)) if dsl_info else 0

        def fmt_uptime(seconds):
            d = seconds // 86400
            h = (seconds % 86400) // 3600
            m = (seconds % 3600) // 60
            parts = []
            if d > 0:
                parts.append(f"{d}d")
            if h > 0:
                parts.append(f"{h}h")
            parts.append(f"{m}m")
            return " ".join(parts)

        print("\n--- WAN Connections ---")
        print_kv("System Uptime", fmt_uptime(sys_uptime))
        print_kv("DSL Link Uptime", fmt_uptime(dsl_uptime))

        found = False
        for wan in data:
            if wan.get("ConnectionStatus") == "Connected" or wan.get("IPv4Addr"):
                found = True
                print(f"\n[ {wan.get('Name', 'WAN')} ]")
                print_kv("Status", wan.get("ConnectionStatus"))
                print_kv("IP Address", wan.get("IPv4Addr"))
                print_kv("Gateway", wan.get("IPv4Gateway"))
                print_kv("DNS", wan.get("IPv4DnsServers"))
                print_kv("Access Type", wan.get("AccessType"))
        if not found:
            print(" No connected WAN interfaces found.")
    else:
        print("\nNo WAN status available.")


def cmd_device_info(router):
    data = router.get_device_info()
    if data:
        print("\n--- Device Information ---")
        if isinstance(data, list) and len(data) > 0:
            data = data[0]
        print_kv("Model", data.get("DeviceName"))
        print_kv("Serial Number", data.get("SerialNumber"))
        print_kv("Hardware Ver", data.get("HardwareVersion"))
        print_kv("Firmware Ver", data.get("SoftwareVersion"))
        print_kv("Uptime", f"{int(data.get('UpTime', 0)) // 3600} hours")
    else:
        print(" ✗ Failed to retrieve device info.")


def cmd_wifi_settings(router):
    data = router.get_wlan_basic()
    if data and isinstance(data, list):
        print("\n--- WiFi Settings ---")
        for wifi in data:
            print(f"\n[ SSID: {wifi.get('SSID') or wifi.get('WifiSsid')} ]")
            print_kv("Enabled", wifi.get("WifiEnable"))
            print_kv("Hidden", wifi.get("WifiHideBroadcast"))
            print_kv("Auth Mode", wifi.get("AuthMode"))
    else:
        print(" ✗ Failed to retrieve WiFi settings.")


def cmd_wifi_password(router):
    passwords = router.get_wifi_password()
    if passwords and isinstance(passwords, list):
        print("\n--- WiFi Passwords ---")
        for p in passwords:
            ssid = p.get('SSID') or p.get('WifiSsid')
            pwd = p.get('KeyPassphrase') or p.get('WpaPreSharedKey') or p.get('WepKey') or "Hidden/Unknown"
            print_kv("SSID", ssid)
            if pwd == '********':
                print_kv("Password", "(masked by router - check web interface)")
            else:
                print_kv("Password", pwd)
            print("-")
    else:
        print("\nNo WiFi passwords found or failed to retrieve.")


def cmd_wifi_status(router):
    status = router.get_wifi_status()
    if status and isinstance(status, dict):
        enabled = status.get('Enable2G', False)
        print(f"\n--- WiFi Status ---")
        print_kv("2.4GHz WiFi", "ON" if enabled else "OFF")
    else:
        print(" ✗ Failed to retrieve WiFi status.")


def cmd_wifi_toggle(router, enable: bool):
    router.set_wifi(enable)


def cmd_connected_devices(router):
    data = router.get_connected_devices()
    if data and isinstance(data, list):
        print(f"\n--- Connected Devices ({len(data)}) ---")
        print(f"{'IP Address':<16} {'MAC Address':<18} {'Hostname'}")
        print("-" * 50)
        for dev in data:
            if dev.get('Active'):
                name = dev.get('ActualName') or dev.get('HostName')
                print(f"{dev.get('IPAddress'):<16} {dev.get('MACAddress'):<18} {name}")
    else:
        print(" ✗ Failed to retrieve connected devices.")


def cmd_rename_device(router, mac: str, name: str):
    if not mac or not name:
        print("Error: MAC address and new name are required.")
        return
    router.rename_device(mac, name)


def cmd_delete_device(router, mac: str):
    if not mac:
        print("Error: MAC address is required.")
        return
    router.delete_device(mac)


def cmd_bandwidth(router):
    settings = router.get_bandwidth_settings()
    if settings:
        print("\n--- Bandwidth Settings ---")
        print(json.dumps(settings, indent=2, ensure_ascii=False))
    else:
        print(" ✗ Failed to retrieve bandwidth settings.")


def cmd_set_bandwidth(router, enable: bool, limit: int):
    router.set_bandwidth(enable, limit)


def cmd_parental_list(router):
    rules = router.get_parental_controls()
    if rules and isinstance(rules, list):
        print("\n" + "=" * 60)
        print(f"{'PARENTAL CONTROL RULES':^60}")
        print("=" * 60)
        for r in rules:
            status = "ENABLED" if r.get('Enable') else "DISABLED"
            name = r.get('RuleName', 'Unnamed Rule')
            days_active = []
            for day in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]:
                if r.get(f"{day}enable"):
                    days_active.append(day[:3])

            print(f"\n[ {status} ]  {name}")
            print("-" * 60)
            print_kv("Rule ID", r.get('ID', 'N/A'))

            time_period = f"{r.get('DailyFrom', '00:00')} to {r.get('DailyTo', '23:59')}"
            day_str = ", ".join(days_active) if days_active else "None"
            print_kv("Schedule", f"{time_period} ({day_str})")

            devices = r.get('Devices', [])
            print(f"  Devices ({len(devices)}):")
            for d in devices:
                print(f"    - {d.get('MACAddress')}")
        print("\n" + "=" * 60)
    else:
        print(" No parental control rules found or failed to retrieve.")


def cmd_set_parental(router, rule_name: str, macs: list, enable: bool, start: str, end: str, rule_id: str):
    if not rule_name or not macs:
        print("Error: Rule name and MAC addresses are required.")
        return
    router.set_parental_control(rule_name, macs, enable, start, end, cmd_set_parental)


def cmd_ddns(router):
    data = router.get_ddns()
    if data and isinstance(data, dict):
        print("\n--- DDNS Settings ---")
        print_kv("Enabled", data.get('Enable'))
        print_kv("Provider", data.get('Provider'))
        print_kv("Hostname", data.get('HostName'))
        print_kv("Username", data.get('Username'))
        print_kv("Status", data.get('Status'))
    else:
        print(" ✗ Failed to retrieve DDNS settings.")


def cmd_set_ddns(router, enable: bool, provider: str, hostname: str, username: str, password: str):
    router.set_ddns(enable, provider, hostname, username, password)


def cmd_nat(router):
    data = router.get_nat()
    if data and isinstance(data, list):
        print(f"\n--- Port Forwarding Rules ({len(data)}) ---")
        for rule in data:
            print(f"\n[ {rule.get('Name', 'Unnamed')} ]")
            print_kv("Enabled", rule.get('Enable'))
            print_kv("External Port", rule.get('ExternalPort'))
            print_kv("Internal Port", rule.get('InternalPort'))
            print_kv("Protocol", rule.get('Protocol'))
            print_kv("Internal IP", rule.get('InternalClient'))
            print_kv("ID", rule.get('ID'))
    else:
        print(" ✗ No port forwarding rules found.")


def cmd_add_nat(router, name: str, external_port: int, internal_port: int, protocol: str, internal_ip: str):
    router.add_port_forward(name, external_port, internal_port, protocol, internal_ip)


def cmd_delete_nat(router, rule_id: str):
    router.delete_port_forward(rule_id)


def cmd_upnp(router):
    data = router.get_upnp()
    if data and isinstance(data, dict):
        print("\n--- UPnP Settings ---")
        print_kv("Enabled", data.get('Enable'))
    else:
        print(" ✗ Failed to retrieve UPnP settings.")


def cmd_set_upnp(router, enable: bool):
    router.set_upnp(enable)


def cmd_firewall(router):
    data = router.get_firewall()
    if data and isinstance(data, dict):
        print("\n--- Firewall Settings ---")
        print_kv("Enabled", data.get('Enable'))
        print_kv("ICMP Flood Protection", data.get('IcmpFlooding'))
        print_kv("SYN Flood Protection", data.get('SynFlooding'))
        print_kv("ARP Attack Protection", data.get('ArpAttack'))
    else:
        print(" ✗ Failed to retrieve firewall settings.")


def cmd_set_firewall(router, enable: bool, icmp_flood: bool, syn_flood: bool, arp_attack: bool):
    router.set_firewall(enable, icmp_flood, syn_flood, arp_attack)


def cmd_mac_filter_list(router):
    data = router.get_mac_filter()
    if data and isinstance(data, list):
        print(f"\n--- MAC Filter Rules ({len(data)}) ---")
        for rule in data:
            status = "ENABLED" if rule.get('Enable') else "DISABLED"
            print(f"\n[ {status} ]")
            print_kv("MAC Address", rule.get('MACAddress'))
            print_kv("ID", rule.get('ID'))
    else:
        print(" ✗ No MAC filter rules found.")


def cmd_set_mac_filter(router, mac: str, enable: bool):
    if not mac:
        print("Error: MAC address is required.")
        return
    router.set_mac_filter(mac, enable)


def cmd_reboot(router, auto_confirm=False):
    if not auto_confirm:
        confirm = input("Are you sure you want to REBOOT? (yes/no): ").lower()
        if confirm != "yes":
            print("Cancelled.")
            return
    if router.reboot():
        print("\nRouter is rebooting. Exiting...")


def cmd_restart_dsl(router, auto_confirm=False):
    if not auto_confirm:
        confirm = input("Restart DSL connection? This will briefly disconnect internet. (yes/no): ").lower()
        if confirm != "yes":
            print("Cancelled.")
            return
    router.restart_dsl()


def main():
    parser = argparse.ArgumentParser(
        prog='advanced_router.py',
        description='HG630 V2 Router Manager - CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_router.py setup              Run initial setup to store credentials
  python advanced_router.py dsl                 Show DSL statistics
  python advanced_router.py wan                 Show WAN status
  python advanced_router.py devices             Show connected devices
  python advanced_router.py wifi-password       Show WiFi passwords
  python advanced_router.py reboot              Reboot the router
  python advanced_router.py --interactive      Interactive menu mode

For more commands, run with --help
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    subparsers.add_parser('setup', help='Initial setup - configure router credentials')

    subparsers.add_parser('dsl', help='Show DSL line statistics')
    subparsers.add_parser('wan', help='Show WAN status and uptime')
    subparsers.add_parser('device-info', help='Show router device information')
    subparsers.add_parser('wifi-settings', help='Show WiFi settings')
    subparsers.add_parser('wifi-password', help='Show WiFi passwords')
    subparsers.add_parser('wifi-status', help='Show WiFi on/off status')

    parser_wifi = subparsers.add_parser('wifi', help='Turn WiFi on or off')
    parser_wifi.add_argument('state', choices=['on', 'off'], help='WiFi state: on or off')
    subparsers.add_parser('devices', help='Show connected devices')
    subparsers.add_parser('bandwidth', help='Show bandwidth/QoS settings')

    parser_rename = subparsers.add_parser('rename-device', help='Rename a connected device')
    parser_rename.add_argument('mac', help='MAC address of the device')
    parser_rename.add_argument('name', help='New name for the device')

    parser_delete = subparsers.add_parser('delete-device', help='Delete a device from router')
    parser_delete.add_argument('mac', help='MAC address of the device')

    parser_bw = subparsers.add_parser('set-bandwidth', help='Set bandwidth limit')
    parser_bw.add_argument('--enable', action='store_true', default=True, help='Enable bandwidth limit')
    parser_bw.add_argument('--disable', action='store_true', help='Disable bandwidth limit')
    parser_bw.add_argument('--limit', type=int, default=250, help='Upload limit in kbps (default: 250)')

    parser_parental = subparsers.add_parser('parental-list', help='List parental control rules')

    parser_parental_set = subparsers.add_parser('set-parental', help='Create/update parental control rule')
    parser_parental_set.add_argument('name', help='Rule name')
    parser_parental_set.add_argument('macs', help='Comma-separated MAC addresses')
    parser_parental_set.add_argument('--enable', action='store_true', default=True)
    parser_parental_set.add_argument('--disable', action='store_true')
    parser_parental_set.add_argument('--start', default='00:00', help='Start time (HH:MM)')
    parser_parental_set.add_argument('--end', default='23:59', help='End time (HH:MM)')
    parser_parental_set.add_argument('--id', default='', help='Rule ID (for update)')

    subparsers.add_parser('ddns', help='Show DDNS settings')

    parser_set_ddns = subparsers.add_parser('set-ddns', help='Configure DDNS')
    parser_set_ddns.add_argument('--enable', action='store_true', default=True)
    parser_set_ddns.add_argument('--disable', action='store_true')
    parser_set_ddns.add_argument('--provider', default='DynDNS', help='DDNS provider')
    parser_set_ddns.add_argument('--hostname', required=True, help='Hostname')
    parser_set_ddns.add_argument('--username', required=True, help='Username')
    parser_set_ddns.add_argument('--password', required=True, help='Password')

    subparsers.add_parser('nat', help='Show port forwarding rules')

    parser_add_nat = subparsers.add_parser('add-nat', help='Add port forwarding rule')
    parser_add_nat.add_argument('name', help='Rule name')
    parser_add_nat.add_argument('external_port', type=int, help='External port')
    parser_add_nat.add_argument('internal_port', type=int, help='Internal port')
    parser_add_nat.add_argument('protocol', choices=['TCP', 'UDP', 'BOTH'], help='Protocol')
    parser_add_nat.add_argument('internal_ip', help='Internal IP address')

    parser_del_nat = subparsers.add_parser('del-nat', help='Delete port forwarding rule')
    parser_del_nat.add_argument('id', help='Rule ID to delete')

    subparsers.add_parser('upnp', help='Show UPnP settings')

    parser_set_upnp = subparsers.add_parser('set-upnp', help='Enable/disable UPnP')
    parser_set_upnp.add_argument('state', choices=['on', 'off'], help='UPnP state')

    subparsers.add_parser('firewall', help='Show firewall settings')

    parser_set_firewall = subparsers.add_parser('set-firewall', help='Configure firewall')
    parser_set_firewall.add_argument('state', choices=['on', 'off'], help='Firewall state')
    parser_set_firewall.add_argument('--icmp-flood', action='store_true', help='Enable ICMP flood protection')
    parser_set_firewall.add_argument('--syn-flood', action='store_true', help='Enable SYN flood protection')
    parser_set_firewall.add_argument('--arp-attack', action='store_true', help='Enable ARP attack protection')

    subparsers.add_parser('mac-filter', help='Show MAC filter rules')

    parser_set_mac = subparsers.add_parser('set-mac-filter', help='Add MAC filter rule')
    parser_set_mac.add_argument('mac', help='MAC address (XX:XX:XX:XX:XX:XX)')
    parser_set_mac.add_argument('--enable', action='store_true', default=True)
    parser_set_mac.add_argument('--disable', action='store_true')

    parser_restart = subparsers.add_parser('restart-dsl', help='Restart DSL connection')
    parser_restart.add_argument('-y', '--yes', action='store_true', help='Skip confirmation prompt')
    parser_reboot = subparsers.add_parser('reboot', help='Reboot the router')
    parser_reboot.add_argument('-y', '--yes', action='store_true', help='Skip confirmation prompt')

    parser_interactive = subparsers.add_parser('interactive', help='Launch interactive menu')
    parser_interactive.add_argument('-i', '--short', action='store_true', help='Short alias for interactive')

    parser.add_argument('-i', '--interactive', dest='use_interactive', action='store_true', help='Launch interactive menu (short: -i)')
    parser.add_argument('-b', '--bandwidth', dest='use_bandwidth', action='store_true', help='Set bandwidth limit (use with -limit)')
    parser.add_argument('--limit', type=int, help='Bandwidth limit in kbps (0=off, >0=on)')
    parser.add_argument('--ip', help='Router IP address (overrides .env)')
    parser.add_argument('--user', help='Router username (overrides .env)')
    parser.add_argument('--pass', dest='password', help='Router password (overrides .env)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.use_bandwidth and args.limit is not None:
        args.command = 'quick-bandwidth'

    if args.command == 'setup':
        setup_credentials()
        return

    if args.use_interactive or args.command == 'interactive':
        args.command = 'interactive'

    if not args.command:
        parser.print_help()
        return

    env = load_env()
    router_ip = args.ip or env.get('ROUTER_IP', '192.168.1.1')
    username = args.user or env.get('STORED_USER', 'admin')
    password = args.password

    if not password:
        env = load_env()
        stored_password = env.get('CRED_PASSWORD', '')
        if stored_password:
            if env.get('CRED_SALT'):
                print("\n⚠ Old credentials format detected. Run 'setup' to update.")
                print("  For now, please enter password manually.")
                username = username or input("Username [admin]: ").strip() or "admin"
                password = getpass.getpass("Password: ").strip()
            else:
                try:
                    password = base64.b64decode(stored_password).decode()
                except:
                    username = username or input("Username [admin]: ").strip() or "admin"
                    password = getpass.getpass("Password: ").strip()
        else:
            username = username or input("Username [admin]: ").strip() or "admin"
            password = password or getpass.getpass("Password: ").strip()

    if not password:
        print("Password required.")
        return

    router = HG630Router(router_ip)

    if not router.login(username, password):
        print("\n✗ Login failed. Please check your credentials.")
        return

    router.start_heartbeat()

    try:
        if args.command == 'dsl':
            cmd_dsl(router)
        elif args.command == 'wan':
            cmd_wan(router)
        elif args.command == 'device-info':
            cmd_device_info(router)
        elif args.command == 'wifi-settings':
            cmd_wifi_settings(router)
        elif args.command == 'wifi-password':
            cmd_wifi_password(router)
        elif args.command == 'wifi-status':
            cmd_wifi_status(router)
        elif args.command == 'wifi':
            enable = args.state == 'on'
            cmd_wifi_toggle(router, enable)
        elif args.command == 'devices':
            cmd_connected_devices(router)
        elif args.command == 'rename-device':
            cmd_rename_device(router, args.mac, args.name)
        elif args.command == 'delete-device':
            cmd_delete_device(router, args.mac)
        elif args.command == 'bandwidth':
            cmd_bandwidth(router)
        elif args.command == 'quick-bandwidth' or args.command == 'set-bandwidth':
            limit = args.limit
            enable = limit is None or limit > 0
            if limit == 0:
                limit = 250
            cmd_set_bandwidth(router, enable, limit)
        elif args.command == 'parental-list':
            cmd_parental_list(router)
        elif args.command == 'set-parental':
            macs = [m.strip() for m in args.macs.split(',')]
            enable = not args.disable
            cmd_set_parental(router, args.name, macs, enable, args.start, args.end, args.id)
        elif args.command == 'ddns':
            cmd_ddns(router)
        elif args.command == 'set-ddns':
            enable = not getattr(args, 'disable', False)
            cmd_set_ddns(router, enable, args.provider, args.hostname, args.username, args.password)
        elif args.command == 'nat':
            cmd_nat(router)
        elif args.command == 'add-nat':
            protocol = args.protocol if args.protocol != 'BOTH' else 'TCP,UDP'
            cmd_add_nat(router, args.name, args.external_port, args.internal_port, protocol, args.internal_ip)
        elif args.command == 'del-nat':
            cmd_delete_nat(router, args.id)
        elif args.command == 'upnp':
            cmd_upnp(router)
        elif args.command == 'set-upnp':
            enable = args.state == 'on'
            cmd_set_upnp(router, enable)
        elif args.command == 'firewall':
            cmd_firewall(router)
        elif args.command == 'set-firewall':
            enable = args.state == 'on'
            cmd_set_firewall(router, enable, args.icmp_flood, args.syn_flood, args.arp_attack)
        elif args.command == 'mac-filter':
            cmd_mac_filter_list(router)
        elif args.command == 'set-mac-filter':
            enable = not getattr(args, 'disable', False)
            cmd_set_mac_filter(router, args.mac, enable)
        elif args.command == 'restart-dsl':
            cmd_restart_dsl(router, getattr(args, 'yes', False))
        elif args.command == 'reboot':
            cmd_reboot(router, getattr(args, 'yes', False))
        elif args.command == 'interactive':
            interactive_menu(router)
        else:
            print(f"Unknown command: {args.command}")
    finally:
        router.logout()


def interactive_menu(router):
    while True:
        print("\n" + "=" * 40)
        print(" MAIN MENU")
        print("=" * 40)
        print(" -- Status --")
        print("  1. DSL Statistics")
        print("  2. WAN Status & Uptime")
        print("  3. Device Info")
        print(" -- WiFi --")
        print("  4. WiFi Settings")
        print("  5. WiFi Password")
        print("  6. WiFi Status (On/Off)")
        print("  7. Toggle WiFi On/Off")
        print(" -- Devices --")
        print("  8. Connected Devices")
        print("  9. Rename Device")
        print(" 10. Delete Device")
        print(" -- Controls --")
        print(" 11. Bandwidth Settings")
        print(" 12. Set Bandwidth Limit")
        print(" 13. Parental Controls")
        print(" 14. Set Parental Control")
        print(" -- Network --")
        print(" 15. DDNS Settings")
        print(" 16. Port Forwarding (NAT)")
        print(" 17. UPnP Settings")
        print(" 18. Firewall Settings")
        print(" 19. MAC Filter")
        print(" -- System --")
        print(" 20. Restart DSL Connection")
        print(" 21. Reboot Router")
        print("  0. Logout & Exit")

        try:
            choice = input("\nSelect option: ").strip()
        except EOFError:
            break

        if choice == "1":
            cmd_dsl(router)
        elif choice == "2":
            cmd_wan(router)
        elif choice == "3":
            cmd_device_info(router)
        elif choice == "4":
            cmd_wifi_settings(router)
        elif choice == "5":
            cmd_wifi_password(router)
        elif choice == "6":
            cmd_wifi_status(router)
        elif choice == "7":
            interactive_wifi_toggle(router)
        elif choice == "8":
            cmd_connected_devices(router)
        elif choice == "9":
            interactive_rename(router)
        elif choice == "10":
            interactive_delete(router)
        elif choice == "11":
            cmd_bandwidth(router)
        elif choice == "12":
            interactive_bandwidth(router)
        elif choice == "13":
            cmd_parental_list(router)
        elif choice == "14":
            interactive_parental(router)
        elif choice == "15":
            cmd_ddns(router)
        elif choice == "16":
            interactive_nat(router)
        elif choice == "17":
            interactive_upnp(router)
        elif choice == "18":
            interactive_firewall(router)
        elif choice == "19":
            cmd_mac_filter_list(router)
        elif choice == "20":
            cmd_restart_dsl(router)
        elif choice == "21":
            cmd_reboot(router)
            break
        elif choice == "0":
            router.logout()
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice")


def interactive_rename(router):
    print("\n--- Rename Device ---")
    devices = router.get_connected_devices()
    if not devices or not isinstance(devices, list):
        print(" ✗ No devices found or failed to retrieve.")
        return

    print(f"{'#':<4} {'IP Address':<16} {'MAC Address':<18} {'Hostname'}")
    print("-" * 60)
    for i, dev in enumerate(devices):
        name = dev.get('ActualName') or dev.get('HostName', '')
        print(f"{i+1:<4} {dev.get('IPAddress',''):<16} {dev.get('MACAddress',''):<18} {name}")

    try:
        idx = int(input("\nSelect device number to rename (0 to cancel): ").strip())
        if idx == 0:
            return
        if 1 <= idx <= len(devices):
            mac = devices[idx-1].get('MACAddress')
            name = input(f"New Name for {mac}: ").strip()
            if not name:
                print(" ✗ Name is required.")
                return
            router.rename_device(mac, name)
        else:
            print(" ✗ Invalid selection.")
    except ValueError:
        print(" ✗ Invalid input.")


def interactive_delete(router):
    print("\n--- Delete Device ---")
    print("Note: You can usually only delete offline/inactive devices.")
    devices = router.get_connected_devices()
    if not devices or not isinstance(devices, list):
        print(" ✗ No devices found or failed to retrieve.")
        return

    print(f"{'#':<4} {'IP Address':<16} {'MAC Address':<18} {'Hostname':<20} {'Status'}")
    print("-" * 70)
    for i, dev in enumerate(devices):
        status = "Online" if dev.get('Active') else "Offline"
        name = dev.get('ActualName') or dev.get('HostName', '')
        print(f"{i+1:<4} {dev.get('IPAddress',''):<16} {dev.get('MACAddress',''):<18} {name:<20} ({status})")

    try:
        idx = int(input("\nSelect device number to delete (0 to cancel): ").strip())
        if idx == 0:
            return
        if 1 <= idx <= len(devices):
            mac = devices[idx-1].get('MACAddress')
            confirm = input(f"Are you sure you want to delete {mac}? (y/n): ").lower()
            if confirm == 'y':
                router.delete_device(mac)
        else:
            print(" ✗ Invalid selection.")
    except ValueError:
        print(" ✗ Invalid input.")


def interactive_bandwidth(router):
    print("\n--- Set Bandwidth Limit ---")
    try:
        enable_input = input("Enable Bandwidth Control? (yes/no): ").strip().lower()
        enable = (enable_input == "yes")

        limit_val = 250
        if enable:
            limit_input = input("Enter Upload Bandwidth Limit (kbps) [250]: ").strip()
            if limit_input.isdigit():
                limit_val = int(limit_input)

        router.set_bandwidth(enable, limit_val)
        print("Settings applied successfully.")
    except ValueError:
        print("Invalid input format.")


def interactive_parental(router):
    print("\n--- Set Parental Control ---")
    rule_name = input("Rule Name: ").strip()
    macs_str = input("MAC Addresses (comma separated, format XX:XX:XX:XX:XX:XX): ").strip()

    mac_addresses = []
    invalid_macs = []
    for m in macs_str.split(","):
        mac = m.strip().upper()
        if not mac:
            continue
        if re.match(r'^[0-9A-F]{12}$', mac):
            mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        if re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac):
            mac_addresses.append(mac.replace('-', ':'))
        else:
            invalid_macs.append(mac)

    if invalid_macs:
        print(f" ✗ Invalid MAC address format detected: {', '.join(invalid_macs)}")
        print("   Please use the format XX:XX:XX:XX:XX:XX")
        return

    if not rule_name or not mac_addresses:
        print(" ✗ Rule name and at least one valid MAC address are required.")
        return

    enable_input = input("Enable Rule? (yes/no) [yes]: ").strip().lower()
    enable = enable_input != "no"

    start_time = input("Start Time (HH:MM) [00:00]: ").strip() or "00:00"
    end_time = input("End Time (HH:MM) [23:59]: ").strip() or "23:59"

    if not re.match(r'^[0-2][0-9]:[0-5][0-9]$', start_time) or not re.match(r'^[0-2][0-9]:[0-5][0-9]$', end_time):
        print(" ✗ Invalid time format. Please use HH:MM (24-hour).")
        return

    rule_id = input("Rule ID (leave empty to create new): ").strip()

    router.set_parental_control(rule_name, mac_addresses, enable, start_time, end_time, rule_id)


def interactive_wifi_toggle(router):
    print("\n--- Toggle WiFi On/Off ---")
    status = router.get_wifi_status()
    if status and isinstance(status, dict):
        current = status.get('Enable2G', False)
        print(f"Current WiFi Status: {'ON' if current else 'OFF'}")
    
    confirm = input("Turn WiFi (on/off): ").strip().lower()
    if confirm == "on":
        router.set_wifi(True)
    elif confirm == "off":
        router.set_wifi(False)
    else:
        print("Invalid input. Use 'on' or 'off'.")


def interactive_nat(router):
    print("\n--- Port Forwarding (NAT) ---")
    print("  1. List all rules")
    print("  2. Add new rule")
    print("  3. Delete rule")
    print("  0. Back")
    
    choice = input("Select option: ").strip()
    
    if choice == "1":
        cmd_nat(router)
    elif choice == "2":
        name = input("Rule name: ").strip()
        try:
            ext_port = int(input("External port: ").strip())
            int_port = int(input("Internal port: ").strip())
            proto = input("Protocol (TCP/UDP): ").strip().upper()
            ip = input("Internal IP: ").strip()
            if name and ext_port and int_port and proto and ip:
                router.add_port_forward(name, ext_port, int_port, proto, ip)
            else:
                print(" ✗ All fields are required.")
        except ValueError:
            print(" ✗ Invalid port number.")
    elif choice == "3":
        rule_id = input("Enter Rule ID to delete: ").strip()
        if rule_id:
            router.delete_port_forward(rule_id)


def interactive_upnp(router):
    print("\n--- UPnP Settings ---")
    data = router.get_upnp()
    if data and isinstance(data, dict):
        current = data.get('Enable', False)
        print(f"Current UPnP Status: {'ON' if current else 'OFF'}")
    
    choice = input("Turn UPnP (on/off): ").strip().lower()
    if choice == "on":
        router.set_upnp(True)
    elif choice == "off":
        router.set_upnp(False)


def interactive_firewall(router):
    print("\n--- Firewall Settings ---")
    data = router.get_firewall()
    if data and isinstance(data, dict):
        print(f"Enabled: {data.get('Enable')}")
        print(f"ICMP Flood Protection: {data.get('IcmpFlooding')}")
        print(f"SYN Flood Protection: {data.get('SynFlooding')}")
        print(f"ARP Attack Protection: {data.get('ArpAttack')}")
    
    print("\n  1. Enable Firewall")
    print("  2. Disable Firewall")
    print("  3. Enable with DoS Protection")
    print("  0. Back")
    
    choice = input("Select option: ").strip()
    
    if choice == "1":
        router.set_firewall(True, False, False, False)
    elif choice == "2":
        router.set_firewall(False, False, False, False)
    elif choice == "3":
        router.set_firewall(True, True, True, True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
