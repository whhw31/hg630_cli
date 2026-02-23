#!/usr/bin/env python3
"""
Simple Router Login App for HG630 V2
Login and control your router programmatically
"""

import requests
import hashlib
import base64
import re
import json
import threading
import time

class HG630Router:
    def __init__(self, ip="192.168.1.1"):
        self.base_url = f"http://{ip}"
        self.session = requests.Session()
        self.csrf_param = None
        self.csrf_token = None
        self.is_logged_in = False
        self.heartbeat_thread = None
        self.stop_heartbeat = threading.Event()
        self.heartbeat_interval = 5  # seconds, from router response
    
    def _hash_password(self, password, username):
        """
        Hash password using router's algorithm:
        SHA256(username + base64(SHA256(password_as_hex)) + csrf_param + csrf_token)
        """
        # Step 1: SHA256 the password (returns hex string)
        pwd_hash_hex = hashlib.sha256(password.encode()).hexdigest()
        
        # Step 2: Base64 encode the hex string
        pwd_hash_b64 = base64.b64encode(pwd_hash_hex.encode()).decode()
        
        # Step 3: Concatenate all components
        concat_string = username + pwd_hash_b64 + self.csrf_param + self.csrf_token
        
        # Step 4: Final SHA256
        final_hash = hashlib.sha256(concat_string.encode()).hexdigest()
        
        return final_hash
    
    def _extract_csrf(self, html_content):
        """Extract CSRF tokens from HTML meta tags"""
        # Look for csrf_param
        param_match = re.search(r'<meta[^>]*name=["\']csrf_param["\'][^>]*content=["\']([^"\']+)["\']', html_content)
        token_match = re.search(r'<meta[^>]*name=["\']csrf_token["\'][^>]*content=["\']([^"\']+)["\']', html_content)
        
        # Try alternate format
        if not param_match:
            param_match = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf_param["\']', html_content)
        if not token_match:
            token_match = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']', html_content)
        
        if param_match and token_match:
            self.csrf_param = param_match.group(1)
            self.csrf_token = token_match.group(1)
            return True
        
        # Also check in script tags
        script_match = re.search(r'csrf_param["\']?\s*[:=]\s*["\']([^"\']+)', html_content)
        token_script_match = re.search(r'csrf_token["\']?\s*[:=]\s*["\']([^"\']+)', html_content)
        
        if script_match and token_script_match:
            self.csrf_param = script_match.group(1)
            self.csrf_token = token_script_match.group(1)
            return True
        
        return False
    
    def login(self, username, password):
        """
        Login to the router
        
        Returns:
            bool: True if login successful, False otherwise
        """
        print(f"\nConnecting to router at {self.base_url}...")
        
        # Step 1: Get login page to extract CSRF tokens
        try:
            response = self.session.get(self.base_url, timeout=10)
            print(f"  Status: {response.status_code}")
            
            if response.status_code != 200:
                print(f"  ✗ Failed to connect to router")
                return False
            
            # Extract CSRF tokens
            if not self._extract_csrf(response.text):
                print("  ✗ Could not extract CSRF tokens from login page")
                print("  The router might use a different login method")
                return False
            
            print(f"  ✓ CSRF Param: {self.csrf_param}")
            print(f"  ✓ CSRF Token: {self.csrf_token}")
            
        except requests.exceptions.ConnectionError:
            print("  ✗ Connection failed. Is the router at this IP address?")
            return False
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False
        
        # Step 2: Hash the password
        print("\nAuthenticating...")
        hashed_password = self._hash_password(password, username)
        
        # Step 3: Create login payload
        payload = {
            "csrf": {
                "csrf_param": self.csrf_param,
                "csrf_token": self.csrf_token
            },
            "data": {
                "UserName": username,
                "Password": hashed_password
            }
        }
        
        # Step 4: Send login request
        try:
            response = self.session.post(
                f"{self.base_url}/api/system/user_login",
                json=payload,
                headers={
                    "Content-Type": "application/json;charset=UTF-8",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": self.base_url,
                    "Referer": f"{self.base_url}/"
                },
                timeout=10
            )
            
            print(f"  Login response: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    
                    if result.get('errorCategory') == 'ok':
                        self.is_logged_in = True
                        user_level = result.get('level', 'unknown')
                        print(f"  ✓✓✓ Login successful!")
                        print(f"  User level: {user_level}")
                        # Start heartbeat to keep session alive
                        self.start_heartbeat()
                        return True
                    else:
                        error = result.get('errorCategory', 'Unknown error')
                        print(f"  ✗ Login failed: {error}")
                        return False
                        
                except json.JSONDecodeError:
                    print("  ✓ Login request sent (non-JSON response)")
                    self.is_logged_in = True
                    # Start heartbeat to keep session alive
                    self.start_heartbeat()
                    return True
            else:
                print(f"  ✗ Login failed with status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ✗ Error during login: {e}")
            return False
    
    def _parse_response(self, response):
        """Parse API response (handles while(1); wrapper)"""
        try:
            text = response.text
            # Remove while(1); wrapper if present
            if text.startswith('while(1);'):
                text = text[9:]  # Remove 'while(1);'
            if text.startswith(' /*'):
                text = text[2:]  # Remove ' /*'
            if text.endswith('*/'):
                text = text[:-2]  # Remove '*/'
            text = text.strip()
            
            if not text:
                return None
                
            return json.loads(text)
        except:
            # Try parsing as-is
            try:
                return response.json()
            except:
                return None
    
    def get_bandwidth_settings(self):
        """Get current QoS/bandwidth settings"""
        if not self.is_logged_in:
            print("Not logged in. Please login first.")
            return None
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/app/qos",
                headers={"X-Requested-With": "XMLHttpRequest"},
                timeout=10
            )
            
            print(f"  Response status: {response.status_code}")
            print(f"  Response preview: {response.text[:100]}")
            
            if response.status_code == 200:
                data = self._parse_response(response)
                return data
            else:
                print(f"  ✗ Failed to get bandwidth settings: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return None
    
    def set_bandwidth(self, enable=True, upload_kbps=250):
        """
        Set bandwidth limit
        
        Args:
            enable: True to enable bandwidth limiting
            upload_kbps: Upload bandwidth limit in KB/s
        """
        if not self.is_logged_in:
            print("Not logged in. Please login first.")
            return False
        
        # Get fresh CSRF tokens first
        try:
            print("  Getting fresh CSRF tokens...")
            response = self.session.get(f"{self.base_url}/", timeout=5)
            self._extract_csrf(response.text)
        except:
            pass
        
        payload = {
            "csrf": {
                "csrf_param": self.csrf_param,
                "csrf_token": self.csrf_token
            },
            "data": {
                "Enable": enable,
                "UpBandWidth": str(upload_kbps)
            }
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/app/qos",
                json=payload,
                headers={
                    "Content-Type": "application/json;charset=UTF-8",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": self.base_url,
                    "Referer": f"{self.base_url}/html/advance.html"
                },
                timeout=10
            )
            
            print(f"  Response status: {response.status_code}")
            print(f"  Response: {response.text[:200]}")
            
            if response.status_code == 200:
                result = self._parse_response(response)
                if result:
                    error = result.get('errorCategory', 'ok')
                    if error == 'ok':
                        print(f"  ✓ Bandwidth limit set to {upload_kbps} KB/s")
                        return True
                    else:
                        print(f"  ✗ Error: {error}")
                        return False
                else:
                    print(f"  ✓ Request sent (check router for changes)")
                    return True
            else:
                print(f"  ✗ Failed to set bandwidth: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False
    
    def get_connected_devices(self):
        """Get list of connected devices"""
        if not self.is_logged_in:
            print("Not logged in. Please login first.")
            return None
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/system/HostInfo",
                headers={"X-Requested-With": "XMLHttpRequest"},
                timeout=10
            )
            
            print(f"  Response status: {response.status_code}")
            print(f"  Response preview: {response.text[:100]}")
            
            if response.status_code == 200:
                data = self._parse_response(response)
                return data
            else:
                print(f"  ✗ Failed to get device list: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return None
    
    def _heartbeat_worker(self):
        """Background thread to send heartbeat every 5 seconds"""
        print(f"  [Heartbeat] Started (every {self.heartbeat_interval}s)")
        
        while not self.stop_heartbeat.is_set() and self.is_logged_in:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/system/heartbeat",
                    headers={"X-Requested-With": "XMLHttpRequest"},
                    timeout=5
                )
                
                if response.status_code == 200:
                    # Try to parse interval from response
                    try:
                        data = self._parse_response(response)
                        if data and 'interval' in data:
                            self.heartbeat_interval = int(data['interval']) / 1000  # Convert ms to s
                    except:
                        pass
                else:
                    print(f"  [Heartbeat] Warning: Status {response.status_code}")
                    
            except Exception as e:
                print(f"  [Heartbeat] Error: {e}")
            
            # Wait for interval or until stopped
            self.stop_heartbeat.wait(self.heartbeat_interval)
        
        print("  [Heartbeat] Stopped")
    
    def start_heartbeat(self):
        """Start the heartbeat thread to keep session alive"""
        if self.heartbeat_thread is None or not self.heartbeat_thread.is_alive():
            self.stop_heartbeat.clear()
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_worker, daemon=True)
            self.heartbeat_thread.start()
    
    def stop_heartbeat_thread(self):
        """Stop the heartbeat thread"""
        self.stop_heartbeat.set()
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)
    
    def logout(self):
        """Logout from router"""
        # Stop heartbeat first
        self.stop_heartbeat_thread()
        
        if not self.is_logged_in:
            return True
        
        try:
            self.session.get(f"{self.base_url}/api/system/logout", timeout=5)
            self.is_logged_in = False
            print("✓ Logged out successfully")
            return True
        except:
            return False


def main():
    print("=" * 60)
    print("HG630 V2 Router Login App")
    print("=" * 60)
    
    # Get credentials from user
    ip = input("\nRouter IP [192.168.1.1]: ").strip() or "192.168.1.1"
    username = input("Username [admin]: ").strip() or "admin"
    password = input("Password: ").strip()
    
    if not password:
        print("✗ Password is required!")
        return
    
    # Create router instance and login
    router = HG630Router(ip)
    
    if router.login(username, password):
        print("\n" + "=" * 60)
        print("Login successful! What would you like to do?")
        print("(Auto-heartbeat enabled - session will stay alive)")
        print("=" * 60)
        
        while True:
            print("\nOptions:")
            print("1. View bandwidth settings")
            print("2. Set bandwidth limit")
            print("3. View connected devices")
            print("4. Logout and exit")
            
            choice = input("\nChoice [1-4]: ").strip()
            
            if choice == "1":
                settings = router.get_bandwidth_settings()
                if settings:
                    print("\nBandwidth Settings:")
                    print(json.dumps(settings, indent=2))
                else:
                    print("\n  Could not parse settings (check response above)")
            
            elif choice == "2":
                try:
                    enable = input("Enable bandwidth limiting? [y/n]: ").strip().lower() == 'y'
                    kbps = int(input("Upload limit in KB/s [250]: ").strip() or "250")
                    router.set_bandwidth(enable, kbps)
                except ValueError:
                    print("✗ Invalid input")
            
            elif choice == "3":
                devices = router.get_connected_devices()
                if devices:
                    print("\nConnected Devices:")
                    print(json.dumps(devices, indent=2))
                else:
                    print("\n  Could not parse device list (check response above)")
            
            elif choice == "4":
                router.logout()
                print("\nGoodbye!")
                break
            
            else:
                print("Invalid choice")
    else:
        print("\n✗ Login failed. Please check your credentials.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting...")
