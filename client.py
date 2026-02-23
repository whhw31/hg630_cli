"""
Huawei HG630 VDSL Router API Client

A Python client for interacting with the Huawei HG630 router's web API.
Based on reverse-engineered firmware analysis and traffic captures.
"""

import hashlib
import re
import json
import base64
import time
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass
from enum import IntEnum

import requests


class UserLevel(IntEnum):
    """User permission levels for the router."""
    NOT_LOGGED_IN = 0
    USER = 1
    ADMIN = 2
    SUPPORT = 4


class LoginError(Exception):
    """Raised when login fails."""
    pass


class APIError(Exception):
    """Raised when an API call fails."""
    pass


@dataclass
class CSRFToken:
    param: str
    token: str

    def to_dict(self) -> Dict[str, str]:
        return {"csrf_param": self.param, "csrf_token": self.token}


@dataclass
class LoginResult:
    level: UserLevel
    is_first_login: bool
    is_wizard: bool
    csrf: CSRFToken


class HG630Client:
    def __init__(self, router_ip: str = "192.168.1.1", timeout: int = 30):
        self.base_url = f"http://{router_ip}"
        self.timeout = timeout
        self.session = requests.Session()
        self.csrf: Optional[CSRFToken] = None
        self.user_level: UserLevel = UserLevel.NOT_LOGGED_IN

    # ── password hashing ────────────────────────────────────────────
    def _hash_password(self, password: str, username: str,
                       csrf_param: str, csrf_token: str) -> str:
        """SHA256(username + base64(SHA256(password)) + csrf_param + csrf_token)"""
        pwd_sha = hashlib.sha256(password.encode()).hexdigest()
        pwd_b64 = base64.b64encode(pwd_sha.encode()).decode()
        combined = username + pwd_b64 + csrf_param + csrf_token
        return hashlib.sha256(combined.encode()).hexdigest()

    # ── CSRF helpers ────────────────────────────────────────────────
    def _csrf_from_html(self, html: str) -> CSRFToken:
        for pp, tp in [
            (r'csrf_param\s*[=:]\s*["\']([^"\']+)["\']',
             r'csrf_token\s*[=:]\s*["\']([^"\']+)["\']'),
            (r'"csrf_param"\s*:\s*"([^"]+)"',
             r'"csrf_token"\s*:\s*"([^"]+)"'),
        ]:
            pm = re.search(pp, html)
            tm = re.search(tp, html)
            if pm and tm:
                return CSRFToken(param=pm.group(1), token=tm.group(1))
        raise APIError("Could not extract CSRF tokens from HTML")

    def _csrf_from_json(self, data: Dict[str, Any]) -> CSRFToken:
        p, t = data.get("csrf_param"), data.get("csrf_token")
        if not p or not t:
            raise APIError("CSRF tokens missing from JSON response")
        return CSRFToken(param=p, token=t)

    # ── JSON parser (handles both wrapped and raw) ──────────────────
    @staticmethod
    def _parse_json(text: str) -> Dict[str, Any]:
        """Parse JSON that may or may not be wrapped in while(1);/*…*/"""
        t = text.strip()
        # Try unwrapping first
        if t.startswith("while(1); /*") and t.endswith("*/"):
            t = t[len("while(1); /*"):-len("*/")]
        return json.loads(t)

    # ── HTTP layer ──────────────────────────────────────────────────
    def _request(self, method: str, endpoint: str, *,
                 json_data: Optional[Dict] = None,
                 parse_json: bool = False,
                 **kwargs) -> Union[requests.Response, Dict[str, Any]]:
        url = f"{self.base_url}{endpoint}"
        try:
            r = self.session.request(method, url, json=json_data,
                                     timeout=self.timeout, **kwargs)
            r.raise_for_status()
        except requests.exceptions.Timeout:
            raise APIError(f"Timeout: {url}")
        except requests.exceptions.ConnectionError as e:
            raise APIError(f"Connection failed: {e}")
        except requests.exceptions.HTTPError as e:
            raise APIError(f"HTTP error: {e}")

        if parse_json:
            try:
                return self._parse_json(r.text)
            except json.JSONDecodeError as e:
                raise APIError(f"Bad JSON from {endpoint}: {e}\nRaw: {r.text[:200]}")
        return r

    # ── public API ──────────────────────────────────────────────────
    def get_initial_csrf(self) -> CSRFToken:
        r = self._request("GET", "/")
        self.csrf = self._csrf_from_html(r.text)
        return self.csrf

    def login(self, username: str, password: str) -> LoginResult:
        if self.csrf is None:
            self.get_initial_csrf()

        hashed = self._hash_password(password, username,
                                     self.csrf.param, self.csrf.token)
        payload = {
            "csrf": {"csrf_param": self.csrf.param,
                     "csrf_token": self.csrf.token},
            "data": {"UserName": username, "Password": hashed},
        }
        result = self._request("POST", "/api/system/user_login",
                               json_data=payload, parse_json=True)

        err = result.get("errorCategory", "ok")
        if err == "user_pass_err":
            cnt = result.get("count", 0)
            raise LoginError(f"Wrong credentials (attempts: {cnt})")
        elif err in ("Three_time_err", "Three_time_err_multi"):
            wt = result.get("waitTime", 1)
            raise LoginError(f"Locked out – wait {wt} min")
        elif err == "Duplicate_login":
            raise LoginError("Already logged in elsewhere")
        elif err == "Too_Many_user":
            raise LoginError("Too many users")
        elif err != "ok":
            raise LoginError(f"Login failed: {err}")

        self.user_level = UserLevel(result.get("level", 0))
        self.csrf = self._csrf_from_json(result)
        return LoginResult(
            level=self.user_level,
            is_first_login=result.get("IsFirst", False),
            is_wizard=result.get("IsWizard", False),
            csrf=self.csrf,
        )

    def logout(self) -> None:
        if not self.csrf:
            raise APIError("Not logged in")
        self._request("POST", "/api/system/user_logout",
                      json_data={"csrf": self.csrf.to_dict()})
        self.csrf = None
        self.user_level = UserLevel.NOT_LOGGED_IN

    def heartbeat(self) -> int:
        result = self._request("GET", "/api/system/heartbeat",
                               parse_json=True)
        return int(result.get("interval", 5000))

    def is_logged_in(self) -> bool:
        return self.csrf is not None and self.user_level != UserLevel.NOT_LOGGED_IN

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.is_logged_in():
            try:
                self.logout()
            except APIError:
                pass
        return False


# ── demo ────────────────────────────────────────────────────────────
def main():
    ROUTER_IP = "192.168.1.1"
    USERNAME = "admin"
    PASSWORD = input("Enter router password for 'admin': ")

    client = HG630Client(router_ip=ROUTER_IP)
    try:
        print(f"Connecting to {ROUTER_IP}...")

        print("\n[1] Fetching CSRF tokens...")
        csrf = client.get_initial_csrf()
        print(f"  ✓ Param: {csrf.param}")
        print(f"  ✓ Token: {csrf.token[:20]}...")

        print(f"\n[2] Logging in as '{USERNAME}'...")
        res = client.login(USERNAME, PASSWORD)
        print(f"  ✓ Login OK!  Level: {res.level.name}")

        print("\n[3] Heartbeat...")
        ms = client.heartbeat()
        print(f"  ✓ Interval: {ms}ms")

        print("\n[4] Session active:", client.is_logged_in())

        print("\n[5] Logging out...")
        client.logout()
        print("  ✓ Done. Logged in:", client.is_logged_in())

    except (LoginError, APIError) as e:
        print(f"\n✗ {e}")
        return 1
    print("\n✓ All steps passed!")
    return 0


if __name__ == "__main__":
    exit(main())
