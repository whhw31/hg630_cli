# Huawei HG630 VDSL Router API Client

A Python client library for managing Huawei HG630 VDSL routers via their web API.

## Features

- **Full Authentication Flow**: Handles CSRF token extraction and password hashing
- **Session Management**: Maintains session cookies and CSRF tokens automatically
- **Error Handling**: Comprehensive error handling with specific exception types
- **Modular Design**: Clean, well-documented, and easy to extend
- **Context Manager Support**: Use with `with` statements for automatic cleanup

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### Basic Login Example

```python
from hg630 import HG630Client, LoginError

# Initialize client
client = HG630Client(router_ip="192.168.1.1")

try:
    # Login
    result = client.login("admin", "your_password")
    print(f"Logged in as {result.level.name}")
    
    # Check heartbeat
    interval = client.heartbeat()
    print(f"Session timeout: {interval}ms")
    
    # Logout when done
    client.logout()
    
except LoginError as e:
    print(f"Login failed: {e}")
```

### Using Context Manager (Recommended)

```python
from hg630 import HG630Client, LoginError

try:
    with HG630Client("192.168.1.1") as client:
        client.login("admin", "your_password")
        print("Successfully logged in!")
        # Client automatically logs out on exit
        
except LoginError as e:
    print(f"Error: {e}")
```

## Authentication Flow

The client implements the complete authentication flow as documented in the HG630 API:

1. **Fetch Initial Page**: GET `/` to extract `csrf_param` and `csrf_token` from HTML
2. **Hash Password**: SHA256 hash of the plaintext password (64-character hex string)
3. **Login Request**: POST `/api/system/user_login` with:
   - `UserName`: The username (typically "admin")
   - `Password`: SHA256 hash of the plaintext password
   - CSRF tokens from step 1
4. **Session Cookie**: The router returns a `SessionID_R3` cookie for subsequent requests
5. **CSRF Token Update**: Each response includes new CSRF tokens (single-use)

## Client Methods

### `HG630Client(router_ip, timeout)`

Initialize the client.

- `router_ip`: IP address of the router (default: "192.168.1.1")
- `timeout`: Request timeout in seconds (default: 30)

### `get_initial_csrf()`

Fetch the initial page and extract CSRF tokens. Called automatically by `login()` if needed.

Returns: `CSRFToken` object with `param` and `token` attributes.

### `login(username, password)`

Authenticate with the router.

- `username`: Router username
- `password`: Plaintext password

Returns: `LoginResult` object containing:
- `level`: UserLevel enum (NOT_LOGGED_IN, USER, ADMIN, SUPPORT)
- `is_first_login`: Boolean indicating first login
- `is_wizard`: Boolean indicating wizard mode
- `csrf`: CSRFToken for subsequent requests

Raises: `LoginError` if authentication fails.

### `logout()`

Log out and invalidate the session. Called automatically when using context manager.

### `heartbeat()`

Send a heartbeat ping to keep the session alive. Should be called every 5 seconds.

Returns: Heartbeat interval in milliseconds (typically 5000).

### `is_logged_in()`

Check if the client has an active session.

Returns: `True` if logged in, `False` otherwise.

### `get_user_level()`

Get the current user's permission level.

Returns: `UserLevel` enum value.

## Error Handling

The client raises specific exceptions:

- **`LoginError`**: Authentication failures (wrong password, locked account, etc.)
- **`APIError`**: General API failures (connection issues, invalid responses, etc.)

## User Levels

| Level | Name | Access |
|-------|------|--------|
| 0 | NOT_LOGGED_IN | No access |
| 1 | USER | Limited access |
| 2 | ADMIN | Full access |
| 4 | SUPPORT | ISP support level |

## Login Error Codes

| Error Category | Meaning |
|----------------|---------|
| `user_pass_err` | Invalid username or password |
| `Three_time_err` | 3 failed attempts, locked for 1 minute |
| `Three_time_err_multi` | Multiple failed attempts, longer lockout |
| `Duplicate_login` | User already logged in elsewhere |
| `Too_Many_user` | Too many users logged in |

## Session Management

- CSRF tokens are **single-use** - each request returns new tokens
- Sessions expire without heartbeat pings every ~5 seconds
- The client automatically tracks and updates CSRF tokens
- Sessions are tied to the `SessionID_R3` cookie

## Examples

See the `example_basic_login.py` file for a complete working example.

```bash
python example_basic_login.py
```

## Technical Details

This client is based on reverse-engineered firmware analysis of the Huawei HG630 router:

- **Firmware**: HG630.bin (SquashFS extraction)
- **Web Server**: Custom Huawei ATP web server (`bin/cms`)
- **Backend**: Lua handlers
- **Data Model**: TR-069 / TR-098 (`InternetGatewayDevice.*`)

## License

MIT License

## References

- `HG630_API_REFERENCE.md`: Complete API documentation
- `TASK.md`: Reverse engineering task documentation
- `extracted_lua/user_login.lua`: Login handler source code
