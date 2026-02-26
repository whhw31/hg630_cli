import re

with open('wifi_toggle.pcap', 'rb') as f:
    data = f.read()
    
    # Check for "WlanBasic" case-insensitively
    matches = list(re.finditer(b'wlanbasic', data, re.IGNORECASE))
    print(f"Found {len(matches)} occurrences of wlanbasic")
    for m in matches:
        print(f"Match at {m.start()}")
        print(data[m.start()-50:m.end()+500].decode('utf-8', errors='ignore'))