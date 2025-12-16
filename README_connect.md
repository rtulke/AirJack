# connect.py - WiFi Monitor Mode Recovery Tool

## Description

Recovery tool for macOS WiFi interfaces stuck in monitor mode. Automatically detects connection status and reconnects to networks.

## Features

- Detects and exits monitor mode
- Multi-method connection verification (ifconfig + wdutil)
- Custom SSID/password support via CLI
- Interactive scan & connect: scan networks, pick by ID, uses saved Keychain creds first, prompts for password if needed
- Secure password input (getpass)
- Network scanning (CoreWLAN preferred, airport as fallback)
- Error detection with actionable fixes

## Requirements

- macOS (tested on recent versions)
- Root privileges (sudo)
- Python 3.6+

## Usage

### Auto-connect to preferred network
```bash
sudo ./connect.py
```

### Connect to specific network (password prompt)
```bash
sudo ./connect.py -s "MyNetwork"
# Will prompt: Enter password for 'MyNetwork':
```

### Connect with password
```bash
sudo ./connect.py -s "MyNetwork" -p "MyPassword123"
```

### Scan for available networks
```bash
sudo ./connect.py --scan
# Shows ID, SSID, RSSI, channel (no BSSID), sorted by strongest signal.
# Enter the ID to connect; uses saved credentials first, otherwise asks for a password.
```

### Help
```bash
./connect.py --help
```

## Exit Scenarios

1. **Already connected** - Script exits immediately
2. **Monitor mode active** - Full recovery performed
3. **Not connected** - Attempts connection to preferred network
4. **Custom connection** - Connects to specified SSID

## Common Errors

### Error -3900: Authentication failed
```bash
# Remove saved password
sudo security delete-generic-password -l "NetworkName"

# Reconnect
sudo ./connect.py -s "NetworkName" -p "NewPassword"
```

### Error -3905: Network not found
```bash
# Scan for available networks
sudo ./connect.py --scan
```

## Technical Details

### Connection Detection Methods
1. `networksetup -getairportnetwork` (primary)
2. `ifconfig` - checks IP and status (reliable)
3. `wdutil info` - gets SSID details

### Tools Used
- `wdutil` - Modern WiFi diagnostics (info, diagnose)
- CoreWLAN (preferred scan on macOS, no deprecation warnings)
- `airport` - Fallback scan (deprecated)
- `networksetup` - Network configuration
- `ifconfig` - Interface configuration

## Troubleshooting

**Script says "not connected" but I am connected:**
- This is a known macOS issue where `networksetup` reports incorrect status
- Script uses `ifconfig` as fallback - should work correctly

**Connection fails repeatedly:**
- Check if network is in range: `sudo ./connect.py --scan`
- If scan shows no BSSID/SSID on macOS, ensure Location Services for your terminal are enabled
- Remove saved credentials: `sudo security delete-generic-password -l "SSID"`
- Try manual connection with password

**Monitor mode won't disable:**
- Script attempts interface restart
- May require system reboot in rare cases

## Security Notes

- Passwords passed via `-p` are visible in process list
- Use password prompt (without `-p`) for better security
- Passwords stored in macOS Keychain after successful connection

## License

Created for personal use - modify as needed
