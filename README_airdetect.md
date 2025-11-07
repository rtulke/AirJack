# AirDetect

A passive Wi-Fi access point security scanner for analyzing WLAN security characteristics without associating to networks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)

## ⚠️ Legal Disclaimer

This tool is provided for **EDUCATIONAL AND SECURITY RESEARCH PURPOSES ONLY**. Only use AirDetect on networks you own or have explicit permission to test. Unauthorized monitoring of wireless networks may be illegal in your jurisdiction.

## Features

- **Passive WiFi Scanning** - No active probing or association required
- **Cross-Platform Support** - Works on macOS (CoreWLAN) and Linux (Monitor Mode)
- **Comprehensive Security Analysis**:
  - WPA/WPA2/WPA3/OWE detection
  - WEP and Open network identification
  - AKM suite detection (PSK, 802.1X, SAE, FT, OWE)
  - Cipher analysis (CCMP, TKIP, GCMP)
  - PMF/802.11w capability detection
  - WPS status and vulnerability detection
- **Advanced Features**:
  - 802.11r Fast Transition (FT) detection
  - 802.11k Radio Resource Management (RRM)
  - 802.11v BSS Transition Management
  - Channel width detection (20/40/80/160 MHz)
  - Deauth attack detection
  - 4-Way Handshake observation (EAPOL)
  - **RSSI tracking** with min/max/current values and signal strength history
  - **Data rate estimation** (macOS: theoretical max + RSSI-based estimate, Linux: actual from RadioTap)
- **Interactive Mode** (Permanent Scan):
  - Real-time continuous scanning with auto-refresh
  - Interactive AP selection with Enter key
  - Detailed per-AP popups: Statistics, Information, Signal Strength History
  - Visual signal strength graph with time-based tracking
  - Keyboard navigation (↑/↓ arrows, Enter, ESC, h for help)
- **Vendor Identification** - Comprehensive OUI database (2010-2025) with 1,366+ vendors
- **Colorized Output** - RSSI-based signal strength colors, security type highlighting
- **PCAP Analysis** - Read and analyze existing capture files

## Screenshots

### Colorized Terminal Output
```
========================================================================================================================
BSSID              RSSI     Ch   Band      SSID                      Vendor            Security            Features
========================================================================================================================
0c:8e:39:f9:50:91  -42dBm   40   5 GHz     5g.ramstein.mil.gov       Cisco Meraki      WPA2-Personal       -
18:58:80:d2:82:8c  -56dBm   6    2.4 GHz   5g.ramstein.mil.gov       Unknown           WPA2-Personal       -
dc:15:1b:7d:d4:58  -88dBm   53   5 GHz     hve-45591                 Unknown           WPA3-Personal       -
2c:91:eb:25:a6:2f  -74dBm   11   2.4 GHz   LegoLAN                   TP-Link           WPA2-Personal       WPS RRM BSS-T 20MHz
========================================================================================================================

Total APs: 10
  • WPS enabled: 1
  • PMF required: 0
  • WPA3: 1
  • Hidden SSID: 0
```

**Color Coding:**
- **RSSI**: 🟢 Green (>-60dBm), 🟡 Yellow (>-80dBm), 🔴 Red (≤-80dBm)
- **Security**: 🟢 WPA3/OWE (most secure), 🔵 WPA2 (secure), 🟡 WPA (less secure), 🔴 WEP/Open (insecure)

## Requirements

### System Requirements

**macOS:**
- macOS 10.10+ (Yosemite or later)
- Python 3.8+
- No monitor mode required (uses CoreWLAN framework)

**Linux:**
- Any modern Linux distribution
- Python 3.8+
- Wireless interface capable of monitor mode
- Root/sudo access for packet capture

### Python Dependencies
```
scapy>=2.5.0
```

**macOS only (optional, for CoreWLAN support):**
```
pyobjc-framework-CoreWLAN
pyobjc-framework-CoreLocation
```

## Installation

### Quick Installation (macOS)

Using system Python (recommended for macOS):
```bash
# Clone repository
git clone https://github.com/rtulke/AirJack.git
cd AirJack

# Install dependencies for system Python
/usr/bin/python3 -m pip install --user scapy pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation

# Make executable
chmod +x airdetect.py

# Run directly
./airdetect.py
```

### Quick Installation (Linux)

```bash
# Clone repository
git clone https://github.com/rtulke/AirJack.git
cd AirJack

# Install dependencies
sudo apt update
sudo apt install python3-pip
pip3 install scapy

# Install monitor mode tools (optional, for automatic setup)
sudo apt install aircrack-ng

# Make executable
chmod +x airdetect.py
```

### Manual Installation

1. **Clone the repository:**
```bash
git clone https://github.com/rtulke/AirJack.git
cd AirJack
```

2. **Create virtual environment (optional):**
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/macOS
```

3. **Install Python dependencies:**
```bash
pip install -r requirements.txt
# Or install manually:
pip install scapy

# macOS only (for CoreWLAN support):
pip install pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation
```

4. **Verify vendor database exists:**
```bash
# The vendor_oui.json file should be in the same directory as airdetect.py
ls -lh vendor_oui.json
```

### System-Wide Installation (Optional)

```bash
# Copy script to /usr/local/bin
sudo cp airdetect.py /usr/local/bin/airdetect
sudo chmod +x /usr/local/bin/airdetect

# Copy vendor database
sudo cp vendor_oui.json /usr/local/bin/

# Use from anywhere
airdetect -h
```

## Usage

### Basic Usage

**macOS (No monitor mode needed):**
```bash
# Scan for 30 seconds using CoreWLAN
./airdetect.py

# Or with custom timeout
./airdetect.py -t 60
```

**Linux (Requires monitor mode):**
```bash
# Enable monitor mode first
sudo airmon-ng start wlan0

# Scan on monitor interface
sudo ./airdetect.py -i wlan0mon -t 30

# Stop monitor mode when done
sudo airmon-ng stop wlan0mon
```

**Read from PCAP file (cross-platform):**
```bash
# Analyze existing capture
./airdetect.py -r capture.pcap

# Include EAPOL handshake detection
./airdetect.py -r capture.pcap --eapol
```

### Command Line Options

```
usage: airdetect.py [-h] [-i IFACE | -r READ | -l] [-t TIMEOUT] [--eapol] [--channel CHANNEL]

Passive Wi‑Fi AP security analyzer (beacons/probe responses/optional EAPOL)

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Monitor‑mode interface (e.g. wlan0mon)
  -r READ, --read READ  Read from pcap instead of live capture
  -l, --list-interfaces
                        List all available wireless interfaces and exit
  -t TIMEOUT, --timeout TIMEOUT
                        Sniffing duration in seconds (live mode) (default: 30)
  --eapol               Also mark if a 4‑Way Handshake was observed (EAPOL frames)
  --channel CHANNEL     Hint: channel to scan (set with iw/airmon externally; this is informational only)
```

### Understanding the Output

#### Table Columns

| Column | Description | Example |
|--------|-------------|---------|
| **BSSID** | MAC address of the access point | `2c:91:ab:c5:a6:2f` |
| **RSSI** | Signal strength in dBm (colored) | `-42dBm` (green) |
| **Ch** | WiFi channel number | `11`, `40`, `100` |
| **Band** | Frequency band | `2.4 GHz`, `5 GHz`, `6 GHz` |
| **SSID** | Network name | `MyNetwork` or `<hidden>` |
| **Vendor** | Device manufacturer (from OUI) | `TP-Link`, `Cisco Meraki` |
| **Security** | Security type (colored) | `WPA2-Personal`, `WPA3-Personal` |
| **Features** | Advanced capabilities (see below) | `WPS PMF:req FT 40MHz` |

#### Security Types

AirDetect detects and displays the following WiFi security types, color-coded by security level:

##### 🟢 Modern & Secure

**WPA3-Personal** (Green)
- **Description**: Latest WiFi security standard using SAE (Simultaneous Authentication of Equals / Dragonfly)
- **Authentication**: Pre-Shared Key (password-based)
- **Use Case**: Home networks, small offices
- **Security Level**: Most secure - resistant to offline dictionary attacks
- **Example**: Modern routers from 2020+

**WPA3-Transition** (Green)
- **Description**: Mixed mode supporting both WPA3 and WPA2 for backward compatibility
- **Authentication**: SAE (for WPA3 clients) or PSK (for WPA2 clients)
- **Use Case**: Networks transitioning to WPA3 while supporting older devices
- **Security Level**: High - allows gradual migration to WPA3
- **Example**: Recent routers with "WPA2/WPA3" setting

**WPA2-Enterprise** (Cyan)
- **Description**: Enterprise-grade security with 802.1X authentication via RADIUS server
- **Authentication**: Individual user credentials (username/password or certificates)
- **Use Case**: Corporate networks, universities, large organizations
- **Security Level**: High - centralized user management and auditing
- **Example**: Eduroam, corporate WiFi with AD/LDAP integration
- **Advantages**:
  - Per-user access control
  - Revocable credentials without changing network password
  - Audit logging of connections
  - Certificate-based authentication support

**OWE** (Opportunistic Wireless Encryption) (Green)
- **Description**: Enhanced Open - encrypted open network without password
- **Authentication**: None (automatic encryption via Diffie-Hellman)
- **Use Case**: Public WiFi (cafés, airports) providing encryption without passwords
- **Security Level**: High encryption, no authentication
- **Example**: Modern public hotspots using WPA3 OWE

##### 🔵 Standard & Secure

**WPA2-Personal** (Cyan)
- **Description**: Current standard for most home networks using PSK (Pre-Shared Key)
- **Authentication**: Single shared password for all users
- **Use Case**: Home networks, small businesses, guest WiFi
- **Security Level**: Secure when using strong passwords (12+ characters)
- **Example**: Most home routers (2010-2020)
- **Note**: Vulnerable to brute-force attacks with weak passwords

**WPA2** (Cyan)
- **Description**: Generic WPA2 when AKM suite cannot be determined
- **Authentication**: Unspecified (likely PSK or 802.1X)
- **Use Case**: Various scenarios
- **Security Level**: Secure (details depend on configuration)

##### 🟡 Legacy & Less Secure

**WPA** (Yellow)
- **Description**: Original WPA version 1 (legacy, deprecated)
- **Authentication**: PSK or 802.1X
- **Use Case**: Very old devices (pre-2004)
- **Security Level**: Less secure - vulnerable to known attacks (TKIP weaknesses)
- **Recommendation**: Upgrade to WPA2/WPA3
- **Example**: Old routers from 2003-2006

##### 🔴 Insecure & Unencrypted

**WEP** (Wired Equivalent Privacy) (Red)
- **Description**: Obsolete encryption from 1999 - **completely broken**
- **Authentication**: Shared WEP key
- **Use Case**: Ancient devices (pre-2004)
- **Security Level**: **INSECURE** - can be cracked in minutes
- **Recommendation**: **Never use WEP** - upgrade immediately
- **Example**: Very old routers from 1999-2004
- **Vulnerabilities**: RC4 key reuse, weak IV, easily cracked with tools like aircrack-ng

**Open** (Red)
- **Description**: No encryption or authentication - completely unprotected
- **Authentication**: None
- **Use Case**: Public hotspots (legacy), guest networks
- **Security Level**: **INSECURE** - all traffic visible to attackers
- **Recommendation**: Use OWE instead for public networks, or WPA2/WPA3 with password
- **Example**: Public WiFi in cafés, hotels (legacy)
- **Risk**: Man-in-the-middle attacks, traffic sniffing, session hijacking

---

**Security Recommendations:**
- ✅ **Use**: WPA3-Personal, WPA3-Transition, or WPA2-Enterprise
- ⚠️ **Acceptable**: WPA2-Personal with strong passwords (12+ chars, mixed case, numbers, symbols)
- ❌ **Never use**: WEP or Open networks for sensitive data
- 🔒 **Public WiFi**: Always use VPN on Open networks; prefer OWE when available

#### Feature Flags

**Security Features:**
- **🔓WPS** (red) - WPS enabled and unlocked (vulnerable to brute-force)
- **WPS** (yellow) - WPS enabled and locked
- **PMF:req** (green) - Protected Management Frames required (protects against deauth attacks)
- **PMF:cap** (cyan) - Protected Management Frames supported but optional
- **4WH** (green) - 4-Way Handshake observed during scan

**Roaming & Mobility:**
- **FT** (cyan) - Fast Transition (802.11r) - enables seamless roaming
- **RRM** (cyan) - Radio Resource Management (802.11k) - optimizes channel selection
- **BSS-T** (cyan) - BSS Transition Management (802.11v) - supports assisted roaming

**Technical Details:**
- **20MHz / 40MHz / 80MHz / 160MHz** (blue) - Channel width (higher = more bandwidth)

**Security Warnings:**
- **⚠️DA:X** (red) - Deauth attack detected! (X = number of deauth frames > 10)

#### Summary Statistics

```
Total APs: 10
  • WPS enabled: 1      # Yellow if >0 (security risk), green if 0
  • PMF required: 0     # Green if >0 (good), yellow if 0
  • WPA3: 1             # Green if >0 (modern security), yellow if 0
  • Hidden SSID: 0      # Informational count
  • ⚠️ Potential attacks detected: 2 APs with excessive deauth frames
```

## Examples

### Example 1: Quick macOS Scan
```bash
# Scan for 30 seconds (default)
./airdetect.py

# Scan for 2 minutes for more thorough results
./airdetect.py -t 120
```

### Example 2: Linux Monitor Mode Scan
```bash
# Enable monitor mode
sudo airmon-ng start wlan0

# Scan for 60 seconds with EAPOL handshake detection
sudo ./airdetect.py -i wlan0mon -t 60 --eapol

# Disable monitor mode
sudo airmon-ng stop wlan0mon
```

### Example 3: Analyze Existing Capture
```bash
# Analyze a Wireshark capture
./airdetect.py -r wifi_capture.pcap

# Analyze with handshake detection
./airdetect.py -r wifi_capture.pcap --eapol
```

### Example 4: List Available Interfaces
```bash
# See all wireless interfaces
./airdetect.py -l

# Example output:
# ======================================================================
# Interface             Mode             Status
# ======================================================================
# wlan0                 Managed          Available
# wlan0mon              Monitor          Available
# ======================================================================
```

### Example 5: Channel-Specific Scan (Linux)
```bash
# Lock to channel 6 before scanning
sudo iw dev wlan0mon set channel 6
sudo ./airdetect.py -i wlan0mon -t 60 --channel 6
```

## Vendor Database

AirDetect includes a comprehensive vendor OUI (Organizationally Unique Identifier) database in `vendor_oui.json`:

- **1,366+ vendor entries** covering 2010-2025
- **Network Equipment**: Cisco (300+), TP-Link (33), Netgear (40), Asus (50+), Ubiquiti (18)
- **Printers**: HP (75), Canon (33), Epson (19), Brother (13), Xerox (8)
- **Consumer Electronics**: Apple (200+), Samsung (200+), Google (15), Huawei (80+), Xiaomi (50+)
- **IoT & Development**: Raspberry Pi (5), Arduino, ESP32 modules

The database is automatically loaded at startup with fallback to a minimal built-in list if the file is missing.

### Updating the Vendor Database

To add new vendors, edit `vendor_oui.json`:

```json
{
  "comment": "WiFi Vendor OUI Database (2010-2025)",
  "version": "1.0",
  "last_updated": "2025-11-04",
  "vendors": {
    "00:0C:43": "MediaTek",
    "2C:91:AB": "TP-Link",
    "A0:B5:49": "Cisco Meraki",
    "XX:XX:XX": "Your New Vendor"
  }
}
```

Find OUI information at: https://maclookup.app/ or https://standards-oui.ieee.org/

## Platform-Specific Notes

### macOS

**Advantages:**
- ✅ No monitor mode required (uses CoreWLAN framework)
- ✅ No root/sudo needed for basic scanning
- ✅ Easy to use, just run the script
- ✅ Works on all Mac laptops and desktops with WiFi

**Limitations:**
- ⚠️ Limited information elements (IE) parsing
- ⚠️ Fewer advanced features detected (WPS, PMF details, channel width)
- ⚠️ Cannot capture EAPOL handshakes
- ℹ️ For advanced features, use Linux with monitor mode or analyze PCAP files

**Best Practices:**
```bash
# Use system Python for best compatibility
/usr/bin/python3 airdetect.py

# Increase timeout for more thorough scans
./airdetect.py -t 90
```

### Linux

**Advantages:**
- ✅ Full monitor mode support
- ✅ Complete information element (IE) parsing
- ✅ All advanced features detected (WPS, PMF, channel width, etc.)
- ✅ Can capture EAPOL handshakes
- ✅ Can detect deauth attacks

**Requirements:**
- Wireless adapter with monitor mode support
- Root/sudo access
- Monitor mode tools (airmon-ng recommended)

**Best Practices:**
```bash
# Check if your adapter supports monitor mode
iw list | grep -A 10 "Supported interface modes"

# Use airmon-ng for easy monitor mode setup
sudo airmon-ng start wlan0

# Channel hop for comprehensive scan
sudo airodump-ng wlan0mon &
sudo ./airdetect.py -i wlan0mon -t 120 --eapol

# Always stop monitor mode when done
sudo airmon-ng stop wlan0mon
```

## 🔧 Troubleshooting

### macOS Issues

#### 1. "CoreWLAN not available"

**Cause:** PyObjC frameworks not installed or using non-system Python.

**Solution:**
```bash
# Option 1: Use system Python (recommended)
/usr/bin/python3 -m pip install --user pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation
/usr/bin/python3 airdetect.py

# Option 2: Install in virtual environment
pip install pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation
```

#### 2. No Networks Found or Limited Results

**Cause:** Short scan timeout or location services issues.

**Solutions:**
```bash
# Increase scan timeout
./airdetect.py -t 120

# Enable Location Services for your terminal app:
# System Settings → Privacy & Security → Location Services → Terminal/iTerm2
```

#### 3. Missing Vendor Names (Shows "Unknown")

**Cause:** `vendor_oui.json` file not found or not in the same directory.

**Solution:**
```bash
# Check if vendor database exists
ls -lh vendor_oui.json

# If missing, download it from the repository
wget https://raw.githubusercontent.com/rtulke/AirJack/main/vendor_oui.json
```

### Linux Issues

#### 1. "Permission denied" Error

**Cause:** Packet capture requires root privileges.

**Solution:**
```bash
# Run with sudo
sudo ./airdetect.py -i wlan0mon -t 30
```

#### 2. "No such device" Error

**Cause:** Interface not in monitor mode or doesn't exist.

**Solution:**
```bash
# List available interfaces
./airdetect.py -l

# Enable monitor mode
sudo airmon-ng start wlan0

# Verify monitor interface exists
iwconfig
```

#### 3. Monitor Mode Not Working

**Cause:** Adapter doesn't support monitor mode or conflicting processes.

**Solutions:**
```bash
# Kill conflicting processes
sudo airmon-ng check kill

# Try manual monitor mode setup
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Verify monitor mode is active
iwconfig wlan0
```

#### 4. "No APs discovered" Despite Active Networks

**Causes:**
- Wrong channel (not hopping)
- Short timeout
- USB WiFi adapter not receiving packets

**Solutions:**
```bash
# Use airodump-ng to verify packet capture works
sudo airodump-ng wlan0mon

# If working, increase timeout and try again
sudo ./airdetect.py -i wlan0mon -t 90

# Check if your adapter is receiving packets
sudo tcpdump -i wlan0mon -c 10
```

### General Issues

#### 1. "Failed to import scapy"

**Solution:**
```bash
pip install scapy
# Or on Linux:
sudo apt install python3-scapy
```

#### 2. Table Alignment Issues in Terminal

**Cause:** Terminal width too narrow for 120-character table.

**Solution:**
- Resize terminal window to at least 120 characters wide
- Use full-screen terminal
- Reduce font size slightly

#### 3. Colors Not Displaying

**Cause:** Terminal doesn't support ANSI color codes.

**Solutions:**
- Use a modern terminal (iTerm2 on macOS, GNOME Terminal on Linux)
- Check if `TERM` environment variable is set correctly:
  ```bash
  echo $TERM  # Should be xterm-256color or similar
  ```

## Advanced Usage

### Combining with Other Tools

**Use with Wireshark:**
```bash
# Capture with AirDetect, analyze with Wireshark
sudo ./airdetect.py -i wlan0mon -t 300 &
sudo wireshark -i wlan0mon -k
```

**Create Custom Wordlists from SSIDs:**
```bash
# Extract all SSIDs to wordlist
./airdetect.py -r capture.pcap | grep -v "hidden" | awk '{print $5}' > ssids.txt
```

**Export to JSON (using external tools):**
```bash
# Capture to PCAP
sudo ./airdetect.py -i wlan0mon -t 60
# Convert with tshark
tshark -r capture.pcap -T json > capture.json
```

### Security Research Workflow

1. **Discovery Phase:**
   ```bash
   # Comprehensive 5-minute scan
   ./airdetect.py -t 300
   ```

2. **Identify Vulnerable Networks:**
   - Look for 🔓WPS (unlocked WPS)
   - Look for WEP/Open networks (red security)
   - Check for missing PMF (no PMF:req)
   - Note networks with deauth attacks (⚠️DA:X)

3. **Detailed Analysis:**
   ```bash
   # Capture with EAPOL for handshake analysis
   sudo ./airdetect.py -i wlan0mon -t 600 --eapol -r detailed.pcap
   ```

4. **Report Generation:**
   - Document findings
   - Export PCAP for evidence
   - Use vendor information for asset inventory

## Performance Tips

- **Scan Duration**: 30-60 seconds for quick scan, 2-5 minutes for comprehensive scan
- **Channel Coverage**: On Linux, use channel hopping tools (airodump-ng) for better coverage
- **PCAP Files**: For large PCAP files (>100MB), analysis may take several minutes
- **Memory Usage**: Minimal (<50MB RAM typically)

## Privacy & Ethics

**AirDetect is a passive monitoring tool. Please use responsibly:**

- ✅ **DO**: Use on your own networks for security auditing
- ✅ **DO**: Use for authorized penetration testing
- ✅ **DO**: Use for educational purposes in controlled environments
- ✅ **DO**: Respect privacy laws and regulations

- ❌ **DON'T**: Monitor networks without authorization
- ❌ **DON'T**: Use for malicious purposes
- ❌ **DON'T**: Attempt to decrypt or access networks you don't own
- ❌ **DON'T**: Share captured data containing private information

**Legal Note:** Simply scanning for WiFi networks is generally legal (similar to viewing available networks in your WiFi settings), but laws vary by jurisdiction. Capturing packet data, even passively, may require authorization. Always obtain proper permission.

## Contributing

Contributions are welcome! Here's how you can help:

### Adding New Vendors

Submit PR with updates to `vendor_oui.json`:
```json
{
  "vendors": {
    "XX:XX:XX": "New Vendor Name"
  }
}
```

### Feature Requests

Open an issue on GitHub with:
- Clear description of the feature
- Use case / why it's useful
- Example output (if applicable)

### Bug Reports

Include:
- Operating system and version
- Python version (`python3 --version`)
- Complete error message
- Steps to reproduce
- Sample PCAP file (if relevant)

### Pull Requests

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -am 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## Related Tools

- **airjack.py** - WPA/WPA2 handshake capture and cracking tool
- **airodump-ng** - Network monitoring and packet capture
- **Wireshark** - Network protocol analyzer
- **Kismet** - Wireless network detector and IDS

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Uses [Scapy](https://scapy.net/) for packet manipulation
- Vendor database compiled from [IEEE OUI registry](https://standards-oui.ieee.org/)
- Inspired by airodump-ng and Kismet

## Support

- **Issues**: https://github.com/rtulke/AirJack/issues
- **Documentation**: https://github.com/rtulke/AirJack/wiki
- **Discussions**: https://github.com/rtulke/AirJack/discussions

---

**Version**: 1.0
**Last Updated**: 2025-11-04
**Author**: AirJack Project Contributors
