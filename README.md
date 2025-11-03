# AirJack

A macOS Wi-Fi security testing tool for analyzing WPA/WPA2 network security.

![License](https://img.shields.io/badge/license-MIT-blue.svg)

## ⚠️ Legal Disclaimer

This tool is provided for **EDUCATIONAL PURPOSES ONLY**. Only use AirJack on networks you own or have explicit permission to test. Unauthorized access to computer networks is illegal and punishable by law.

## Features

- Scan for nearby Wi-Fi networks
- Capture WPA/WPA2 handshakes 
- Perform dictionary or brute-force attacks
- Configurable via command line or config files
- Detailed logging and verbose mode

## Requirements

### System Requirements
- macOS (uses CoreWLAN and CoreLocation)
- Python 3.7+

### External Dependencies
These tools must be installed separately:
- [hashcat](https://hashcat.net/hashcat/) - Password recovery utility
- [zizzania](https://github.com/cyrus-and/zizzania) - WPA handshake capture tool
- [hcxpcapngtool](https://github.com/ZerBea/hcxtools) - Conversion tool for handshake captures


### Quick Setup
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/rtulke/AirJack/main/install.sh)"
```

### Python Dependencies
```
pip install -r requirements.txt
```

## Manuel Installation

1. Clone the repository:
```bash
git clone https://github.com/rtulke/AirJack.git
cd AirJack
python3 -m venv venv
source venv/bin/activate
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install external tools:
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install hashcat and hcxtools
brew install hashcat hcxtools

# Install zizzania
git clone https://github.com/cyrus-and/zizzania.git ~/zizzania
cd ~/zizzania
make
```

5. Setup System wide
```bash
# Copy AirJack script to `/usr/local/bin/airjack`
sudo cp airjack.py /usr/local/bin/airjack
sudo chmod +x /usr/local/bin/airjack

# Install man page and updating mandb
sudo cp airjack.1 /usr/local/share/man/man1/
sudo mandb

# Use the AirJack script from any directory
$ airjack -h

# Create default configuration (optional)
$ airjack -C ~/.airjack.conf

# You can also try to edit the new generated configuration file
$ vim ~/.airjack.conf

# Try using the manual
$ man airjack
```


## Usage

### Basic Usage

```bash
python airjack.py
```

This will:
1. Scan for available networks
2. Allow you to select a target network
3. Capture a handshake
4. Provide options for cracking the handshake

### Command Line Options

```
Configuration:
  -c CONFIG, --config CONFIG
                        Path to configuration file
  -C PATH, --create-config PATH
                        Create a default configuration file at the specified path

Network Selection:
  -i INTERFACE, --interface INTERFACE
                        Network interface to use
  -n INDEX, --network-index INDEX
                        Select network by index (skips interactive selection)

Capture Options:
  -d, --deauth          Enable deauthentication (default: disabled)
  --capture-file FILE   Output capture file (default: capture.pcap)
  
Cracking Options:
  -m MODE, --mode MODE  Attack mode: 1=Dictionary, 2=Brute-force, 3=Manual
  -w FILE, --wordlist FILE
                        Path to wordlist for dictionary attack
  -p PATTERN, --pattern PATTERN
                        Pattern for brute-force attack
  -o, --optimize        Enable hashcat optimization

Misc Options:
  --auth-timeout SECONDS
                        Timeout for location authorization (default: 60 seconds)
  --cleanup             Clean up sensitive files after completion
  --dry-run             Simulate actions without running external tools
  -v, --verbose         Enable verbose output
```

### Configuration File

AirJack supports configuration files in INI format. The tool checks for configuration in this order:
1. Custom config specified with `-c/--config`
2. User config at `~/.airjack.conf`
3. System config at `/etc/airjack.conf`

Example configuration:

```ini
[General]
capture_file = capture.pcap
hashcat_file = capture.hc22000
auth_timeout = 60
cleanup = false

[Paths]
hashcat_path = /usr/local/bin/hashcat
zizzania_path = /usr/local/bin/zizzania

[Defaults]
interface = en0
deauth = false
optimize = true
verbose = false
```

## Examples

### Dictionary Attack on Specific Network

```bash
python airjack.py -n 1 -m 1 -w /path/to/wordlist.txt -o
```

### Brute Force with Pattern

```bash
python airjack.py -m 2 -p "?d?d?d?d?d?d?d?d" -o
```

### Using Custom Configuration

```bash
python airjack.py -c /path/to/custom/config.conf
```

## 🔧 Troubleshooting

### Common Issues

#### 1. "Error: Missing required dependency: No module named 'CoreWLAN'"

**Cause:** You're using a non-system Python (e.g., from Homebrew or python.org) which doesn't have access to macOS frameworks by default.

**Solution Option 1** (Recommended): Use system Python
```bash
/usr/bin/python3 -m pip install prettytable pyfiglet
/usr/bin/python3 airjack.py
```

**Solution Option 2**: Install PyObjC for your Python
```bash
pip3 install pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation
```

---

#### 2. Location Services Authorization Issues

**Problem:** Location services popup doesn't appear, or authorization fails.

**Solutions:**

**For "Already Denied" errors:**
1. Open **System Settings** → **Privacy & Security** → **Location Services**
2. Find your terminal app (Terminal.app or iTerm2)
3. Enable location services for it
4. Restart AirJack

**For macOS 15+ (Sequoia/Tahoe) where popup doesn't appear:**
1. The popup may not appear automatically on newer macOS versions
2. Manually enable location services:
   - Go to **System Settings** → **Privacy & Security** → **Location Services**
   - Look for your terminal app in the list
   - If not listed, you may need to run the tool once to trigger the system to add it
3. Try using **Terminal.app** instead of iTerm2 (sometimes works better)

**For "NoneType" authorization errors:**
- This has been fixed in the latest version
- Update to the latest version from the main branch
- The tool now handles None authorization status gracefully

---

#### 3. "Capture file not found: capture.hc22000"

**Cause:** No valid WPA handshake was captured in the pcap file.

**Solutions:**
1. Ensure clients are connected to the target network (handshakes are captured during client connection)
2. Enable deauthentication with `-d` flag to force reconnections:
   ```bash
   python airjack.py -d
   ```
3. Wait longer for clients to naturally connect/reconnect
4. Use verbose mode to see more details:
   ```bash
   python airjack.py -v
   ```
5. Verify the capture file exists and has data:
   ```bash
   ls -lh capture.pcap
   ```

---

#### 4. Networks Showing as `<hidden>` with No BSSID

**Cause:** Some network entries return invalid BSSID data.

**Status:** Fixed in the latest version (commit 221deb8)
- Networks with invalid BSSID are now automatically skipped
- Update to the latest version if you encounter this issue

---

#### 5. Permission Errors

**Problem:** "Permission denied" when running tools.

**Solution:**
```bash
# AirJack needs sudo for packet capture
sudo python airjack.py
```

Make sure external tools are executable:
```bash
chmod +x ~/zizzania/src/zizzania
```

---

#### 6. Tool Not Found Errors

**Problem:** "hashcat not found", "zizzania not found", or "hcxpcapngtool not found"

**Solution:**
Check tool paths and install if missing:
```bash
# Check if tools are installed
which hashcat
which hcxpcapngtool

# Install via Homebrew
brew install hashcat hcxtools

# Build zizzania
git clone https://github.com/cyrus-and/zizzania.git ~/zizzania
cd ~/zizzania && make
```

Or specify custom paths:
```bash
python airjack.py --hashcat-path /custom/path/hashcat \
                  --zizzania-path /custom/path/zizzania
```

---

### Getting Help

If you encounter issues not covered here:
1. Check existing [GitHub Issues](https://github.com/rtulke/AirJack/issues)
2. Run with verbose flag `-v` for detailed output
3. Open a new issue with:
   - macOS version
   - Python version (`python3 --version`)
   - Complete error message
   - Steps to reproduce

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -am 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
