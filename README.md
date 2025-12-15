# AirJack

AirJack scans nearby Wi‑Fi networks on macOS using CoreWLAN, helps you pick a target, and orchestrates [AirSnare](https://github.com/rtulke/airsnare) plus [hcxpcapngtool](https://github.com/ZerBea/hcxtools) to capture WPA/WPA2/WPA3 handshakes. It then converts the capture to [hashcat](https://hashcat.net/hashcat/) format and guides you through dictionary, brute‑force, or manual cracking workflows with optional cleanup for sensitive files.

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
- [zizzania](https://github.com/cyrus-and/zizzania) **or** [AirSnare](https://github.com/rtulke/airsnare) - WPA handshake capture tool
- [hcxpcapngtool](https://github.com/ZerBea/hcxtools) - Conversion tool for handshake captures


### Quick Setup (macOS)
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/rtulke/AirJack/main/install.sh)"
```

### Python Dependencies
```
pip install -r requirements.txt
```

## Manuel Installation (macOS)

1. Clone the repository and install virutal python environment:
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
brew install hashcat hcxtools libpcap wget

# Install Zizzania, https://github.com/cyrus-and/zizzania
git clone https://github.com/cyrus-and/zizzania.git
cd zizzania
make -f config.Makefile
make
# make install
# make uninstall

# Or install AirSnare, a fork and rewritten version of Zizzania, instead.
git clone https://github.com/rtulke/airsnare.git
cd airsnare
make install
```

5. Setup system wide
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

**Recommended (uses launcher script):**
```bash
./airjack
```

**Or directly with Python:**
```bash
# On macOS 15+ (Sequoia), use system Python:
/usr/bin/python3 airjack.py

# On older macOS or if not using venv:
python3 airjack.py
```

This will:
1. Scan for available networks
2. Allow you to select a target network
3. Capture a handshake
4. Provide options for cracking the handshake

**Note:** The `./airjack` launcher automatically selects the correct Python version for your system, especially important on macOS 15+.

### Command Line Options

```
Configuration:
  -c CONFIG, --config CONFIG
                        Path to configuration file
  -C PATH, --create-config PATH
                        Create a default configuration file at the specified path

Capture Backend:
  --capture-tool {zizzania,airsnare}
                        Select capture backend (default: auto, prefers zizzania if available)
  --zizzania-path PATH  Path to zizzania executable
  --airsnare-path PATH  Path to airsnare executable

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
airsnare_path = /usr/local/bin/airsnare

[Defaults]
interface = en0
deauth = false
optimize = true
verbose = false
```

## Examples

### Dictionary Attack on Specific Network

```bash
./airjack -n 1 -m 1 -w /path/to/wordlist.txt -o

# Or with Python directly:
/usr/bin/python3 airjack.py -n 1 -m 1 -w /path/to/wordlist.txt -o
```

### Brute Force with Pattern

```bash
./airjack -m 2 -p "?d?d?d?d?d?d?d?d" -o
```

### Using Custom Configuration

```bash
./airjack -c /path/to/custom/config.conf
```

## 🔧 Troubleshooting

### Common Issues

#### 1. "Error: Missing required dependency: No module named 'CoreWLAN'"

**Cause:** You're using a non-system Python (e.g., from Homebrew or python.org) which doesn't have access to macOS frameworks by default.

**Solution Option 1** (Recommended): Use the launcher script
```bash
./airjack
```
The launcher automatically handles Python selection.

**Solution Option 2**: Use system Python directly
```bash
/usr/bin/python3 -m pip install prettytable pyfiglet
/usr/bin/python3 airjack.py
```

**Solution Option 3**: Install PyObjC for your Python
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

**For macOS 15+ (Sequoia) - IMPORTANT:**

macOS 15 has significant changes to Location Services that affect Python scripts:

**Problem:** Networks show with `BSSID: None` even though Python has Location Services enabled.

**Root Cause:** When using a Python virtual environment (venv), the Python process runs under your terminal app (iTerm2, Terminal.app, etc.), NOT as the Python shown in Location Services. macOS 15 removed the "+" button to manually add apps, making it impossible to add terminal apps to Location Services.

**Solution 1: Use the Launcher Script (Easiest)**
```bash
./airjack  # ✅ Automatically uses system Python on macOS 15+
```

The launcher script automatically detects your macOS version and uses the appropriate Python.

**Solution 2: Use System Python Directly**
```bash
# Instead of using venv Python:
source venv/bin/activate
python airjack.py  # ❌ Won't work - runs under terminal, no Location Services

# Use system Python directly:
/usr/bin/python3 airjack.py  # ✅ Works - uses Python's Location Services permission
```

**Setup for System Python:**
```bash
# Install dependencies for system Python (one-time)
/usr/bin/python3 -m pip install --user prettytable pyfiglet
```

**Why This Works:**
- System Python (`/usr/bin/python3`) has its own entry in Location Services
- Virtual environment Python inherits terminal app's permissions (which don't exist)
- Using system Python bypasses the terminal app permission requirement

**Alternative (if system Python doesn't work):**
Try resetting Location Services for your terminal:
```bash
# For iTerm2:
killall iTerm2
tccutil reset LocationServices com.googlecode.iterm2

# For Terminal.app:
killall Terminal
tccutil reset LocationServices com.apple.Terminal
```

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
   ./airjack -d
   ```
3. Wait longer for clients to naturally connect/reconnect
4. Use verbose mode to see more details:
   ```bash
   ./airjack -v
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
sudo ./airjack
# Or with Python directly:
sudo /usr/bin/python3 airjack.py
```

Make sure external tools are executable:
```bash
chmod +x /usr/local/bin/airsnare
```

---

#### 6. Tool Not Found Errors

**Problem:** "hashcat not found", "airsnare not found", or "hcxpcapngtool not found"

**Solution:**
Check tool paths and install if missing:
```bash
# Check if tools are installed
which hashcat
which hcxpcapngtool

# Install via Homebrew
brew install hashcat hcxtools

# Build AirSnare
git clone https://github.com/rtulke/airsnare.git
cd airsnare && make && make install
```

Or specify custom paths:
```bash
./airjack --hashcat-path /custom/path/hashcat \
          --airsnare-path /custom/path/airsnare
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
