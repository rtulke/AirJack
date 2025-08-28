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
git clone https://github.com/yourusername/AirJack.git
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
sudo cp AirJack.py /usr/local/bin/airjack
sudo chmod +x /usr/local/bin/airjack

# Install man page and updating mandb
sudo cp airjack.1 /usr/local/share/man/man1/
sudo mandb

# Use the AirJack script from any directory
$ airjack -h

# Create default configuration (optional)
$ airjack.py -C ~/.airjack.conf

# Uou can also try to edit the new generated configuration file
$ vim ~/.airjack.conf

# Try using the manual
$ man airjack
```


## Usage

### Basic Usage

```bash
python AirJack.py
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
python AirJack.py -n 1 -m 1 -w /path/to/wordlist.txt -o
```

### Brute Force with Pattern

```bash
python AirJack.py -m 2 -p "?d?d?d?d?d?d?d?d" -o
```

### Using Custom Configuration

```bash
python AirJack.py -c /path/to/custom/config.conf
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -am 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
