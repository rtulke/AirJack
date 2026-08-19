#!/usr/bin/env python3
"""
AirJack — Wi-Fi security testing tool for macOS.

Workflow
--------
1. Request CoreLocation permission (required to read BSSIDs on macOS 14+).
2. Scan nearby networks via CoreWLAN and present an interactive selection table.
3. Disassociate from the current network, tune the interface to the target channel.
4. Launch AirSnare (capture backend) via sudo to capture a WPA/WPA2 handshake.
5. Convert the pcap to hashcat-22000 format with hcxpcapngtool.
6. Run hashcat for dictionary, brute-force or manual cracking.
7. Optionally clean up sensitive capture files.

Platform requirements
---------------------
macOS 14 (Sonoma) or later — uses CoreWLAN and CoreLocation.
Python 3.8+ (uses walrus operator style; f-strings since 3.6).

macOS-version notes
-------------------
• macOS 14 / 15: CoreWLAN stable; Location Services changes on 15+ may cause
  BSSID:None for networks if the calling process is not /usr/bin/python3 (see
  the venv warning emitted at startup).
• macOS 26+: airport utility expected to be removed; CoreWLAN API changes
  possible. The code guards against both by using CoreWLAN as the primary path
  and airport only as a fallback.
• Apple Silicon (arm64): pcap_inject() is not supported on the built-in Wi-Fi
  adapter — deauthentication (active mode) will fail. Use passive mode (-n) or
  an external USB adapter.

External tools required
-----------------------
  airsnare        WPA handshake capture  (brew tap rtulke/airsnare && brew install airsnare)
  hcxpcapngtool   pcap → hashcat format  (brew install hcxtools)
  hashcat         WPA cracking           (brew install hashcat)

Legal notice
------------
For educational purposes and security testing of networks you own or have
explicit written permission to test. Unauthorized access is illegal.
"""

import queue
import select
import signal
import subprocess
import re
import argparse
import os
import sys
import logging
import configparser
import shutil
import platform
import threading
import time
import json
import tempfile
from os.path import expanduser, join, exists, dirname, abspath
from time import sleep
from typing import List, Dict, Tuple, Optional, Any, Union

BASE_DIR = dirname(abspath(__file__))

try:
    import CoreWLAN
    import CoreLocation
    from Foundation import NSObject, NSRunLoop, NSDate
    from prettytable import PrettyTable
    from pyfiglet import Figlet
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("\n=== Troubleshooting Guide ===")

    if "CoreWLAN" in str(e) or "CoreLocation" in str(e):
        print("\nCoreWLAN and CoreLocation are macOS system frameworks.")
        print("They cannot be installed via pip.")
        print("\nPossible causes:")
        print("1. You are using a non-system Python (e.g., from python.org or Homebrew)")
        print("2. You are not running on macOS")
        print("\nSolution:")
        print("- Use the system Python: /usr/bin/python3")
        print("- Or install PyObjC to access macOS frameworks:")
        print("  pip3 install pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation")
        print("\nExample:")
        print("  /usr/bin/python3 -m pip install prettytable pyfiglet")
        print("  /usr/bin/python3 airjack.py")
    else:
        print("\nPlease install required packages with:")
        print("  pip3 install prettytable pyfiglet")

    sys.exit(1)


class _AirJackLocationDelegate(NSObject):
    """Minimal CLLocationManager delegate.

    CoreLocation only surfaces the permission prompt and registers the process
    in the Location Services list when a delegate is set *and* the owning
    thread's run loop is being serviced. The callback body can stay empty — its
    mere presence, combined with a running run loop (see
    request_location_permission), is what lets macOS present the prompt and
    create the Location Services entry. Without this, requestWhenInUse...
    returns silently and nothing ever appears (issue #11).
    """

    def locationManagerDidChangeAuthorization_(self, manager):
        pass


# ---------------------------------------------------------------------------
# macOS 15+/26 BSSID recovery via monitor mode
# ---------------------------------------------------------------------------
# On macOS 15 (Sequoia) and 26 (Tahoe) CoreWLAN redacts CWNetwork.bssid() to
# None for command-line processes even when Location Services report the
# process as authorized: BSSID exposure is additionally gated behind a real,
# signed .app bundle, which a terminal-launched script can never satisfy. SSID,
# RSSI and channel still come through — only the BSSID is stripped.
#
# We recover the BSSIDs the way any passive scanner does: put the Wi-Fi card
# into monitor mode (RFMON) with tcpdump, hop across the channels CoreWLAN
# already reported as in use, and read the BSSID straight out of the 802.11
# beacon / probe-response headers. This path does not touch Location Services.
# It needs root (RFMON + channel tuning), so the unprivileged main process
# re-invokes this file under `sudo ... --mon-bssid-scan` and reads back a JSON
# list of {bssid, ssid, channel}. See WiFiCracker._recover_bssids_via_monitor.

def _freq_to_channel(freq):
    """Map a radiotap channel frequency in MHz to an 802.11 channel number."""
    if not freq:
        return None
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:            # 6 GHz (Wi-Fi 6E)
        return (freq - 5950) // 5
    return None


def _parse_beacon(pkt):
    """Extract (bssid, ssid_or_None, channel_or_None, rssi_or_None) from a frame.

    Returns None if the frame carries no usable BSSID.
    """
    from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap
    # Drop frames the radio flagged with a bad FCS: they parse into garbage
    # (bogus BSSIDs / oversized SSID elements) and pollute the results.
    try:
        rt = pkt.getlayer(RadioTap)
        flags = getattr(rt, "Flags", None)
        if flags is not None and ("BadFCS" in flags or int(flags) & 0x40):
            return None
    except Exception:
        pass

    d = pkt.getlayer(Dot11)
    if d is None or not d.addr3:
        return None
    bssid = d.addr3.lower()
    if bssid in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return None
    ssid = None
    channel = None
    el = pkt.getlayer(Dot11Elt)
    while isinstance(el, Dot11Elt):
        if el.ID == 0 and ssid is None:                 # SSID element
            raw = bytes(el.info)
            if len(raw) > 32:                           # malformed IE (spec max 32)
                return None
            if raw and any(b != 0 for b in raw):        # skip hidden (all-null)
                try:
                    ssid = raw.decode("utf-8", "replace")
                except Exception:
                    ssid = None
        elif el.ID == 3 and len(el.info) >= 1:          # DS Parameter Set
            channel = el.info[0]
        elif el.ID == 61 and len(el.info) >= 1 and channel is None:  # HT Operation
            channel = el.info[0]
        el = el.payload.getlayer(Dot11Elt)
    if channel is None:
        try:
            channel = _freq_to_channel(getattr(pkt.getlayer(RadioTap), "ChannelFrequency", None))
        except Exception:
            channel = None
    rssi = None
    try:
        sig = getattr(pkt.getlayer(RadioTap), "dBm_AntSignal", None)
        if sig is not None:
            rssi = int(sig)
    except Exception:
        rssi = None
    return bssid, ssid, channel, rssi


def monitor_bssid_scan(interface="en0", channels=None, dwell=0.5, rounds=2,
                       max_seconds=45):
    """Recover BSSIDs via RFMON. MUST run as root. Returns [{bssid,ssid,channel}].

    Args:
        interface:  Wi-Fi interface (e.g. "en0").
        channels:   list of channel numbers to hop; if empty, discovered via a
                    CoreWLAN scan and then a sensible default set.
        dwell:      seconds to linger on each channel per pass.
        rounds:     number of passes over the channel list.
        max_seconds: hard cap on the capture phase.
    """
    client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
    iface = client.interfaceWithName_(interface) or client.interface()
    if iface is None:
        return []

    if not channels:
        scan, _err = iface.scanForNetworksWithName_error_(None, None)
        seen = set()
        for n in (scan or []):
            cw = n.wlanChannel()
            if cw:
                seen.add(cw.channelNumber())
        channels = sorted(seen) or [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]

    # Resolve channel numbers to CWChannel objects (one per number, first wins).
    by_num = {}
    for cw in (iface.supportedWLANChannels() or []):
        num = cw.channelNumber()
        if num in channels and num not in by_num:
            by_num[num] = cw
    targets = [by_num[n] for n in channels if n in by_num]
    if not targets:
        return []

    # Create the capture file securely: root writes to it via tcpdump -w, so a
    # predictable mktemp() path in world-writable /tmp is a symlink/TOCTOU risk.
    fd, pcap = tempfile.mkstemp(suffix=".pcap", dir="/tmp")
    os.close(fd)
    proc = subprocess.Popen(
        ["/usr/sbin/tcpdump", "-I", "-i", interface, "-y", "IEEE802_11_RADIO",
         "-w", pcap, "-U", "-s", "512"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    if proc.poll() is not None:                 # tcpdump failed to enter RFMON
        try:
            os.unlink(pcap)
        except OSError:
            pass
        return []

    # Free the card only now that RFMON is confirmed up, so a doomed attempt
    # (e.g. no BPF access) does not needlessly drop the user's Wi-Fi.
    try:
        iface.disassociate()
    except Exception:
        pass

    start = time.time()
    try:
        for _ in range(rounds):
            for cw in targets:
                iface.setWLANChannel_error_(cw, None)
                time.sleep(dwell)
                if time.time() - start > max_seconds:
                    raise TimeoutError
    except TimeoutError:
        pass
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    from scapy.all import rdpcap
    from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
    try:
        pkts = rdpcap(pcap)
    except Exception:
        pkts = []
    finally:
        try:
            os.unlink(pcap)
        except Exception:
            pass

    found = {}
    for p in pkts:
        if not (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)):
            continue
        parsed = _parse_beacon(p)
        if not parsed:
            continue
        bssid, ssid, channel, rssi = parsed
        e = found.get(bssid)
        if e is None:
            e = {"bssid": bssid, "ssid": ssid, "channel": channel,
                 "rssi": rssi, "count": 0}
            found[bssid] = e
        e["count"] += 1
        if ssid and not e["ssid"]:
            e["ssid"] = ssid
        if channel and not e["channel"]:
            e["channel"] = channel
        if rssi is not None and (e["rssi"] is None or rssi > e["rssi"]):
            e["rssi"] = rssi          # keep the strongest sample
    return list(found.values())


def _run_mon_bssid_scan_cli(args):
    """Internal subcommand: run monitor_bssid_scan and print a single JSON line.

    Everything else must stay off stdout so the parent can json.loads() it.
    """
    interface = args.interface or "en0"
    channels = None
    if args.mon_channels:
        try:
            channels = [int(x) for x in args.mon_channels.split(",") if x.strip()]
        except ValueError:
            channels = None
    try:
        results = monitor_bssid_scan(interface=interface, channels=channels)
        print(json.dumps({"ok": True, "bssids": results}))
        return 0
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e), "bssids": []}))
        return 1


# --- macOS 15+ Virtual Environment Warning ---
def check_macos_venv_issue():
    """Check if running in venv on macOS 15+ and warn user."""
    # Never prompt during the internal, sudo-reinvoked monitor-mode subcommand:
    # its stdout must stay a single JSON line and it must not block on input().
    if '--mon-bssid-scan' in sys.argv:
        return
    # Check if we're on macOS
    if platform.system() != 'Darwin':
        return

    # Check macOS version
    try:
        macos_version = platform.mac_ver()[0]
        major_version = int(macos_version.split('.')[0])

        # macOS 15+ (Sequoia)
        if major_version >= 15:
            # Check if running in virtual environment
            in_venv = hasattr(sys, 'real_prefix') or (
                hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
            )

            if in_venv:
                print("\n" + "="*70)
                print("⚠️  WARNING: Virtual Environment on macOS 15+ Detected")
                print("="*70)
                print("\nmacOS 15+ has Location Services issues with virtual environments.")
                print("You may see 'BSSID: None' for all networks.\n")
                print("RECOMMENDED: Use system Python instead:")
                print(f"  /usr/bin/python3 {' '.join(sys.argv)}")
                print("\nPress Enter to continue anyway, or Ctrl+C to abort...")
                print("="*70 + "\n")

                try:
                    input()
                except KeyboardInterrupt:
                    print("\nAborted by user.")
                    sys.exit(0)
    except Exception:
        # If we can't determine version, skip warning
        pass


# Check for macOS 15+ venv issue early
check_macos_venv_issue()


# --- Tool Path Detection Helpers ---

def find_tool_path(tool_name: str, manual_locations: List[str] = None) -> Optional[str]:
    """
    Smart detection for external tool paths.

    Checks in order:
    1. System PATH (via which/shutil.which) - Homebrew installations
    2. Manual build locations (~/tool_name/...)
    3. Common macOS locations

    Args:
        tool_name: Name of the tool (e.g., 'hashcat', 'airsnare')
        manual_locations: Optional list of additional paths to check

    Returns:
        Full path to tool if found, None otherwise
    """
    # 1. Check system PATH first (Homebrew installations)
    path_result = shutil.which(tool_name)
    if path_result and os.path.isfile(path_result) and os.access(path_result, os.X_OK):
        return path_result

    # 2. Check manual build locations
    manual_paths = manual_locations or []

    # Add common manual build locations
    if tool_name == 'hashcat':
        manual_paths.extend([
            join(expanduser('~'), 'hashcat', 'hashcat'),
            join(expanduser('~'), 'hashcat', 'bin', 'hashcat'),
            '/usr/local/bin/hashcat',
        ])
    elif tool_name == 'airsnare':
        manual_paths.extend([
            join(expanduser('~'), 'airsnare', 'build', 'airsnare'),
            join(expanduser('~'), 'airsnare', 'src', 'airsnare'),
            join(expanduser('~'), 'airsnare', 'airsnare'),
            '/usr/local/bin/airsnare',
        ])
    elif tool_name == 'zizzania':
        manual_paths.extend([
            join(expanduser('~'), 'zizzania', 'src', 'zizzania'),
            '/usr/local/bin/zizzania',
        ])
    elif tool_name == 'hcxpcapngtool':
        manual_paths.extend([
            '/usr/local/bin/hcxpcapngtool',
        ])

    # 3. Check each manual location
    for path in manual_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # 4. Common Homebrew locations (fallback if shutil.which didn't find it)
    homebrew_locations = [
        '/opt/homebrew/bin',  # Apple Silicon
        '/usr/local/bin',     # Intel Mac
    ]

    for brew_dir in homebrew_locations:
        full_path = join(brew_dir, tool_name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path

    return None


def detect_wifi_interface_mac() -> Optional[str]:
    """Detect a usable Wi-Fi interface on macOS."""
    # Prefer CoreWLAN
    try:
        if platform.system() == "Darwin":
            client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
            iface = client.interface()
            if iface and iface.interfaceName():
                return str(iface.interfaceName())
    except Exception:
        pass

    # Fallback: networksetup parsing
    try:
        output = subprocess.check_output(
            ["networksetup", "-listallhardwareports"], text=True
        )
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if "Hardware Port: Wi-Fi" in line or "Hardware Port: AirPort" in line:
                # Next line typically: Device: en0
                if i + 1 < len(lines) and "Device:" in lines[i + 1]:
                    return lines[i + 1].split("Device:")[-1].strip()
    except Exception:
        pass

    # Fallback: common defaults
    for candidate in ("en0", "en1"):
        try:
            subprocess.check_call(["ifconfig", candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return candidate
        except Exception:
            continue
    return None


def list_wifi_interfaces_mac() -> List[str]:
    """List Wi-Fi-capable interfaces on macOS."""
    interfaces = []
    try:
        output = subprocess.check_output(
            ["networksetup", "-listallhardwareports"], text=True
        )
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if "Hardware Port: Wi-Fi" in line or "Hardware Port: AirPort" in line:
                if i + 1 < len(lines) and "Device:" in lines[i + 1]:
                    iface = lines[i + 1].split("Device:")[-1].strip()
                    interfaces.append(iface)
    except Exception:
        pass
    # Fallback: probe common names
    for candidate in ("en0", "en1"):
        if candidate not in interfaces:
            try:
                subprocess.check_call(["ifconfig", candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                interfaces.append(candidate)
            except Exception:
                continue
    return interfaces


def is_executable(path: str) -> bool:
    return path is not None and os.path.isfile(path) and os.access(path, os.X_OK)


def get_default_tool_paths() -> Dict[str, str]:
    """
    Get default paths for all required tools.

    Returns:
        Dictionary with detected or default paths for each tool
    """
    paths = {}

    # Detect hashcat
    hashcat_path = find_tool_path('hashcat')
    paths['hashcat_path'] = hashcat_path or join(expanduser('~'), 'hashcat', 'hashcat')

    # Detect capture backends
    zizzania_path = find_tool_path('zizzania', manual_locations=[
        join(BASE_DIR, 'zizzania', 'src', 'zizzania')
    ])
    airsnare_path = find_tool_path('airsnare', manual_locations=[
        join(BASE_DIR, 'airsnare', 'src', 'airsnare')
    ])

    paths['zizzania_path'] = zizzania_path or join(expanduser('~'), 'zizzania', 'src', 'zizzania')
    paths['airsnare_path'] = airsnare_path or join(expanduser('~'), 'airsnare', 'src', 'airsnare')

    return paths


class ConfigManager:
    """Manages configuration file operations."""
    
    DEFAULT_USER_CONFIG = "~/.airjack.conf"
    DEFAULT_SYSTEM_CONFIG = "/etc/airjack.conf"
    
    def __init__(self):
        """Initialize the config manager."""
        self.config = configparser.ConfigParser()
        
    def create_default_config(self, config_path: str) -> bool:
        """Create a default configuration file.

        Args:
            config_path: Path where to create the config file

        Returns:
            bool: True if successful, False otherwise
        """
        config_path = os.path.expanduser(config_path)

        # Detect tool paths intelligently
        detected_paths = get_default_tool_paths()

        # Create default config
        self.config["General"] = {
            "capture_file": "capture.pcap",
            "hashcat_file": "capture.hc22000",
            "auth_timeout": "60",
            "cleanup": "false",
        }

        # Use detected paths (Homebrew-first, then manual build fallback)
        self.config["Paths"] = {
            "hashcat_path": detected_paths['hashcat_path'],
            "airsnare_path": detected_paths['airsnare_path'],
            "zizzania_path": detected_paths['zizzania_path'],
            "capture_tool": "airsnare" if find_tool_path('airsnare') else "zizzania",
        }
        
        self.config["Defaults"] = {
            "interface": "",
            "deauth": "false",
            "optimize": "false",
            "verbose": "false",
        }
        
        # dirname("filename") returns "" when no directory component is given.
        # os.makedirs("") raises FileNotFoundError, so fall back to "." (CWD).
        config_dir = dirname(config_path) or '.'
        os.makedirs(config_dir, exist_ok=True)
        
        # Write config
        try:
            with open(config_path, 'w') as configfile:
                self.config.write(configfile)
            return True
        except Exception as e:
            print(f"Error creating config file: {e}")
            return False
    
    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file.
        
        Args:
            config_path: Path to config file or None to use default locations
            
        Returns:
            dict: Configuration as a dictionary
        """
        config_dict = {}
        config_loaded = False
        
        # Try specified config path if provided
        if config_path:
            expanded_path = os.path.expanduser(config_path)
            if os.path.exists(expanded_path):
                try:
                    self.config.read(expanded_path)
                    config_loaded = True
                except Exception as e:
                    print(f"Error loading config from {expanded_path}: {e}")
        
        # Try default locations if no config loaded yet
        if not config_loaded and not config_path:
            user_config = os.path.expanduser(self.DEFAULT_USER_CONFIG)
            system_config = self.DEFAULT_SYSTEM_CONFIG
            
            config_files = []
            if os.path.exists(system_config):
                config_files.append(system_config)
            if os.path.exists(user_config):
                config_files.append(user_config)
                
            if config_files:
                self.config.read(config_files)
                config_loaded = True
        
        # Convert config to dictionary
        if config_loaded:
            for section in self.config.sections():
                for key, value in self.config[section].items():
                    config_dict[key] = value
        
        return config_dict


class WiFiCracker:
    """Main class for WiFi security testing functionality."""
    
    def __init__(self, args: argparse.Namespace):
        """Initialize the WiFi cracker with command-line arguments.
        
        Args:
            args: Command-line arguments parsed by argparse
        """
        self.args = args
        
        # Load config if specified or available
        self.config_manager = ConfigManager()
        self.config = self.config_manager.load_config(args.config)
        
        # Apply config to args (command line takes precedence)
        self._apply_config_to_args()
        
        self.setup_logging()
        self.setup_tools()
        self.networks = []
        self.saved_ssid = None  # Track disconnected network for reconnection
        self.default_interface = detect_wifi_interface_mac()
        self.resolved_interface = None

        # Initialize CoreWLAN
        self.cwlan_client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
        self.cwlan_interface = self.cwlan_client.interface()
        
        # Output files (from config or defaults)
        self.capture_file = self.args.capture_file
        self.hashcat_file = self.args.hashcat_file
        
        # Fancy banner
        if not self.args.no_banner:
            f = Figlet(font='big')
            print('\n' + f.renderText('AirJack'))
            print("WiFi Security Testing Tool - For Educational Purposes Only")
            print("WARNING: Only use on networks you own or have permission to test!\n")
            
    def _apply_config_to_args(self):
        """Apply configuration values to args if not specified on command line."""
        # Helper to convert string to boolean
        def str_to_bool(s: str) -> bool:
            return s.lower() in ('true', 'yes', '1', 'on')

        # Set defaults for required arguments (always needed, even without config)
        if self.args.capture_file is None:
            self.args.capture_file = self.config.get('capture_file', "capture.pcap") if self.config else "capture.pcap"

        if self.args.hashcat_file is None:
            self.args.hashcat_file = self.config.get('hashcat_file', "capture.hc22000") if self.config else "capture.hc22000"

        if self.args.auth_timeout is None:
            if self.config and 'auth_timeout' in self.config:
                self.args.auth_timeout = int(self.config['auth_timeout'])
            else:
                self.args.auth_timeout = 60  # Default timeout

        # Only apply config if available
        if self.config:
                
            if self.args.hashcat_path is None:
                self.args.hashcat_path = self.config.get('hashcat_path', None)

            if self.args.airsnare_path is None:
                self.args.airsnare_path = self.config.get('airsnare_path', None)

            if self.args.zizzania_path is None:
                self.args.zizzania_path = self.config.get('zizzania_path', None)

            if self.args.capture_tool is None:
                self.args.capture_tool = self.config.get('capture_tool', None)

            if self.args.interface is None:
                self.args.interface = self.config.get('interface', None)

            # Boolean flags (only set to True if in config and not set via command line)
            if not self.args.cleanup and 'cleanup' in self.config:
                self.args.cleanup = str_to_bool(self.config['cleanup'])
                
            if not self.args.deauth and 'deauth' in self.config:
                self.args.deauth = str_to_bool(self.config['deauth'])
                
            if not self.args.optimize and 'optimize' in self.config:
                self.args.optimize = str_to_bool(self.config['optimize'])
                
            if not self.args.verbose and 'verbose' in self.config:
                self.args.verbose = str_to_bool(self.config['verbose'])
    
    def setup_logging(self):
        """Configure a named logger for AirJack.

        Uses a dedicated 'airjack' logger (not the root logger) to avoid
        polluting other modules' log output when AirJack is imported as a
        library. Adds a StreamHandler only once to prevent duplicate lines
        if WiFiCracker is instantiated more than once in the same process.
        """
        log_level = logging.DEBUG if self.args.verbose else logging.INFO
        logger = logging.getLogger('airjack')
        logger.setLevel(log_level)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            logger.addHandler(handler)
        self.log = logger
    
    def setup_tools(self):
        """Set up paths to external tools and verify their existence."""
        # Priority order:
        # 1. Command-line arguments (--hashcat-path, --airsnare-path)
        # 2. Config file values
        # 3. Smart detection (Homebrew-first, then manual builds)
        # 4. Hardcoded fallback defaults

        # Capture backend selection: prefer explicit choice, otherwise auto preferring zizzania
        preferred_capture = (self.args.capture_tool.lower()
                             if getattr(self.args, 'capture_tool', None)
                             else None)

        # Paths
        z_path = self.args.zizzania_path or find_tool_path('zizzania', manual_locations=[
            join(BASE_DIR, 'zizzania', 'src', 'zizzania')
        ]) or join(expanduser('~'), 'zizzania', 'src', 'zizzania')
        a_path = self.args.airsnare_path or find_tool_path('airsnare', manual_locations=[
            join(BASE_DIR, 'airsnare', 'src', 'airsnare')
        ]) or join(expanduser('~'), 'airsnare', 'src', 'airsnare')

        # Decide capture tool (prefer airsnare — actively maintained)
        if preferred_capture:
            self.capture_tool = preferred_capture
        else:
            self.capture_tool = 'airsnare' if is_executable(a_path) else 'zizzania'

        # Assign capture path
        if self.capture_tool == 'zizzania':
            self.capture_path = z_path
        else:
            self.capture_path = a_path

        # Enforce requested backend presence
        if preferred_capture == 'zizzania' and not is_executable(self.capture_path):
            self.log.error(f"Requested capture tool 'zizzania' not found at {self.capture_path}")
            if not self.args.ignore_missing:
                sys.exit(1)
        if preferred_capture == 'airsnare' and not is_executable(self.capture_path):
            self.log.error(f"Requested capture tool 'airsnare' not found at {self.capture_path}")
            if not self.args.ignore_missing:
                sys.exit(1)

        # If auto-selected airsnare because zizzania missing, log hint
        if not preferred_capture and self.capture_tool != 'zizzania':
            if not is_executable(z_path):
                self.log.info("zizzania not found; falling back to airsnare. Build zizzania to use it by default.")

        if self.args.hashcat_path:
            self.hashcat_path = self.args.hashcat_path
        else:
            detected = find_tool_path('hashcat')
            self.hashcat_path = detected or join(expanduser('~'), 'hashcat', 'hashcat')

        # hcxpcapngtool converts pcap → hashcat-22000; detect early so the error
        # is shown at startup rather than after a 10-minute capture session.
        self.hcxpcapngtool_path = shutil.which('hcxpcapngtool') or 'hcxpcapngtool'

        # Validate tool paths if not in dry_run mode
        if not self.args.dry_run:
            missing_tools = []

            if not exists(self.hashcat_path):
                missing_tools.append(f"hashcat: {self.hashcat_path}")
                homebrew_hashcat = find_tool_path('hashcat')
                if homebrew_hashcat:
                    self.log.info(f"Hint: Found hashcat at {homebrew_hashcat}")
                    self.log.info(f"Use --hashcat-path {homebrew_hashcat} or add to config file")

            if not is_executable(self.capture_path):
                missing_tools.append(f"{self.capture_tool}: {self.capture_path}")
                found_airsnare = find_tool_path('airsnare')
                found_zizzania = find_tool_path('zizzania')
                if found_zizzania:
                    self.log.info(f"Hint: Found zizzania at {found_zizzania}")
                    self.log.info(f"Use --zizzania-path {found_zizzania} or add to config file")
                if found_airsnare:
                    self.log.info(f"Hint: Found airsnare at {found_airsnare}")
                    self.log.info(f"Use --airsnare-path {found_airsnare} or add to config file")

            # Check hcxpcapngtool separately — it is only needed after capture,
            # but missing it wastes the entire capture session.
            if not shutil.which('hcxpcapngtool'):
                missing_tools.append("hcxpcapngtool (from hcxtools): not found in PATH")

            if missing_tools:
                self.log.error("Missing required tools:")
                for tool in missing_tools:
                    self.log.error(f"  - {tool}")
                self.log.error("")
                self.log.error("Solutions:")
                self.log.error("  brew tap rtulke/airsnare && brew install airsnare hashcat hcxtools")
                if not self.args.ignore_missing:
                    sys.exit(1)

        self.log.debug(f"Using hashcat: {self.hashcat_path}")
        self.log.debug(f"Using hcxpcapngtool: {self.hcxpcapngtool_path}")
        self.log.debug(f"Using capture backend ({self.capture_tool}): {self.capture_path}")

    def resolve_interface(self) -> Optional[str]:
        """Determine which Wi-Fi interface to use (with interactive fallback)."""
        if self.resolved_interface:
            return self.resolved_interface

        # CLI override
        if self.args.interface:
            self.resolved_interface = self.args.interface
            return self.resolved_interface

        # Auto-detected default
        if self.default_interface:
            self.resolved_interface = self.default_interface
            return self.resolved_interface

        # CoreWLAN current interface
        try:
            cw_iface = self.cwlan_interface.interfaceName()
            if cw_iface:
                self.resolved_interface = cw_iface
                return self.resolved_interface
        except Exception:
            pass

        # Interactive selection from detected interfaces
        candidates = list_wifi_interfaces_mac()
        if len(candidates) == 1:
            self.resolved_interface = candidates[0]
            return self.resolved_interface
        elif len(candidates) > 1:
            print("\nDetected Wi-Fi interfaces:")
            for idx, name in enumerate(candidates, start=1):
                print(f"  {idx}) {name}")
            try:
                choice = input(f"Select interface [1-{len(candidates)}] (default 1): ").strip()
                if choice == "":
                    self.resolved_interface = candidates[0]
                else:
                    sel = int(choice)
                    if sel < 1 or sel > len(candidates):
                        self.log.error("Invalid selection, falling back to first interface.")
                        self.resolved_interface = candidates[0]
                    else:
                        self.resolved_interface = candidates[sel - 1]
                return self.resolved_interface
            except (ValueError, EOFError, KeyboardInterrupt):
                self.log.error("Interface selection cancelled or invalid, using first candidate.")
                self.resolved_interface = candidates[0]
                return self.resolved_interface

        # Last resort
        self.resolved_interface = "en0"
        return self.resolved_interface

    @staticmethod
    def _is_macos_15_plus() -> bool:
        """True on macOS 15 (Sequoia) or later, where CoreWLAN redacts BSSIDs."""
        try:
            return int(platform.mac_ver()[0].split('.')[0]) >= 15
        except Exception:
            return False

    def _note_bssid_source(self) -> None:
        """Tell the user, once, where BSSIDs will actually come from."""
        if self._is_macos_15_plus():
            self.log.info("macOS 15+/26: BSSIDs are recovered via monitor mode during "
                          "the scan (this needs sudo and briefly drops Wi-Fi).")

    def _recover_bssids_via_monitor(self, channels) -> list:
        """Recover CoreWLAN-redacted BSSIDs (macOS 15+/26) via monitor mode.

        Tries an in-process RFMON scan first — on machines where /dev/bpf is
        accessible without root (e.g. Wireshark's ChmodBPF) this avoids a sudo
        prompt entirely — and falls back to re-invoking this file under sudo.
        Returns a list of {bssid, ssid, channel} dicts.
        """
        try:
            iface_name = self.cwlan_interface.interfaceName()
        except Exception:
            iface_name = self.resolve_interface() or "en0"
        chan_list = sorted(set(channels)) if channels else None

        # Remember the current network so run()'s finally-block can reconnect.
        try:
            cur = self.cwlan_interface.ssid()
            if cur and not self.saved_ssid:
                self.saved_ssid = cur
        except Exception:
            pass

        # 1) In-process attempt — only worth trying (it disassociates Wi-Fi and
        # spins up tcpdump) when RFMON can actually succeed unprivileged: we are
        # already root, or /dev/bpf* is readable (e.g. Wireshark's ChmodBPF).
        # Otherwise skip straight to sudo to avoid a doomed Wi-Fi drop.
        can_inprocess = (hasattr(os, "geteuid") and os.geteuid() == 0) or \
            any(os.access(f"/dev/bpf{i}", os.R_OK) for i in range(8))
        if can_inprocess:
            self.log.info("Recovering BSSIDs via monitor mode (this briefly drops Wi-Fi)...")
            try:
                results = monitor_bssid_scan(interface=iface_name, channels=chan_list)
            except Exception as e:
                self.log.debug(f"In-process monitor scan failed: {e}")
                results = []
            if results:
                return results

        # 2) Privileged fallback: re-invoke airjack under sudo.
        self.log.warning("Monitor mode needs elevated privileges here; requesting sudo "
                         "(this is the same elevation the capture step uses)...")
        try:
            if subprocess.run(["sudo", "-v"]).returncode != 0:
                self.log.error("sudo authentication failed; cannot recover BSSIDs.")
                return []
        except Exception as e:
            self.log.error(f"Could not run sudo: {e}")
            return []

        # The child runs as root but must import scapy/CoreWLAN, which are often
        # installed only for the invoking user (pip --user or a venv) and are
        # NOT on root's default import path. Pass the interpreter's own
        # site-packages via PYTHONPATH and tell sudo to preserve it, otherwise
        # the child fails at `import CoreWLAN`/`import scapy`.
        import site
        py_paths = [p for p in sys.path if p and 'site-packages' in p]
        try:
            py_paths.append(site.getusersitepackages())
        except Exception:
            pass
        env = dict(os.environ)
        env['PYTHONPATH'] = os.pathsep.join(
            dict.fromkeys(filter(None, py_paths + [env.get('PYTHONPATH', '')])))

        script = os.path.abspath(__file__)
        cmd = ["sudo", "--preserve-env=PYTHONPATH", "-n", sys.executable, script,
               "--mon-bssid-scan", "-i", iface_name]
        if chan_list:
            cmd += ["--mon-channels", ",".join(str(c) for c in chan_list)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150, env=env)
        except subprocess.TimeoutExpired:
            self.log.error("Monitor-mode scan timed out.")
            return []
        out = (proc.stdout or "").strip()
        if not out:
            self.log.error("Monitor-mode scan produced no output. "
                           f"{(proc.stderr or '').strip()[:200]}")
            return []
        try:
            data = json.loads(out.splitlines()[-1])
        except Exception as e:
            self.log.error(f"Could not parse monitor-scan output: {e}")
            self.log.debug(f"stdout={out!r} stderr={(proc.stderr or '')!r}")
            return []
        if not data.get("ok"):
            self.log.error(f"Monitor-mode scan error: {data.get('error')}")
        return data.get("bssids", []) or []

    def _merge_recovered_bssids(self, recovered) -> None:
        """Fill missing BSSIDs on self.networks from monitor-mode results,
        matching by SSID (channel as tie-breaker) and falling back to a
        channel-only match for hidden SSIDs."""
        missing_before = sum(1 for n in self.networks if not n['bssid'])
        by_ssid = {}
        for r in recovered:
            ssid = r.get('ssid')
            if ssid:
                by_ssid.setdefault(ssid, []).append(r)
        # Seed with BSSIDs CoreWLAN already provided (lowercased, as recovered
        # entries are), so a recovered duplicate is never assigned to a second,
        # different network on a mixed/rescan pass.
        used = {n['bssid'].lower() for n in self.networks if n['bssid']}
        matched = 0
        for net in self.networks:
            if net['bssid']:
                continue
            cands = by_ssid.get(net['ssid'], [])
            pick = None
            for r in cands:                      # same SSID + same channel
                if r['bssid'] not in used and r.get('channel') == net['channel_number']:
                    pick = r
                    break
            if pick is None:                     # same SSID, any channel
                for r in cands:
                    if r['bssid'] not in used:
                        pick = r
                        break
            if pick is None and (not net['ssid'] or net['ssid'] == "<hidden>"):
                # Hidden SSID only: match by channel, but ONLY to a recovered AP
                # that is itself hidden (ssid-less). We must not grab a named
                # AP's BSSID here — that would aim the capture at the wrong AP.
                # If no hidden AP is on this channel, leave it unresolved.
                pick = next((r for r in recovered
                             if r['bssid'] not in used
                             and not r.get('ssid')
                             and r.get('channel') == net['channel_number']), None)
            if pick is not None:
                net['bssid'] = pick['bssid'].upper()
                used.add(pick['bssid'])
                matched += 1

        # Add APs seen only via monitor mode. In the denied/timeout path CoreWLAN
        # redacts SSIDs, so the SSID-based fill above cannot match named APs and
        # they would be dropped. Rather than guess a channel match onto a redacted
        # placeholder (which would risk targeting the wrong AP), we surface the
        # real beacon data directly: any recovered AP with a real SSID + BSSID
        # that was not used to fill an existing entry becomes its own entry.
        added = 0
        leftovers = [r for r in recovered if r.get('ssid') and r['bssid'] not in used]
        if leftovers:
            chan_objs = {}
            try:
                for cw in (self.cwlan_interface.supportedWLANChannels() or []):
                    chan_objs.setdefault(cw.channelNumber(), cw)
            except Exception:
                pass
            for r in leftovers:
                ch = r.get('channel')
                self.networks.append({
                    'ssid': r['ssid'],
                    'bssid': r['bssid'].upper(),
                    'rssi': r.get('rssi'),
                    'channel_object': chan_objs.get(ch),
                    'channel_number': ch if isinstance(ch, int) else '-',
                    'security': 'Unknown',
                })
                used.add(r['bssid'])
                added += 1

        self.log.info(f"Recovered {matched}/{missing_before} redacted BSSID(s) via "
                      f"monitor mode; added {added} seen only in monitor mode.")

    def request_location_permission(self) -> bool:
        """Request permission to use location services for WiFi scanning.

        Returns:
            bool: True if authorized, False otherwise
        """
        # macOS never shows the Location Services prompt to a root process, and
        # a sudo run is attributed to root rather than the terminal app — so no
        # entry is created. The main process must run unprivileged; AirJack
        # elevates only the capture backend later.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.log.warning("Running as root (sudo): macOS will not present the Location "
                             "Services prompt for a root process, so no entry is created.")
            self.log.warning("Run AirJack WITHOUT sudo — it requests elevation only for the "
                             "capture backend when it is actually needed.")

        # Initialize CoreLocation. A delegate must be set and the run loop must
        # be serviced (see the wait loop below) or the prompt never appears and
        # no Location Services entry is created (issue #11). Keep a strong
        # reference to the delegate so it is not garbage-collected mid-request.
        location_manager = CoreLocation.CLLocationManager.alloc().init()
        self._location_delegate = _AirJackLocationDelegate.alloc().init()
        location_manager.setDelegate_(self._location_delegate)

        # Check if location services are enabled
        if not location_manager.locationServicesEnabled():
            self.log.error("Location services are disabled. Please enable them and try again.")
            self.log.error("Go to: System Settings > Privacy & Security > Location Services")
            return False

        # Check current authorization status before requesting
        current_status = location_manager.authorizationStatus()
        self.log.debug(f"Current authorization status: {current_status}")

        # Handle None case early (can happen on some macOS versions)
        if current_status is None:
            self.log.warning("Unable to determine current authorization status (returned None)")
            self.log.warning("This may indicate a macOS system issue. Proceeding with authorization request...")
            # Don't return False here, continue with the request
        elif current_status in [3, 4]:  # 3 = always, 4 = when in use
            # Authorized is all we need: it de-randomizes CoreWLAN SSIDs. BSSIDs
            # (redacted on macOS 15+/26) are recovered separately via monitor
            # mode in scan_networks, so we no longer gate on a BSSID pre-check.
            self.log.info(f"Location Services authorized (status {current_status}).")
            self._note_bssid_source()
            return True
        elif current_status == 2:  # denied
            if self._is_macos_15_plus():
                self.log.warning("Location Services previously denied; continuing with "
                                 "monitor-mode BSSID recovery (SSID names may be randomized).")
                self.log.warning("For accurate SSID names: System Settings > Privacy & "
                                 "Security > Location Services.")
                self._note_bssid_source()
                return True
            self.log.error("Location services access was previously denied.")
            self.log.error("Please enable it in: System Settings > Privacy & Security > Location Services")
            self.log.error("Look for your terminal app (Terminal, iTerm2, etc.) and enable it.")
            return False
        elif current_status == 1:  # restricted
            self.log.error("Location services access is restricted (possibly by parental controls).")
            return False

        # Not-yet-decided (status 0/None): request authorization. The authorized
        # (3/4) and denied (2) cases already returned above.
        self.log.info("Requesting authorization for location services (required for WiFi scanning)...")
        self.log.info("A permission popup should appear. If it doesn't appear within 10 seconds:")
        self.log.info("1. Check System Settings > Privacy & Security > Location Services")
        self.log.info("2. Look for your terminal app and ensure it's enabled")
        self.log.info("3. On macOS 15+, you may need to manually add your terminal app to Location Services")
        location_manager.requestWhenInUseAuthorization()

        # Wait for location services to be authorized
        max_wait = self.args.auth_timeout if self.args.auth_timeout is not None else 60
        for i in range(max_wait):
            authorization_status = location_manager.authorizationStatus()
            self.log.debug(f"Loop {i}: authorization_status = {authorization_status}")

            # Handle None case (can happen on some macOS versions)
            if authorization_status is None:
                self.log.warning("Authorization status returned None, attempting to continue...")
                # Try one more time after a short delay
                sleep(2)
                authorization_status = location_manager.authorizationStatus()
                if authorization_status is None:
                    self.log.error("Cannot determine authorization status. Please check:")
                    self.log.error("1. System Settings > Privacy & Security > Location Services")
                    self.log.error("2. Ensure your terminal app (Terminal/iTerm2) has Location Services enabled")
                    self.log.error("3. Try running from a different terminal or with different permissions")
                    return False

            # 0 = not determined, 1 = restricted, 2 = denied, 3 = authorized always, 4 = authorized when in use
            if authorization_status in [3, 4]:
                self.log.info("Location Services authorized, continuing...")
                self._note_bssid_source()
                return True


            # Denied during wait: on macOS 15+/26 we can still recover BSSIDs via
            # monitor mode, so proceed — only the SSID names may be randomized.
            if authorization_status == 2:
                if self._is_macos_15_plus():
                    self.log.warning("Location denied; continuing with monitor-mode BSSID "
                                     "recovery (SSID names may be randomized).")
                    self._note_bssid_source()
                    return True
                self.log.error("Location services access was denied during authorization request.")
                self.log.error("Please enable it in: System Settings > Privacy & Security > Location Services")
                return False

            if i == max_wait - 1:
                # Timeout reached with no decision. On macOS 15+/26 this is not
                # fatal: BSSIDs come from monitor mode regardless, and CoreWLAN
                # still returns usable (if possibly randomized) SSIDs.
                if self._is_macos_15_plus():
                    self.log.warning("No Location Services decision within timeout — "
                                     "continuing. BSSIDs will be recovered via monitor "
                                     "mode; SSID names may be approximate.")
                    self._note_bssid_source()
                    return True
                self.log.error("Authorization timeout - Location Services are not working properly.")
                self.log.error("Open System Settings > Privacy & Security > Location Services, "
                               "enable it, then re-run.")
                self.log.error(f"Final authorization status: {authorization_status}")
                return False

            # Service the run loop for ~1s instead of a blind sleep(). This is
            # what lets CoreLocation present the prompt and deliver the delegate
            # callback; a plain sleep() would starve the run loop and the prompt
            # would never appear (issue #11).
            NSRunLoop.currentRunLoop().runUntilDate_(
                NSDate.dateWithTimeIntervalSinceNow_(1.0)
            )
            if i % 5 == 0 and i > 0:
                self.log.info(f"Waiting for authorization... ({i}/{max_wait}s)")

        return False

    def disconnect_from_network(self) -> Tuple[bool, Optional[str]]:
        """Disconnect from current WiFi network.

        Returns:
            Tuple[bool, Optional[str]]: (success, current_ssid)
                - success: True if disconnected successfully
                - current_ssid: Name of the network we were connected to (None if not connected)
        """
        try:
            # Get current SSID before disconnecting
            current_ssid = self.cwlan_interface.ssid()

            if current_ssid:
                self.log.info(f"Disconnecting from '{current_ssid}'...")
            else:
                self.log.info("Not currently connected to any network")
                return True, None

            # Disassociate from current network
            self.cwlan_interface.disassociate()

            # Wait a moment for disconnection to complete
            sleep(1)

            # Verify disconnection
            new_ssid = self.cwlan_interface.ssid()
            if new_ssid is None:
                self.log.info("Successfully disconnected")
                return True, current_ssid
            else:
                self.log.warning(f"Still connected to '{new_ssid}'")
                return False, current_ssid

        except Exception as e:
            self.log.error(f"Error disconnecting: {e}")
            return False, None

    def reconnect_to_network(self, ssid: str) -> bool:
        """Reconnect to a specific WiFi network after capture.

        Retries up to 3 times with increasing delays because macOS needs several
        seconds to release the interface from RFMON mode after AirSnare exits.
        Falls back to networksetup if CoreWLAN association keeps returning -3900.

        Args:
            ssid: Network name to reconnect to

        Returns:
            bool: True if reconnection successful, False otherwise
        """
        if not ssid:
            return False

        max_retries = 3
        for attempt in range(max_retries):
            # Delays: 5 s, 8 s, 11 s — gives macOS time to exit RFMON on each retry.
            delay = 5 + attempt * 3
            if attempt == 0:
                self.log.info(f"Waiting {delay}s for interface to leave RFMON mode...")
            else:
                self.log.info(f"Reconnect attempt {attempt + 1}/{max_retries} (waiting {delay}s)...")
            sleep(delay)

            try:
                self.log.info(f"Attempting to reconnect to '{ssid}'...")

                scan_results, error = self.cwlan_interface.scanForNetworksWithName_error_(ssid, None)
                if error:
                    self.log.warning(f"Scan error on attempt {attempt + 1}: {error}")
                    continue

                if not scan_results or len(scan_results) == 0:
                    self.log.warning(f"Network '{ssid}' not in range on attempt {attempt + 1}")
                    continue

                target_network = None
                for network in scan_results:
                    target_network = network
                    break

                if not target_network:
                    continue

                # macOS uses Keychain credentials automatically when password=None.
                success, error = self.cwlan_interface.associateToNetwork_password_error_(
                    target_network, None, None
                )
                if error:
                    self.log.warning(f"Association failed on attempt {attempt + 1}: {error}")
                    continue

                self.log.info(f"Successfully reconnected to '{ssid}'")
                return True

            except Exception as e:
                self.log.warning(f"Reconnect attempt {attempt + 1} exception: {e}")
                continue

        # All CoreWLAN attempts failed.
        # Persistent -3900 errors mean the interface is still in RFMON or stuck
        # in a transitional state.  Power-cycle WiFi to force it back to managed
        # mode before trying to associate.
        iface = self.resolve_interface() or "en0"
        self.log.info("Attempting automatic monitor-mode exit via WiFi power cycle...")
        try:
            # Remove the monitor-mode mediaopt flag (harmless if not set; needs root)
            subprocess.run(["ifconfig", iface, "-mediaopt", "monitor"],
                           capture_output=True, timeout=5)
            subprocess.run(["networksetup", "-setairportpower", iface, "off"],
                           capture_output=True, timeout=10)
            sleep(2)
            subprocess.run(["networksetup", "-setairportpower", iface, "on"],
                           capture_output=True, timeout=10)
            sleep(3)
            self.log.info("WiFi power cycle complete — retrying connection...")
        except Exception as e:
            self.log.warning(f"Power cycle failed: {e}")

        # networksetup fallback — talks to the Wi-Fi daemon directly, bypasses
        # CoreWLAN's -3900 state.
        self.log.warning("Trying networksetup to associate...")
        try:
            result = subprocess.run(
                ["networksetup", "-setairportnetwork", iface, ssid],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and "Failed" not in result.stdout:
                self.log.info(f"Reconnected to '{ssid}' via networksetup")
                return True
            self.log.warning(f"networksetup failed: {result.stdout or result.stderr}")
        except Exception as e:
            self.log.warning(f"networksetup fallback exception: {e}")

        # Last resort: restart airportd.  After RFMON the WiFi daemon can get
        # stuck in a state where even airport/networksetup can't scan or
        # associate — restarting it clears that state completely.
        # sudo -n uses the credential cache from the earlier sudo -v call.
        self.log.info("Restarting WiFi daemon (airportd) to clear RFMON state...")
        try:
            subprocess.run(["sudo", "-n", "killall", "airportd"],
                           capture_output=True, timeout=5)
            sleep(4)  # airportd takes a moment to restart
            subprocess.run(["networksetup", "-setairportpower", iface, "on"],
                           capture_output=True, timeout=10)
            sleep(3)
            result = subprocess.run(
                ["networksetup", "-setairportnetwork", iface, ssid],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and "Failed" not in result.stdout:
                self.log.info(f"Reconnected to '{ssid}' after daemon restart")
                return True
            self.log.warning(f"Post-restart connect failed: {result.stdout or result.stderr}")
        except Exception as e:
            self.log.warning(f"airportd restart failed: {e}")

        self.log.warning(f"Could not reconnect to '{ssid}'. Please reconnect manually.")
        self.log.warning(f"  sudo networksetup -setairportnetwork {iface} \"{ssid}\"")
        return False

    def colorize_rssi(self, rssi: int) -> str:
        """Colorize RSSI values based on signal strength.
        
        Args:
            rssi: Signal strength in dBm
            
        Returns:
            str: Colorized RSSI string
        """
        if rssi is None:
            return "-"
        if rssi > -60:
            # Green for strong signal
            return f"\033[92m{rssi}\033[0m"
        elif rssi > -80:
            # Yellow for moderate signal
            return f"\033[93m{rssi}\033[0m"
        else:
            # Red for weak signal
            return f"\033[91m{rssi}\033[0m"
    
    def scan_networks(self) -> bool:
        """Scan for WiFi networks and display them.

        Returns:
            bool: True if successful, False otherwise
        """
        self.log.info("Scanning for networks...")

        # Scan for networks
        try:
            scan_results, error = self.cwlan_interface.scanForNetworksWithName_error_(None, None)
            if error:
                error_str = str(error)

                # Check for "Resource busy" error (NSPOSIXErrorDomain Code=16)
                if "Code=16" in error_str or "Resource busy" in error_str:
                    self.log.warning("WiFi interface is busy (likely connected to a network)")

                    # Get current SSID
                    current_ssid = self.cwlan_interface.ssid()
                    if current_ssid:
                        self.log.warning(f"Currently connected to: '{current_ssid}'")

                    # Ask user if they want to disconnect
                    print("\n" + "="*70)
                    print("⚠️  WiFi Interface Busy")
                    print("="*70)
                    print("\nThe WiFi interface is currently in use.")
                    if current_ssid:
                        print(f"Connected to: {current_ssid}")
                    print("\nTo scan for networks, we need to disconnect temporarily.")
                    print("You can reconnect after the scan completes.")
                    print("\nDisconnect and continue? [y/N]: ", end="", flush=True)

                    try:
                        user_input = input().strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        print("\nAborted by user")
                        return False

                    if user_input == 'y':
                        # Disconnect from network
                        success, saved_ssid = self.disconnect_from_network()
                        if not success:
                            self.log.error("Failed to disconnect from network")
                            return False

                        # Store the SSID for later reconnection
                        self.saved_ssid = saved_ssid

                        # Wait longer for interface to become free (macOS needs time to release the interface)
                        self.log.info("Waiting for interface to become available...")
                        sleep(5)

                        # Try scanning with retries
                        max_retries = 3
                        scan_results = None
                        error = None

                        for retry in range(max_retries):
                            if retry > 0:
                                self.log.info(f"Retry {retry}/{max_retries-1}...")
                                sleep(3)

                            scan_results, error = self.cwlan_interface.scanForNetworksWithName_error_(None, None)

                            if error:
                                error_str = str(error)
                                if "Code=16" in error_str or "Resource busy" in error_str:
                                    # Still busy, try again
                                    if retry < max_retries - 1:
                                        continue
                                    else:
                                        self.log.error("Interface still busy after disconnect and retries")
                                        self.log.error("This may be a macOS system issue.")
                                        self.log.error("\nWorkaround:")
                                        self.log.error("1. Manually turn off WiFi in System Settings")
                                        self.log.error("2. Wait 5 seconds")
                                        self.log.error("3. Turn WiFi back on")
                                        self.log.error("4. Run this tool again")
                                        return False
                                else:
                                    # Different error
                                    self.log.error(f"Error scanning after disconnect: {error}")
                                    return False
                            else:
                                # Success!
                                break

                        if error:
                            return False
                    else:
                        self.log.info("Scan cancelled by user")
                        print("\nAlternatives:")
                        print("1. Manually disconnect from WiFi in System Settings")
                        print("2. Use 'networksetup -setairportpower <interface> off' to disable WiFi")
                        print("3. Run this tool when not connected to any network")
                        return False
                else:
                    # Different error
                    self.log.error(f"Error scanning for networks: {error}")
                    return False
        except Exception as e:
            self.log.error(f"Exception during network scan: {e}")
            return False

        # Parse scan results and display in a table
        table = PrettyTable(['Number', 'Name', 'BSSID', 'RSSI', 'Channel', 'Security'])
        self.networks = []

        if scan_results is not None and len(scan_results) > 0:
            for result in scan_results:
                try:
                    # Store relevant network information
                    security_match = re.search(r'security=(.*?)(,|$)', str(result))
                    security = security_match.group(1) if security_match else "Unknown"

                    # BSSID may be None on macOS 15+/26 (CoreWLAN redaction);
                    # keep the entry and recover the BSSID via monitor mode
                    # after the scan instead of dropping it here.
                    bssid = result.bssid()

                    # wlanChannel() returns a CWChannel object; channelNumber() extracts
                    # the integer. result.channel() is deprecated and returns a CWChannel
                    # object (not an int) on macOS 14+, which breaks PrettyTable display.
                    cw_channel = result.wlanChannel()
                    network_info = {
                        'ssid': result.ssid() or "<hidden>",
                        'bssid': bssid,
                        'rssi': result.rssiValue(),
                        'channel_object': cw_channel,
                        'channel_number': cw_channel.channelNumber() if cw_channel else '-',
                        'security': security
                    }
                    self.networks.append(network_info)
                except Exception as e:
                    self.log.warning(f"Error parsing network: {e}")
                    continue

            # Recover BSSIDs that CoreWLAN redacted to None (macOS 15+/26).
            missing = [n for n in self.networks if not n['bssid']]
            if missing and self._is_macos_15_plus():
                self.log.info(f"{len(missing)}/{len(self.networks)} network(s) have no "
                              "BSSID (macOS redaction); recovering via monitor mode...")
                chans = sorted({n['channel_number'] for n in self.networks
                                if isinstance(n['channel_number'], int)})
                recovered = self._recover_bssids_via_monitor(chans)
                if recovered:
                    self._merge_recovered_bssids(recovered)

            # Drop entries whose BSSID could not be resolved — capture needs it.
            unresolved = [n for n in self.networks if not n['bssid']]
            if unresolved:
                self.log.warning(f"{len(unresolved)} network(s) had no obtainable BSSID "
                                 "and were hidden from the list.")
                self.networks = [n for n in self.networks if n['bssid']]

            if not self.networks:
                self.log.error("No networks with a usable BSSID were found.")
                if self._is_macos_15_plus():
                    self.log.error("Monitor-mode recovery returned nothing — make sure "
                                   "Wi-Fi is on, then re-run (it needs sudo).")
                return False

            # Sort by RSSI descending; guard against None (some entries return None
            # for rssiValue() when the scan result is partially formed).
            self.networks = sorted(
                self.networks,
                key=lambda x: x['rssi'] if x['rssi'] is not None else -999,
                reverse=True
            )

            # Add sorted networks to table
            for i, network in enumerate(self.networks):
                colorized_rssi = self.colorize_rssi(network['rssi'])
                table.add_row([
                    i + 1, 
                    network['ssid'], 
                    network['bssid'], 
                    colorized_rssi, 
                    network['channel_number'], 
                    network['security']
                ])
                
            print("\n" + str(table))
            return True
        else:
            self.log.error("No networks found or an error occurred.")
            return False
    
    def select_network(self) -> int:
        """Let user select a network to crack.

        Returns:
            int: Index of selected network, -1 if canceled, -2 if retry requested
        """
        if not self.networks:
            self.log.error("No networks available to select.")
            return -1

        try:
            if self.args.network_index is not None:
                x = int(self.args.network_index) - 1
                if x < 0 or x >= len(self.networks):
                    self.log.error(f"Invalid network index: {x+1}. Must be between 1 and {len(self.networks)}")
                    return -1
            else:
                user_input = input('\nSelect a network (1-{}, r=rescan, q=quit): '.format(len(self.networks))).strip().lower()

                # Check for quit
                if user_input == 'q':
                    self.log.info("Operation canceled by user.")
                    return -1

                # Check for retry
                if user_input == 'r':
                    self.log.info("Rescanning for networks...")
                    return -2

                # Try to parse as number
                try:
                    x = int(user_input) - 1
                    if x < 0 or x >= len(self.networks):
                        self.log.error(f"Invalid selection. Must be between 1 and {len(self.networks)}")
                        return -1
                    return x
                except ValueError:
                    self.log.error("Invalid input. Enter a number (1-{}), 'r' to rescan, or 'q' to quit.".format(len(self.networks)))
                    return -1

            return x
        except (ValueError, EOFError, KeyboardInterrupt):
            self.log.error("\nInvalid input or interrupted.")
            return -1
    
    def capture_network(self, bssid: str, channel) -> bool:
        """Capture a WPA/WPA2 handshake for the selected network.

        Lifecycle
        ---------
        1. Disassociate from current network (CoreWLAN) so the interface is free.
        2. Tune the interface to the target channel via CoreWLAN
           setWLANChannel_error_() — must happen *before* RFMON is activated
           because pcap_activate() takes over the interface.
        3. Build and launch the capture backend (AirSnare or zizzania) via sudo.
           AirSnare activates RFMON, optionally sends deauth frames, and writes
           captured frames to a pcap file.
        4. Stream AirSnare's stderr output (merged into stdout) in real-time
           through a daemon reader thread → queue to avoid blocking the timeout
           check (see _enqueue_output inner function).
        5. After AirSnare exits (handshake captured, Ctrl-C, or timeout), convert
           the pcap to hashcat-22000 format using hcxpcapngtool.

        AirSnare log-level note
        -----------------------
        AirSnare's default log level is ERROR (0 — only [!] messages).
        We always pass at least -v (INFO level, [+] messages) so "New client"
        and "^_^ Full handshake" events appear in the output stream.  With
        --verbose, -vvv is passed to also surface DEBUG-level deauth events.

        Args:
            bssid:   Target AP BSSID string (e.g. "AA:BB:CC:DD:EE:FF").
            channel: CWChannel object returned by CWNetwork.wlanChannel().
                     Used for CoreWLAN channel tuning and, when channelNumber()
                     is extractable, passed as -c <n> to AirSnare.

        Returns:
            True if a handshake was captured and converted successfully.
        """
        try:
            # Step 1: Disassociate.  CoreWLAN requires the interface to be
            # disassociated before setWLANChannel_error_() can change the channel.
            self.cwlan_interface.disassociate()

            # Step 2: Set the channel
            self.cwlan_interface.setWLANChannel_error_(channel, None)

            # Determine the network interface
            iface = self.resolve_interface()
            if not iface:
                self.log.error("No WiFi interface detected.")
                return False
            self.log.info(f"Using interface: {iface}")

            self.log.info(f"Initiating handshake capture on BSSID: {bssid}")

            if self.args.dry_run:
                self.log.info("DRY RUN: Would run airsnare capture (skipped)")
                return True

            # Explain what's happening
            print("\n" + "="*70)
            print("Waiting for WPA Handshake")
            print("="*70)
            print("\nAirSnare is now listening for a handshake. This happens when:")
            print("  1. A client connects to the network")
            print("  2. A client reconnects after disconnection")

            if not self.args.deauth:
                print("\n⚠️  Deauth is DISABLED (-n flag)")
                print("  - Waiting passively for clients to connect naturally")
                print("  - This can take 5-30 minutes or longer")
                print("  - Recommendation: Enable deauth with -d flag for faster capture")
            else:
                print("\n✓ Deauth is ENABLED")
                print("  - Actively disconnecting clients to force reconnection")
                print("  - Handshake should be captured within 1-5 minutes")
                # Warn on Apple Silicon macOS — built-in Wi-Fi does not support pcap_inject().
                # Note: platform.machine() == 'arm64' also matches Linux ARM (Raspberry Pi),
                # so the additional Darwin check is required to avoid false positives.
                if platform.system() == 'Darwin' and platform.machine() == 'arm64':
                    print("\n⚠️  WARNING: Apple Silicon detected")
                    print("  Packet injection (deauth) is NOT supported on the built-in Wi-Fi")
                    print("  adapter of Apple Silicon Macs. AirSnare will likely exit with an")
                    print("  injection error.")
                    print("  → Use passive mode (omit -d) or an external USB Wi-Fi adapter.")

            print("\nPress Ctrl+C to abort capture")
            print("="*70 + "\n")

            # Build the command with verbose output
            channel_number = None
            try:
                if hasattr(channel, 'channelNumber'):
                    cn_attr = channel.channelNumber
                    channel_number = cn_attr() if callable(cn_attr) else cn_attr
                elif isinstance(channel, int):
                    channel_number = channel
            except Exception:
                channel_number = None

            # On macOS, CoreWLAN already set the channel before this subprocess
            # starts (see setWLANChannel_error_() call above).  Passing -c to
            # the capture tool triggers its own channel-setting logic which
            # calls networksetup / airport — both removed / broken on macOS 15+.
            # Skip -c on macOS; the interface is already on the right channel.
            pass_channel = channel_number and platform.system() != 'Darwin'

            if self.capture_tool == 'zizzania':
                cmd = [
                    'sudo', self.capture_path,
                    '-i', iface,
                    '-b', bssid,
                    '-w', self.capture_file,
                ]
                if pass_channel:
                    cmd.extend(['-c', str(channel_number)])
                if not self.args.deauth:
                    cmd.append('-n')  # passive mode -> no deauth
                if self.args.verbose:
                    cmd.append('-v')
            else:
                cmd = [
                    'sudo', self.capture_path,
                    '-i', iface,
                    '-b', bssid,
                    '-w', self.capture_file,
                ]
                if pass_channel:
                    cmd.extend(['-c', str(channel_number)])
                if not self.args.deauth:
                    # Passive mode: pass ONLY -n. AirSnare treats -n together with
                    # any CLI deauth option (-d/-a/-t) as contradictory and exits.
                    # Its conflict check keys on whether those flags appear on the
                    # command line, not on the resulting state, so config-file
                    # deauth values are ignored under -n and never trigger it.
                    # (Older AirSnare keyed on state, so we used to pass the
                    # defaults explicitly to override ~/.airsnarerc. That
                    # workaround now causes the very conflict it once avoided —
                    # see issue #12.)
                    cmd.append('-n')
                # AirSnare default log level is ERROR (0); -v raises it to INFO (1)
                # which is required to see "New client" and "^_^ Full handshake" events.
                # With AirJack verbose, add -vvv to also see deauth debug messages.
                if self.args.verbose:
                    cmd.append('-vvv')
                else:
                    cmd.append('-v')

            if self.args.verbose:
                self.log.debug(f"Running command: {' '.join(cmd)}")

            # Cache sudo credentials before we lose the controlling terminal.
            # start_new_session=True (used below) calls setsid(), which detaches
            # the child from the controlling tty so sudo cannot prompt for a
            # password.  Running "sudo -v" here — while we still own the tty —
            # refreshes the credential cache so the subsequent sudo invocation
            # succeeds without prompting.
            self.log.info("Requesting sudo credentials for capture tool...")
            ret = subprocess.run(['sudo', '-v'])
            if ret.returncode != 0:
                self.log.error("sudo authentication failed; cannot start capture.")
                return

            # Launch AirSnare and stream its output.
            #
            # Design note — why a reader thread instead of readline() in a loop:
            # readline() is a blocking call. During passive captures with no nearby
            # clients, AirSnare can run silently for minutes. A blocking readline()
            # in the main loop makes the timeout check unreachable and causes the
            # tool to appear frozen. A daemon reader thread drains stdout into a
            # queue; the main loop uses queue.get(timeout=0.5) which unblocks every
            # 0.5 s so the elapsed-time check always fires on schedule.
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # merge stderr into stdout pipe
                    text=True,
                    bufsize=1,                 # line-buffered (requires text=True)
                    universal_newlines=True,
                    preexec_fn=os.setpgrp,     # new process group (not session) → killpg works, /dev/tty preserved for sudo
                )

                # Background reader thread: drain stdout → queue until EOF.
                output_queue: queue.Queue = queue.Queue()

                def _enqueue_output(stream: Any, q: queue.Queue) -> None:
                    """Push lines from *stream* to *q*; sentinel None signals EOF."""
                    try:
                        for raw in iter(stream.readline, ''):
                            q.put(raw)
                    finally:
                        q.put(None)  # EOF sentinel consumed by main loop

                reader = threading.Thread(
                    target=_enqueue_output,
                    args=(process.stdout, output_queue),
                    daemon=True,   # killed automatically when main thread exits
                )
                reader.start()

                # Session state for diagnostics and early-exit decisions.
                timeout_seconds = 600   # 10-minute cap; configurable in future
                start_time = time.time()
                clients_seen: set = set()
                deauth_sent = 0
                handshake_found = False

                print(f"[INFO] Capture timeout: {timeout_seconds // 60} minutes\n")

                # Main output/timeout loop.
                # queue.get(timeout=0.5) blocks for at most 0.5 s, so the elapsed
                # check fires every half-second even when AirSnare is quiet.
                while True:
                    elapsed = time.time() - start_time
                    if elapsed > timeout_seconds:
                        print(f"\n[TIMEOUT] Capture exceeded {timeout_seconds // 60} minutes")
                        print("\n" + "="*70)
                        print("Diagnostics:")
                        print("="*70)
                        print(f"  • Clients discovered: {len(clients_seen)}")
                        print(f"  • Deauth frames sent: {deauth_sent}")
                        print(f"  • Handshake captured: {handshake_found}")

                        if deauth_sent == 0 and self.args.deauth:
                            print("\n⚠️  WARNING: No deauth frames were sent!")
                            print("  Possible causes:")
                            print("  1. AirSnare lacks permissions for packet injection")
                            print("  2. macOS interface doesn't support injection")
                            print("  3. Clients are not responding to deauth")
                        elif len(clients_seen) == 0:
                            print("\n⚠️  WARNING: No clients discovered!")
                            print("  The network may have no active clients")
                        else:
                            print("\n⚠️  Clients seen but no handshake captured")
                            print("  Possible causes:")
                            print("  1. Clients are not reconnecting")
                            print("  2. Handshake packets are being missed")
                            print("  3. Network uses WPA3-only (not supported)")

                        print("\nRecommendations:")
                        print("  • Try again during peak hours (more client activity)")
                        print("  • Ensure you're close to the access point")
                        print("  • Check if network is WPA2 (not WPA3-only)")
                        print("="*70)

                        try:
                            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait()
                        return False

                    # Try to fetch the next line; yield control after 0.5 s if
                    # no output arrived (allows the timeout check above to fire).
                    try:
                        raw_line = output_queue.get(timeout=0.5)
                    except queue.Empty:
                        # No output yet; bail out if AirSnare already exited.
                        if process.poll() is not None:
                            break
                        continue

                    if raw_line is None:   # EOF sentinel from reader thread
                        break

                    line = raw_line.rstrip()
                    print(f"[{self.capture_tool}] {line}")

                    # --- Parse AirSnare diagnostic output ---
                    #
                    # AirSnare writes to stderr; we redirect it to stdout via
                    # stderr=STDOUT. When output is a pipe (not a TTY), AirSnare
                    # omits ANSI colours, so prefixes are plain ASCII:
                    #
                    #   [+] message   INFO  level (visible with -v or higher)
                    #   [*] message   DEBUG level (visible with -vvv or higher)
                    #   [!] message   ERROR level (always visible)
                    #
                    # Source references are to the AirSnare C source.

                    # "[+] New client AA:BB:CC:DD:EE:FF @ CC:DD:... $'SSID'"
                    # dissector.c: zz_info("New client %s @ %s $'%s'", station, bssid, ssid)
                    # parts[3] is the station MAC address.
                    if 'New client' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            clients_seen.add(parts[3])

                    # "[*] Deauthenticating AA:BB:... @ CC:DD:..."
                    # killer.c: zz_debug("Deauthenticating %s @ %s", station, bssid)
                    # Only visible when -vvv is passed (DEBUG level).
                    elif 'Deauthenticating' in line:
                        deauth_sent += 1

                    # "[+] ^_^ Full handshake for AA:BB:... @ CC:DD:... $'SSID'"
                    # "[+] ^_^ PMKID for AA:BB:... @ CC:DD:... $'SSID': WPA*01*..."
                    # dissector.c: zz_info("^_^ Full handshake ...") / zz_info("^_^ PMKID ...")
                    elif '^_^ Full handshake' in line or '^_^ PMKID' in line:
                        handshake_found = True
                        print("\n✓ HANDSHAKE CAPTURED! Finishing capture...")

                    # "[!] Packet injection failed (...) — built-in Wi-Fi adapters on macOS
                    #      do not support monitor-mode injection; use passive mode (-n) or
                    #      an external USB adapter"
                    # killer.c: zz_error() on pcap_inject() failure
                    elif 'Packet injection failed' in line:
                        print("\n⚠️  Packet injection not supported on this adapter.")
                        print("   Use passive mode (remove -d flag) or an external USB Wi-Fi adapter.")
                        print("   See: https://github.com/rtulke/airsnare#packet-injection-deauth")

                # AirSnare exited normally (EOF on stdout).
                return_code = process.wait()
                if return_code != 0:
                    self.log.error(f"AirSnare exited with code {return_code}")
                    return False

            except KeyboardInterrupt:
                self.log.warning("\nCapture interrupted by user")
                # process.terminate() only signals the sudo wrapper, leaving
                # the airsnare child orphaned in RFMON mode. Kill the entire
                # process group (sudo + airsnare) so nothing is left behind.
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                return False

            # Check if capture file was created
            if not exists(self.capture_file):
                self.log.error(f"Capture file was not created: {self.capture_file}")
                self.log.error("This may indicate that no handshake was captured.")
                return False

            # Convert the capture to hashcat-22000 format.
            # hcxpcapngtool path was resolved in setup_tools() at startup to avoid
            # discovering a missing binary after a 10-minute capture session.
            self.log.info("Converting capture to hashcat format...")
            conv_cmd = [self.hcxpcapngtool_path, '-o', self.hashcat_file, self.capture_file]

            if self.args.verbose:
                self.log.debug(f"Running command: {' '.join(conv_cmd)}")

            process = subprocess.run(
                conv_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if process.returncode != 0:
                self.log.error(f"Conversion error: {process.stderr}")
                return False

            # Verify the hashcat file was created
            if not exists(self.hashcat_file):
                self.log.error(f"Hashcat file was not created: {self.hashcat_file}")
                self.log.error("Possible reasons:")
                self.log.error("1. No valid handshake was captured in the pcap file")
                self.log.error("2. The capture file format is incorrect")
                self.log.error("3. hcxpcapngtool encountered an error")
                if self.args.verbose:
                    self.log.error(f"hcxpcapngtool output: {process.stdout}")
                return False

            self.log.info("Handshake ready for cracking.")
            return True
            
        except Exception as e:
            self.log.error(f"Error during capture: {e}")
            return False
    
    def crack_capture(self) -> bool:
        """Crack the captured handshake.
        
        Returns:
            bool: True if successful, False otherwise
        """
        # Check if capture file exists
        if not exists(self.hashcat_file):
            self.log.error(f"Capture file not found: {self.hashcat_file}")
            return False
            
        # Ask user to select a cracking method from menu
        if self.args.mode is None:
            options = PrettyTable(['Number', 'Mode'])
            modes = ['Dictionary', 'Brute-force', 'Manual']
            for i, mode in enumerate(modes):
                options.add_row([i + 1, mode])
            print("\n" + str(options))
            
            try:
                method = int(input('\nSelect an attack mode: '))
                if method < 1 or method > 3:
                    self.log.error("Invalid selection")
                    return False
            except ValueError:
                self.log.error("Invalid input. Please enter a number.")
                return False
        else:
            method = int(self.args.mode)
        
        # Get the wordlist or pattern
        if method == 1:  # Dictionary attack
            if self.args.wordlist is None:
                wordlist = input('\nInput a wordlist path: ')
                if not exists(wordlist):
                    self.log.error(f"Wordlist not found: {wordlist}")
                    return False
            else:
                wordlist = self.args.wordlist
                if not exists(wordlist):
                    self.log.error(f"Wordlist not found: {wordlist}")
                    return False
                    
            self.log.info(f"Starting dictionary attack using: {wordlist}")
            
            if self.args.dry_run:
                self.log.info("DRY RUN: Would run hashcat dictionary attack (skipped)")
                return True
                
            # Build command
            cmd = [self.hashcat_path, '-m', '22000', self.hashcat_file, wordlist]
            if self.args.optimize:
                cmd.append('-O')
                
            # Run hashcat for dictionary attack
            return self._run_hashcat(cmd)
            
        elif method == 2:  # Brute-force attack
            # Get the brute-force pattern
            if self.args.pattern is None:
                pattern = input('\nInput a brute-force pattern: ')
            else:
                pattern = self.args.pattern
                
            self.log.info(f"Starting brute-force attack using pattern: {pattern}")
            
            if self.args.dry_run:
                self.log.info("DRY RUN: Would run hashcat brute-force attack (skipped)")
                return True
                
            # Build command
            cmd = [self.hashcat_path, '-m', '22000', '-a', '3', self.hashcat_file, pattern]
            if self.args.optimize:
                cmd.append('-O')
                
            # Run hashcat for brute-force attack
            return self._run_hashcat(cmd)
            
        elif method == 3:  # Manual mode
            self.log.info(f"Manual mode selected. Run hashcat against: {self.hashcat_file}")
            print(f"\nRun hashcat against: {self.hashcat_file}")
            print(f"Example command: {self.hashcat_path} -m 22000 {self.hashcat_file} <wordlist>")
            return True
            
        return False
    
    def _run_hashcat(self, cmd: List[str]) -> bool:
        """Run hashcat with the given command.
        
        Args:
            cmd: Hashcat command to run
            
        Returns:
            bool: True if successful, False otherwise
        """
        if self.args.verbose:
            self.log.debug(f"Running command: {' '.join(cmd)}")
            
        try:
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE if not self.args.verbose else None,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if process.returncode != 0 and process.returncode != 1:
                # Return code 1 is often used by hashcat to indicate normal completion
                self.log.error(f"Hashcat error (code {process.returncode}): {process.stderr}")
                return False
                
            return True
            
        except Exception as e:
            self.log.error(f"Error running hashcat: {e}")
            return False
    
    def cleanup(self) -> None:
        """Clean up sensitive files."""
        if self.args.cleanup:
            sensitive_files = [self.capture_file, self.hashcat_file]
            for file in sensitive_files:
                if exists(file):
                    try:
                        os.remove(file)
                        self.log.info(f"Removed file: {file}")
                    except Exception as e:
                        self.log.error(f"Failed to remove {file}: {e}")
    
    def run(self) -> int:
        """Run the main program flow.

        Returns:
            int: Exit code (0 for success, non-zero for failure)
        """
        exit_code = 1  # Default to error

        try:
            # Request location permission for WiFi scanning
            if not self.request_location_permission():
                return 1

            # Scan for networks (with retry loop)
            while True:
                if not self.scan_networks():
                    return 1

                # Select a network
                network_idx = self.select_network()

                if network_idx == -2:
                    # User requested rescan
                    continue
                elif network_idx < 0:
                    # User canceled
                    return 1
                else:
                    # Valid selection, break out of loop
                    break

            # Capture handshake
            selected_network = self.networks[network_idx]
            self.log.info(f"Selected network: {selected_network['ssid']} ({selected_network['bssid']})")

            if not self.capture_network(selected_network['bssid'], selected_network['channel_object']):
                return 1

            # Crack the capture
            if not self.crack_capture():
                return 1

            # Clean up if requested
            self.cleanup()

            exit_code = 0  # Success
            return exit_code

        finally:
            # Always attempt reconnection if we disconnected
            if self.saved_ssid:
                print("\n" + "="*70)
                print("Reconnect to Original Network")
                print("="*70)
                print(f"\nYou were disconnected from: {self.saved_ssid}")
                print("Would you like to reconnect now? [Y/n]: ", end="", flush=True)

                try:
                    user_input = input().strip().lower()
                    # Default to yes if user just presses Enter
                    if user_input in ['', 'y', 'yes']:
                        self.reconnect_to_network(self.saved_ssid)
                    else:
                        print("Skipping reconnection - you can manually reconnect via System Settings")
                except (KeyboardInterrupt, EOFError):
                    print("\nSkipping reconnection - you can manually reconnect via System Settings")


def setup_argparse() -> argparse.ArgumentParser:
    """Set up argument parser with all available options.
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="AirJack is a WiFi Security Testing Tool for macOS",
        epilog="WARNING: Only use on networks you own or have explicit permission to test!"
    )
    
    # Config file options
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument('-c', '--config', 
                      help='Path to configuration file')
    config_group.add_argument('-C', '--create-config', metavar='PATH',
                      help='Create a default configuration file at the specified path')
    
    # Tool paths
    parser.add_argument('--hashcat-path', default=None,
                      help='Path to hashcat executable (default: from config or ~/hashcat/hashcat)')
    parser.add_argument('--airsnare-path', default=None,
                      help='Path to airsnare executable (default: from config or ~/airsnare/src/airsnare)')
    parser.add_argument('--zizzania-path', default=None,
                      help='Path to zizzania executable (default: from config or ~/zizzania/src/zizzania)')
    parser.add_argument('--capture-tool', choices=['airsnare', 'zizzania'], default=None,
                      help='Capture backend to use (default: auto; prefers zizzania if present)')
    
    # Network selection
    parser.add_argument('-i', '--interface', default=None,
                      help='Network interface to use (default: from config or auto-detect)')
    parser.add_argument('-n', '--network-index', type=int, default=None,
                      help='Select network by index (skips interactive selection)')

    # Capture options
    parser.add_argument('-d', '--deauth', action='store_true',
                      help='Enable deauthentication (default: from config or disabled)')
    parser.add_argument('--capture-file', default=None,
                      help='Output capture file (default: from config or capture.pcap)')
    parser.add_argument('--hashcat-file', default=None,
                      help='Output hashcat file (default: from config or capture.hc22000)')
    
    # Cracking options
    parser.add_argument('-m', '--mode', type=int, choices=[1, 2, 3], default=None,
                      help='Attack mode: 1=Dictionary, 2=Brute-force, 3=Manual')
    parser.add_argument('-w', '--wordlist', default=None,
                      help='Path to wordlist for dictionary attack')
    parser.add_argument('-p', '--pattern', default=None,
                      help='Pattern for brute-force attack')
    parser.add_argument('-o', '--optimize', action='store_true',
                      help='Enable hashcat optimization (default: from config or disabled)')

    # Misc options
    parser.add_argument('--auth-timeout', type=int, default=None,
                      help='Timeout for location authorization (default: from config or 60 seconds)')
    parser.add_argument('--cleanup', action='store_true',
                      help='Clean up sensitive files after completion (default: from config or disabled)')
    parser.add_argument('--dry-run', action='store_true',
                      help='Simulate actions without running external tools')
    parser.add_argument('--ignore-missing', action='store_true',
                      help='Ignore missing tools and continue')
    parser.add_argument('--no-banner', action='store_true',
                      help='Disable banner display')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose output (default: from config or disabled)')

    # Internal: monitor-mode BSSID recovery (re-invoked under sudo). Hidden.
    parser.add_argument('--mon-bssid-scan', action='store_true',
                      help=argparse.SUPPRESS)
    parser.add_argument('--mon-channels', default=None,
                      help=argparse.SUPPRESS)

    return parser


def main() -> int:
    """Main entry point for the program.
    
    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Internal subcommand: run the monitor-mode BSSID scan (as root) and emit a
    # single JSON line for the parent process. Handled before anything prints.
    if getattr(args, 'mon_bssid_scan', False):
        return _run_mon_bssid_scan_cli(args)

    # Handle config file creation if requested
    if args.create_config:
        config_manager = ConfigManager()
        if config_manager.create_default_config(args.create_config):
            print(f"Default configuration created at: {os.path.expanduser(args.create_config)}")
            return 0
        else:
            print(f"Failed to create configuration file at: {args.create_config}")
            return 1
    
    try:
        cracker = WiFiCracker(args)
        return cracker.run()
    except KeyboardInterrupt:
        print("\nOperation canceled by user.")
        return 1
    except Exception as e:
        print(f"Unhandled error: {e}")
        if hasattr(args, 'verbose') and args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
