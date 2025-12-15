#!/usr/bin/env python3
# connect.py

"""
WiFi Monitor Mode Recovery Tool for macOS
Restores WiFi interface from monitor mode and reconnects to network

Note: Uses airport utility for network scanning (deprecated but no alternative exists)
      Uses wdutil for WiFi diagnostics and info (modern tool)

Usage:
    sudo ./connect.py                           # Auto-connect to preferred network
    sudo ./connect.py -s "MyNetwork"            # Connect with password prompt
    sudo ./connect.py -s "MyNetwork" -p "pass"  # Connect with password
    sudo ./connect.py --scan                    # Scan for networks
"""

import subprocess
import sys
import os
import time
import argparse
import getpass
from pathlib import Path

COREWLAN_AVAILABLE = False
try:
    import CoreWLAN
    COREWLAN_AVAILABLE = True
except Exception:
    COREWLAN_AVAILABLE = False

# Constants
AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
WDUTIL_PATH = "/usr/bin/wdutil"
DEFAULT_INTERFACE = "en0"

# Note: airport is deprecated but still needed for network scanning
# wdutil has no scan functionality - only info, diagnose, log, dump, clean


def check_root():
    """Check if script is running with root privileges"""
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        print("[*] Please run: sudo python3 connect.py")
        sys.exit(1)


def run_command(cmd, check=True):
    """Execute shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=check
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.CalledProcessError as e:
        return "", str(e), e.returncode


def get_wifi_interface():
    """Detect WiFi interface name"""
    stdout, _, _ = run_command("networksetup -listallhardwareports | grep -A1 Wi-Fi | grep Device | awk '{print $2}'")
    return stdout if stdout else DEFAULT_INTERFACE


def is_monitor_mode(interface):
    """Check if interface is in monitor mode"""
    stdout, _, _ = run_command(f"ifconfig {interface} | grep -i monitor", check=False)
    
    if "monitor" in stdout.lower():
        print(f"[!] {interface} is in monitor mode")
        return True
    
    # Additional check via media type
    stdout, _, _ = run_command(f"ifconfig {interface} | grep 'media:'", check=False)
    if "monitor" in stdout.lower():
        print(f"[!] {interface} is in monitor mode")
        return True
    
    return False


def is_connected(interface):
    """Check if WiFi is already connected using multiple methods"""
    
    # Method 1: networksetup
    stdout, _, code = run_command(f"networksetup -getairportnetwork {interface}", check=False)
    
    if code == 0 and "Current Wi-Fi Network:" in stdout:
        ssid = stdout.split("Current Wi-Fi Network:")[1].strip()
        if ssid and "not associated" not in ssid.lower():
            print(f"[+] Already connected to: {ssid}")
            return True
    
    # Method 2: ifconfig - check for inet address and status
    ifconfig_out, _, _ = run_command(f"ifconfig {interface}", check=False)
    
    has_ip = "inet " in ifconfig_out and "127.0.0.1" not in ifconfig_out
    is_active = "status: active" in ifconfig_out
    
    if has_ip and is_active:
        # Extract IP
        for line in ifconfig_out.split('\n'):
            if 'inet ' in line and 'inet6' not in line:
                ip = line.strip().split()[1]
                
                # Try to get SSID via wdutil
                if Path(WDUTIL_PATH).exists():
                    wdutil_out, _, _ = run_command(f"{WDUTIL_PATH} info", check=False)
                    for wline in wdutil_out.split('\n'):
                        if 'SSID' in wline and ':' in wline:
                            ssid = wline.split(':')[1].strip()
                            if ssid and ssid != "None":
                                print(f"[+] Already connected to: {ssid} (IP: {ip})")
                                return True
                
                print(f"[+] WiFi is active with IP: {ip}")
                return True
    
    return False


def disable_monitor_mode(interface):
    """Disable monitor mode on WiFi interface"""
    print(f"[*] Disabling monitor mode on {interface}...")
    
    # Try using wdutil (modern approach)
    if Path(WDUTIL_PATH).exists():
        stdout, stderr, code = run_command(f"{WDUTIL_PATH} diagnose --no-upload", check=False)
        if code == 0:
            print("[+] Monitor mode disabled via wdutil")
            time.sleep(1)
    
    # Fallback: restart interface
    print("[*] Restarting interface...")
    run_command(f"ifconfig {interface} down", check=False)
    time.sleep(1)
    run_command(f"ifconfig {interface} up", check=False)
    time.sleep(2)
    
    return True


def enable_wifi(interface):
    """Enable WiFi power"""
    print(f"[*] Enabling WiFi on {interface}...")
    stdout, stderr, code = run_command("networksetup -setairportpower en0 on")
    
    if code == 0:
        print("[+] WiFi enabled")
        time.sleep(2)
        return True
    else:
        print(f"[!] Failed to enable WiFi: {stderr}")
        return False


def get_preferred_networks():
    """Get list of preferred networks"""
    stdout, _, _ = run_command("networksetup -listpreferredwirelessnetworks en0")
    networks = []
    
    for line in stdout.split('\n')[1:]:  # Skip header
        network = line.strip()
        if network:
            networks.append(network)
    
    return networks


def is_network_in_range(interface, ssid):
    """Check if SSID is in range using airport"""
    if not Path(AIRPORT_PATH).exists():
        return None  # Cannot determine
    
    # Suppress deprecation warning with 2>/dev/null
    stdout, _, code = run_command(f"{AIRPORT_PATH} -s 2>/dev/null", check=False)
    
    if code == 0 and ssid in stdout:
        return True
    
    return False


def scan_networks(interface):
    """Scan for available networks.

    Prefers CoreWLAN (no deprecated airport usage). Falls back to airport if CoreWLAN
    is unavailable, and finally suggests WiFi Diagnostics.
    """
    print("[*] Scanning for networks...")

    # Preferred: CoreWLAN (no deprecation warnings)
    if COREWLAN_AVAILABLE:
        try:
            client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
            cw_iface = client.interface()
            networks, error = cw_iface.scanForNetworksWithName_error_(None, None)
            if error:
                print(f"[!] CoreWLAN scan error: {error}")
            elif networks and len(networks) > 0:
                # Collect rows to size columns dynamically
                rows = []
                for net in networks:
                    ssid = net.ssid() or "<hidden>"
                    bssid = net.bssid() or "-"
                    rssi = net.rssiValue()
                    ch = net.wlanChannel().channelNumber() if net.wlanChannel() else "-"
                    rows.append((ssid, bssid, rssi, ch))

                # Column widths (bounded)
                id_w = max(2, len(str(len(rows))))
                ssid_w = min(32, max(8, len("SSID"), max(len(r[0]) for r in rows)))
                bssid_w = max(len("BSSID"), 17)
                rssi_w = max(len("RSSI"), 4)
                ch_w = max(len("CH"), 3)

                print("[+] Available networks (CoreWLAN):")
                header = (
                    f"    {'ID':<{id_w}} "
                    f"{'SSID':<{ssid_w}} "
                    f"{'BSSID':<{bssid_w}} "
                    f"{'RSSI':>{rssi_w}}  "
                    f"{'CH':<{ch_w}}"
                )
                print(header)
                print("    " + "-" * (len(header) - 4))

                for idx, (ssid, bssid, rssi, ch) in enumerate(rows, start=1):
                    print(
                        f"    {idx:<{id_w}} "
                        f"{ssid:<{ssid_w}} "
                        f"{bssid:<{bssid_w}} "
                        f"{rssi:>{rssi_w}}  "
                        f"{ch:<{ch_w}}"
                    )
                    if idx >= 50:
                        print("    ... (truncated)")
                        break
                return "corewlan"
        except Exception as e:
            print(f"[!] CoreWLAN scan failed: {e}")

    # Fallback: airport (deprecated, may stop working)
    if Path(AIRPORT_PATH).exists():
        print("[*] CoreWLAN unavailable or failed, falling back to airport (deprecated)...")
        stdout, stderr, code = run_command(f"{AIRPORT_PATH} -s 2>/dev/null", check=False)

        if code == 0 and stdout:
            lines = stdout.strip().split('\n')

            if len(lines) > 0:
                print("[+] Available networks (airport):")

                for i, line in enumerate(lines[:20]):  # Show first 20 networks
                    if i == 0:
                        print(f"    {line}")
                        print("    " + "-" * 80)
                    else:
                        if line.strip():
                            print(f"    {line}")

                if len(lines) > 20:
                    print(f"\n    ... and {len(lines) - 20} more networks")

                return "airport"
            else:
                print("[!] No networks found")
                return None
        else:
            print("[!] Scan failed (airport).")
    else:
        print(f"[!] Airport utility not found at {AIRPORT_PATH}")

    # Final hint: WiFi Diagnostics
    print("[*] Opening WiFi Diagnostics app (manual scan)...")
    run_command("open '/System/Library/CoreServices/WiFi Diagnostics.app'", check=False)
    print("[*] Note: wdutil has no scan; use WiFi Diagnostics for a GUI scan.")
    return None


def connect_to_network(interface, ssid=None, password=None):
    """Connect to WiFi network"""
    if not ssid:
        # Try to connect to preferred network
        preferred = get_preferred_networks()
        if preferred:
            ssid = preferred[0]
            print(f"[*] Connecting to preferred network: {ssid}")
        else:
            print("[!] No SSID specified and no preferred networks found")
            return False
    else:
        print(f"[*] Connecting to: {ssid}")
    
    if password:
        cmd = f'networksetup -setairportnetwork {interface} "{ssid}" "{password}"'
    else:
        cmd = f'networksetup -setairportnetwork {interface} "{ssid}"'
    
    stdout, stderr, code = run_command(cmd, check=False)
    
    # Check for failure in stdout (networksetup returns 0 even on failure!)
    if "Failed" in stdout or "Error:" in stdout or stderr:
        error_msg = stdout if stdout else stderr
        print(f"[!] Connection failed: {error_msg.split('Error:')[0].strip()}")
        
        # Parse error code
        if "-3900" in error_msg:
            print("[!] Error -3900: Authentication failed or network not in range")
            if not password:
                print("[*] Try providing password: sudo ./connect.py -s '{}' -p 'PASSWORD'".format(ssid))
            else:
                print("[*] Check password or remove saved network:")
                print("[*]   sudo security delete-generic-password -l '{}'".format(ssid))
        elif "-3905" in error_msg:
            print("[!] Error -3905: Network not found")
        
        return False
    
    if code == 0:
        print(f"[+] Connection initiated to {ssid}")
        return True
    else:
        print(f"[!] Connection failed with code {code}")
        return False


def check_connection(interface, retry=3):
    """Check if WiFi is connected with retry logic"""
    for attempt in range(retry):
        if attempt > 0:
            print(f"[*] Retry {attempt}/{retry-1}...")
            time.sleep(2)
        
        # Primary method: networksetup
        stdout, _, code = run_command(f"networksetup -getairportnetwork {interface}", check=False)
        
        if code == 0 and "Current Wi-Fi Network:" in stdout:
            ssid = stdout.split("Current Wi-Fi Network:")[1].strip()
            if ssid and "not associated" not in ssid.lower():
                print(f"[+] Connected to: {ssid}")
                
                # Get IP address
                ifconfig_out, _, _ = run_command(f"ifconfig {interface} inet", check=False)
                if "inet " in ifconfig_out:
                    for line in ifconfig_out.split('\n'):
                        if 'inet ' in line and 'inet6' not in line:
                            ip = line.strip().split()[1]
                            print(f"    IP: {ip}")
                
                return True
    
    print("[*] Not connected to any network")
    return False


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='WiFi Monitor Mode Recovery Tool for macOS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  sudo ./connect.py                           # Auto-connect to preferred network
  sudo ./connect.py -s "MyNetwork"            # Connect to specific SSID (prompt for password)
  sudo ./connect.py -s "MyNetwork" -p "pass"  # Connect with password
  sudo ./connect.py --scan                    # Just scan for networks
        '''
    )
    
    parser.add_argument(
        '-s', '--ssid',
        type=str,
        help='SSID to connect to'
    )
    
    parser.add_argument(
        '-p', '--password',
        type=str,
        help='WiFi password (will prompt if not provided)'
    )
    
    parser.add_argument(
        '--scan',
        action='store_true',
        help='Scan for available networks and exit'
    )
    
    return parser.parse_args()


def main():
    """Main execution flow"""
    args = parse_arguments()
    
    print("=" * 50)
    print("WiFi Monitor Mode Recovery Tool")
    print("=" * 50)
    
    # Check root privileges
    check_root()
    
    # Get WiFi interface
    interface = get_wifi_interface()
    print(f"[*] Using interface: {interface}")
    
    # Handle scan-only mode
    if args.scan:
        print("\n[*] Scanning for available networks...")
        scan_networks(interface)
        return
    
    # Check current status
    print("\n[*] Checking current status...")
    in_monitor = is_monitor_mode(interface)
    connected = is_connected(interface)
    
    # If specific SSID provided, handle custom connection
    if args.ssid:
        print(f"\n[*] Custom connection requested to: {args.ssid}")
        
        # Get password if not provided
        password = args.password
        if not password:
            password = getpass.getpass(f"[*] Enter password for '{args.ssid}': ")
        
        # Ensure WiFi is enabled
        if in_monitor:
            print("[*] Disabling monitor mode first...")
            disable_monitor_mode(interface)
        
        print("[*] Ensuring WiFi is enabled...")
        enable_wifi(interface)
        time.sleep(2)
        
        # Connect
        if connect_to_network(interface, ssid=args.ssid, password=password):
            print("[*] Waiting for connection to establish...")
            time.sleep(8)
            check_connection(interface)
        else:
            print("\n[!] Connection failed")
        
        print("\n[+] Done!")
        return
    
    # Standard auto-recovery flow (no SSID specified)
    # Early exit if everything is OK
    if not in_monitor and connected:
        print("\n[+] WiFi is already connected and not in monitor mode")
        print("[+] No action needed - exiting")
        return
    
    if not in_monitor and not connected:
        print("\n[*] Not in monitor mode, but not connected")
        print("[*] Attempting connection only...")
        
        # Ensure WiFi is enabled first
        print("[*] Ensuring WiFi is enabled...")
        run_command("networksetup -setairportpower en0 on", check=False)
        time.sleep(2)
        
        # Get preferred network
        preferred = get_preferred_networks()
        if preferred:
            ssid = preferred[0]
            print(f"[*] Checking if {ssid} is in range...")
            in_range = is_network_in_range(interface, ssid)
            
            if in_range is False:
                print(f"[!] Network {ssid} not found in range")
                print("[*] Scanning for available networks...")
                scan_networks(interface)
                return
        
        if connect_to_network(interface):
            print("[*] Waiting for connection to establish...")
            time.sleep(8)
            check_connection(interface)
        else:
            print("\n[*] Connection failed. Manual steps:")
            print(f"    1. Remove saved network: sudo security delete-generic-password -l '{preferred[0] if preferred else 'SSID'}'")
            print(f"    2. Reconnect: sudo ./connect.py -s \"SSID\" -p \"PASSWORD\"")
        return
    
    # Interface is in monitor mode - full recovery needed
    print("\n[!] Monitor mode detected - starting recovery...")
    
    # Disable monitor mode
    disable_monitor_mode(interface)
    
    # Enable WiFi
    if not enable_wifi(interface):
        print("[!] Could not enable WiFi")
        sys.exit(1)
    
    # Scan for networks
    if Path(AIRPORT_PATH).exists():
        scan_networks(interface)
    
    # Try to connect
    print("\n[*] Attempting to connect...")
    if not connect_to_network(interface):
        print("\n[*] Connection failed. Manual steps:")
        preferred = get_preferred_networks()
        if preferred:
            print(f"    1. Remove saved network: sudo security delete-generic-password -l '{preferred[0]}'")
        print(f"    2. Reconnect: sudo ./connect.py -s \"SSID\" -p \"PASSWORD\"")
    else:
        print("[*] Waiting for connection to establish...")
        time.sleep(8)
        check_connection(interface)
    
    print("\n[+] Done!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
