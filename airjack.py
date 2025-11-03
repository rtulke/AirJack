#!/usr/bin/env python3
"""
AirJack - A WiFi security testing tool for macOS

This tool is for educational purposes and security testing of YOUR OWN networks only.
Unauthorized access to computer networks is illegal and punishable by law.
"""

import subprocess
import re
import argparse
import os
import sys
import logging
import json
import configparser
import shutil
import platform
from os.path import expanduser, join, exists, dirname
from time import sleep
from typing import List, Dict, Tuple, Optional, Any, Union

try:
    import CoreWLAN
    import CoreLocation
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


# --- macOS 15+ Virtual Environment Warning ---
def check_macos_venv_issue():
    """Check if running in venv on macOS 15+ and warn user."""
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
        tool_name: Name of the tool (e.g., 'hashcat', 'zizzania')
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
    elif tool_name == 'zizzania':
        manual_paths.extend([
            join(expanduser('~'), 'zizzania', 'build', 'zizzania'),
            join(expanduser('~'), 'zizzania', 'src', 'zizzania'),
            join(expanduser('~'), 'zizzania', 'zizzania'),
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

    # Detect zizzania
    zizzania_path = find_tool_path('zizzania')
    paths['zizzania_path'] = zizzania_path or join(expanduser('~'), 'zizzania', 'src', 'zizzania')

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
            "zizzania_path": detected_paths['zizzania_path'],
        }
        
        self.config["Defaults"] = {
            "interface": "",
            "deauth": "false",
            "optimize": "false",
            "verbose": "false",
        }
        
        # Ensure directory exists
        os.makedirs(dirname(config_path), exist_ok=True)
        
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
                
            if not hasattr(self.args, 'hashcat_path') or self.args.hashcat_path is None:
                self.args.hashcat_path = self.config.get('hashcat_path', None)
                
            if not hasattr(self.args, 'zizzania_path') or self.args.zizzania_path is None:
                self.args.zizzania_path = self.config.get('zizzania_path', None)
                
            if not hasattr(self.args, 'interface') or self.args.interface is None:
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
        """Configure logging based on verbosity level."""
        log_level = logging.DEBUG if self.args.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.log = logging
    
    def setup_tools(self):
        """Set up paths to external tools and verify their existence."""
        # Priority order:
        # 1. Command-line arguments (--hashcat-path, --zizzania-path)
        # 2. Config file values
        # 3. Smart detection (Homebrew-first, then manual builds)
        # 4. Hardcoded fallback defaults

        if self.args.hashcat_path:
            self.hashcat_path = self.args.hashcat_path
        else:
            # Try smart detection
            detected = find_tool_path('hashcat')
            self.hashcat_path = detected or join(expanduser('~'), 'hashcat', 'hashcat')

        if self.args.zizzania_path:
            self.zizzania_path = self.args.zizzania_path
        else:
            # Try smart detection
            detected = find_tool_path('zizzania')
            self.zizzania_path = detected or join(expanduser('~'), 'zizzania', 'src', 'zizzania')

        # Validate tool paths if not in dry_run mode
        if not self.args.dry_run:
            missing_tools = []
            if not exists(self.hashcat_path):
                missing_tools.append(f"hashcat: {self.hashcat_path}")
                # Provide helpful hint
                homebrew_hashcat = find_tool_path('hashcat')
                if homebrew_hashcat:
                    self.log.info(f"Hint: Found hashcat at {homebrew_hashcat}")
                    self.log.info(f"Use --hashcat-path {homebrew_hashcat} or add to config file")

            if not exists(self.zizzania_path):
                missing_tools.append(f"zizzania: {self.zizzania_path}")
                # Provide helpful hint
                found_zizzania = find_tool_path('zizzania')
                if found_zizzania:
                    self.log.info(f"Hint: Found zizzania at {found_zizzania}")
                    self.log.info(f"Use --zizzania-path {found_zizzania} or add to config file")

            if missing_tools:
                self.log.error("Missing required tools:")
                for tool in missing_tools:
                    self.log.error(f"  - {tool}")
                self.log.error("")
                self.log.error("Solutions:")
                self.log.error("1. Install via Homebrew: brew install hashcat hcxtools")
                self.log.error("2. Build manually and create config: airjack.py -C ~/.airjack.conf")
                self.log.error("3. Specify paths: --hashcat-path /path/to/hashcat --zizzania-path /path/to/zizzania")
                if not self.args.ignore_missing:
                    sys.exit(1)

        self.log.debug(f"Using hashcat: {self.hashcat_path}")
        self.log.debug(f"Using zizzania: {self.zizzania_path}")
    
    def request_location_permission(self) -> bool:
        """Request permission to use location services for WiFi scanning.

        Returns:
            bool: True if authorized, False otherwise
        """
        # Initialize CoreLocation
        location_manager = CoreLocation.CLLocationManager.alloc().init()

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
            # If already authorized, return immediately
            self.log.info("Already authorized for location services.")
            return True
        elif current_status == 2:  # denied
            # If denied, inform user
            self.log.error("Location services access was previously denied.")
            self.log.error("Please enable it in: System Settings > Privacy & Security > Location Services")
            self.log.error("Look for your terminal app (Terminal, iTerm2, etc.) and enable it.")
            return False
        elif current_status == 1:  # restricted
            self.log.error("Location services access is restricted (possibly by parental controls).")
            return False

        # Request authorization for location services
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
                # macOS sometimes reports status 3 or 4 even when permission wasn't really granted
                # Verify by attempting to scan and check if we get real BSSIDs
                self.log.debug("Status reports authorized, verifying with actual scan...")
                test_results, test_error = self.cwlan_interface.scanForNetworksWithName_error_(None, None)
                if test_results and len(test_results) > 0:
                    # Check if we get real BSSIDs
                    has_real_bssid = False
                    for net in test_results:
                        if net.bssid() is not None:
                            has_real_bssid = True
                            break

                    if has_real_bssid:
                        self.log.info("Received authorization, continuing...")
                        return True
                    else:
                        self.log.warning(f"Status shows {authorization_status} but no BSSIDs available")
                        self.log.warning("Location Services permission may not be properly granted")
                        # Continue waiting
                else:
                    self.log.debug("Test scan returned no networks, continuing to wait...")


            # Check if denied during wait
            if authorization_status == 2:
                self.log.error("Location services access was denied during authorization request.")
                self.log.error("Please enable it in: System Settings > Privacy & Security > Location Services")
                return False

            if i == max_wait - 1:
                # Timeout reached - provide detailed instructions
                if authorization_status in [0, 3, 4]:
                    # Status 0 = not determined, or 3/4 but no real BSSIDs available
                    self.log.error("Authorization timeout - Location Services are not working properly.")
                    self.log.error("")
                    self.log.error("Location Services are required to access WiFi BSSID information.")
                    self.log.error("Without proper authorization, networks will show with BSSID: None")
                    self.log.error("")
                    self.log.error("Manual Setup Required:")
                    self.log.error("1. Open System Settings > Privacy & Security > Location Services")
                    self.log.error("2. Ensure Location Services is enabled (toggle at top)")
                    self.log.error("3. Scroll down and find your terminal app (Terminal.app, iTerm2, Warp, etc.)")
                    self.log.error("4. If your app is NOT in the list:")
                    self.log.error("   - Click the '+' button")
                    self.log.error("   - Navigate to /Applications/Utilities/")
                    self.log.error("   - Select your terminal app (e.g., Terminal.app)")
                    self.log.error("5. If your app IS in the list, enable the checkbox next to it")
                    self.log.error("6. Restart this tool")
                    self.log.error("")
                    self.log.error(f"Note: macOS authorization status reported as {authorization_status}, but BSSIDs unavailable")
                else:
                    self.log.error("Unable to obtain authorization, exiting...")
                    self.log.error(f"Final authorization status: {authorization_status}")
                return False

            sleep(1)
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
        """Reconnect to a specific WiFi network.

        Args:
            ssid: Network name to reconnect to

        Returns:
            bool: True if reconnection successful, False otherwise
        """
        if not ssid:
            return False

        try:
            self.log.info(f"Attempting to reconnect to '{ssid}'...")

            # Wait a moment for interface to be ready for reconnection
            # (after capture operations, interface needs time to stabilize)
            sleep(2)

            # Scan for available networks
            scan_results, error = self.cwlan_interface.scanForNetworksWithName_error_(ssid, None)

            if error:
                self.log.error(f"Error scanning for '{ssid}': {error}")
                return False

            if not scan_results or len(scan_results) == 0:
                self.log.error(f"Network '{ssid}' not found")
                return False

            # scan_results is an NSSet, convert to list to access elements
            # Or just get any network from the set since they all have the same SSID
            target_network = None
            for network in scan_results:
                target_network = network
                break  # Get first network from set

            if not target_network:
                self.log.error(f"Could not retrieve network object for '{ssid}'")
                return False

            # Try to associate with the network (no password, for open networks)
            # For secured networks, macOS will use stored credentials from Keychain
            success, error = self.cwlan_interface.associateToNetwork_password_error_(target_network, None, None)

            if error:
                self.log.warning(f"Could not reconnect to '{ssid}': {error}")
                self.log.info("Please reconnect manually or check your Keychain credentials")
                return False

            self.log.info(f"Successfully reconnected to '{ssid}'")
            return True

        except Exception as e:
            self.log.error(f"Exception during reconnection: {e}")
            return False

    def colorize_rssi(self, rssi: int) -> str:
        """Colorize RSSI values based on signal strength.
        
        Args:
            rssi: Signal strength in dBm
            
        Returns:
            str: Colorized RSSI string
        """
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

                    # Get BSSID and skip if None (invalid network entry)
                    bssid = result.bssid()
                    if bssid is None:
                        self.log.debug(f"Skipping network with no BSSID (SSID: {result.ssid()})")
                        continue

                    network_info = {
                        'ssid': result.ssid() or "<hidden>",
                        'bssid': bssid,
                        'rssi': result.rssiValue(),
                        'channel_object': result.wlanChannel(),
                        'channel_number': result.channel(),
                        'security': security
                    }
                    self.networks.append(network_info)
                except Exception as e:
                    self.log.warning(f"Error parsing network: {e}")
                    continue

            # Sort networks by RSSI value, descending
            self.networks = sorted(self.networks, key=lambda x: x['rssi'], reverse=True)

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
                user_input = input('\nSelect a network (1-{}, 0=cancel, r=rescan): '.format(len(self.networks))).strip().lower()

                # Check for retry
                if user_input == 'r':
                    self.log.info("Rescanning for networks...")
                    return -2

                # Check for cancel
                if user_input == '0':
                    self.log.info("Operation canceled by user.")
                    return -1

                # Try to parse as number
                try:
                    x = int(user_input) - 1
                    if x < 0 or x >= len(self.networks):
                        self.log.error(f"Invalid selection. Must be between 1 and {len(self.networks)}")
                        return -1
                    return x
                except ValueError:
                    self.log.error("Invalid input. Enter a number (1-{}), 'r' to rescan, or '0' to cancel.".format(len(self.networks)))
                    return -1

            return x
        except (ValueError, EOFError, KeyboardInterrupt):
            self.log.error("\nInvalid input or interrupted.")
            return -1
    
    def capture_network(self, bssid: str, channel) -> bool:
        """Capture WPA handshake for the selected network.
        
        Args:
            bssid: BSSID of the target network
            channel: WiFi channel object
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Dissociate from the current network
            self.cwlan_interface.disassociate()

            # Set the channel
            self.cwlan_interface.setWLANChannel_error_(channel, None)

            # Determine the network interface
            iface = self.args.interface or self.cwlan_interface.interfaceName()
            self.log.info(f"Using interface: {iface}")

            self.log.info(f"Initiating handshake capture on BSSID: {bssid}")

            if self.args.dry_run:
                self.log.info("DRY RUN: Would run zizzania capture (skipped)")
                return True

            # Explain what's happening
            print("\n" + "="*70)
            print("Waiting for WPA Handshake")
            print("="*70)
            print("\nZizzania is now listening for a handshake. This happens when:")
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

            print("\nPress Ctrl+C to abort capture")
            print("="*70 + "\n")

            # Build the command with verbose output
            cmd = [
                'sudo', self.zizzania_path,
                '-i', iface,
                '-b', bssid,
                '-w', self.capture_file,
                '-v'  # Always use verbose to see deauth attempts
            ]

            if not self.args.deauth:
                cmd.append('-n')

            if self.args.verbose:
                self.log.debug(f"Running command: {' '.join(cmd)}")

            # Use Popen for live output with timeout
            import time
            import signal

            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True
                )

                # Timeout: 10 minutes (600 seconds)
                timeout_seconds = 600
                start_time = time.time()

                # Track what we've seen
                clients_seen = set()
                deauth_sent = 0
                handshake_found = False

                print(f"[INFO] Capture timeout: {timeout_seconds // 60} minutes\n")

                # Read output line by line with timeout check
                while True:
                    # Check timeout
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
                            print("  1. Zizzania lacks permissions for packet injection")
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

                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        return False

                    # Read line with small timeout
                    line = process.stdout.readline()
                    if not line:
                        # Check if process ended
                        if process.poll() is not None:
                            break
                        time.sleep(0.1)
                        continue

                    line = line.rstrip()

                    # Always display output
                    print(f"[zizzania] {line}")

                    # Parse zizzania output for diagnostics
                    if 'New client' in line:
                        # Extract client MAC
                        parts = line.split()
                        if len(parts) >= 4:
                            client_mac = parts[3]
                            clients_seen.add(client_mac)
                    elif 'Disassoc' in line or 'Deauth' in line:
                        deauth_sent += 1
                    elif 'handshake' in line.lower() or 'EAPOL' in line:
                        handshake_found = True
                        print("\n✓ HANDSHAKE CAPTURED! Finishing capture...")

                # Wait for process to complete
                return_code = process.wait()

                if return_code != 0:
                    self.log.error(f"Zizzania exited with code {return_code}")
                    return False

            except KeyboardInterrupt:
                self.log.warning("\nCapture interrupted by user")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                return False

            # Check if capture file was created
            if not exists(self.capture_file):
                self.log.error(f"Capture file was not created: {self.capture_file}")
                self.log.error("This may indicate that no handshake was captured.")
                return False

            # Convert the capture to hashcat format
            self.log.info("Converting capture to hashcat format...")
            conv_cmd = ['hcxpcapngtool', '-o', self.hashcat_file, self.capture_file]

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
    parser.add_argument('--zizzania-path', default=None,
                      help='Path to zizzania executable (default: from config or ~/zizzania/src/zizzania)')
    
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
    
    return parser


def main() -> int:
    """Main entry point for the program.
    
    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    parser = setup_argparse()
    args = parser.parse_args()
    
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
