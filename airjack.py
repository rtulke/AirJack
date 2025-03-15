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
    print("Please install required packages with: pip install prettytable pyfiglet")
    print("Note: CoreWLAN and CoreLocation are part of macOS and cannot be pip-installed.")
    sys.exit(1)


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
        
        # Create default config
        self.config["General"] = {
            "capture_file": "capture.pcap",
            "hashcat_file": "capture.hc22000",
            "auth_timeout": "60",
            "cleanup": "false",
        }
        
        self.config["Paths"] = {
            "hashcat_path": join(expanduser('~'), 'hashcat', 'hashcat'),
            "zizzania_path": join(expanduser('~'), 'zizzania', 'src', 'zizzania'),
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
        
        # Only set if not provided via command line
        if self.config:
            if not hasattr(self.args, 'capture_file') or self.args.capture_file is None:
                self.args.capture_file = self.config.get('capture_file', "capture.pcap")
                
            if not hasattr(self.args, 'hashcat_file') or self.args.hashcat_file is None:
                self.args.hashcat_file = self.config.get('hashcat_file', "capture.hc22000")
                
            if not hasattr(self.args, 'hashcat_path') or self.args.hashcat_path is None:
                self.args.hashcat_path = self.config.get('hashcat_path', None)
                
            if not hasattr(self.args, 'zizzania_path') or self.args.zizzania_path is None:
                self.args.zizzania_path = self.config.get('zizzania_path', None)
                
            if not hasattr(self.args, 'interface') or self.args.interface is None:
                self.args.interface = self.config.get('interface', None)
                
            if not hasattr(self.args, 'auth_timeout') or self.args.auth_timeout is None:
                timeout = self.config.get('auth_timeout', '60')
                self.args.auth_timeout = int(timeout)
                
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
        # Set tool paths from arguments or use defaults
        self.hashcat_path = self.args.hashcat_path or join(expanduser('~'), 'hashcat', 'hashcat')
        self.zizzania_path = self.args.zizzania_path or join(expanduser('~'), 'zizzania', 'src', 'zizzania')
        
        # Validate tool paths if not in dry_run mode
        if not self.args.dry_run:
            missing_tools = []
            if not exists(self.hashcat_path):
                missing_tools.append(f"hashcat: {self.hashcat_path}")
            if not exists(self.zizzania_path):
                missing_tools.append(f"zizzania: {self.zizzania_path}")
            
            if missing_tools:
                self.log.error("Missing required tools:")
                for tool in missing_tools:
                    self.log.error(f"  - {tool}")
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
            return False

        # Request authorization for location services
        self.log.info("Requesting authorization for location services (required for WiFi scanning)...")
        location_manager.requestWhenInUseAuthorization()

        # Wait for location services to be authorized
        max_wait = self.args.auth_timeout
        for i in range(max_wait):
            authorization_status = location_manager.authorizationStatus()
            # 0 = not determined, 1 = restricted, 2 = denied, 3 = authorized always, 4 = authorized when in use
            if authorization_status in [3, 4]:
                self.log.info("Received authorization, continuing...")
                return True
            if i == max_wait - 1:
                self.log.error("Unable to obtain authorization, exiting...")
                return False
            sleep(1)
            if i % 5 == 0:
                self.log.info(f"Waiting for authorization... ({i}/{max_wait}s)")
                
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
                    
                    network_info = {
                        'ssid': result.ssid() or "<hidden>",
                        'bssid': result.bssid(),
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
            int: Index of selected network or -1 if canceled
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
                x = int(input('\nSelect a network to crack (or 0 to cancel): ')) - 1
                if x == -1:
                    self.log.info("Operation canceled by user.")
                    return -1
                if x < 0 or x >= len(self.networks):
                    self.log.error(f"Invalid selection. Must be between 1 and {len(self.networks)}")
                    return -1
            return x
        except ValueError:
            self.log.error("Invalid input. Please enter a number.")
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
                
            # Build the command
            cmd = [
                'sudo', self.zizzania_path, 
                '-i', iface, 
                '-b', bssid, 
                '-w', self.capture_file
            ]
            
            if not self.args.deauth:
                cmd.append('-n')
                
            if self.args.verbose:
                self.log.debug(f"Running command: {' '.join(cmd)}")
            else:
                cmd.append('-q')
                
            # Use zizzania to capture the handshake
            process = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if process.returncode != 0:
                self.log.error(f"Zizzania error: {process.stderr}")
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
        # Request location permission for WiFi scanning
        if not self.request_location_permission():
            return 1
            
        # Scan for networks
        if not self.scan_networks():
            return 1
            
        # Select a network
        network_idx = self.select_network()
        if network_idx < 0:
            return 1
            
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
        
        return 0


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
    parser.add_argument('--hashcat-path', 
                      help='Path to hashcat executable (default: from config or ~/hashcat/hashcat)')
    parser.add_argument('--zizzania-path', 
                      help='Path to zizzania executable (default: from config or ~/zizzania/src/zizzania)')
    
    # Network selection
    parser.add_argument('-i', '--interface', 
                      help='Network interface to use (default: from config or auto-detect)')
    parser.add_argument('-n', '--network-index', type=int,
                      help='Select network by index (skips interactive selection)')
    
    # Capture options
    parser.add_argument('-d', '--deauth', action='store_true', 
                      help='Enable deauthentication (default: from config or disabled)')
    parser.add_argument('--capture-file',
                      help='Output capture file (default: from config or capture.pcap)')
    parser.add_argument('--hashcat-file',
                      help='Output hashcat file (default: from config or capture.hc22000)')
    
    # Cracking options
    parser.add_argument('-m', '--mode', type=int, choices=[1, 2, 3],
                      help='Attack mode: 1=Dictionary, 2=Brute-force, 3=Manual')
    parser.add_argument('-w', '--wordlist', 
                      help='Path to wordlist for dictionary attack')
    parser.add_argument('-p', '--pattern', 
                      help='Pattern for brute-force attack')
    parser.add_argument('-o', '--optimize', action='store_true',
                      help='Enable hashcat optimization (default: from config or disabled)')
    
    # Misc options
    parser.add_argument('--auth-timeout', type=int,
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
