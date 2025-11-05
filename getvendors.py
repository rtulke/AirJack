#!/usr/bin/env python3
"""
OUI/MAC Vendor Database Updater

This script fetches MAC address vendor data from multiple sources (IEEE, Wireshark, Nmap)
and merges them into a unified JSON database file, removing duplicates.

Configuration is read from vendor-sources.conf
"""

import argparse
import configparser
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Set
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class VendorUpdater:
    """Handles fetching and merging MAC vendor data from multiple sources."""

    def __init__(self, config_file: str, output_file: str, verbose: bool = False):
        self.config_file = config_file
        self.output_file = output_file
        self.verbose = verbose
        self.vendors: Dict[str, str] = {}  # OUI -> Vendor name
        self.sources_processed: Set[str] = set()

    def log(self, message: str):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}")

    def normalize_oui(self, oui: str) -> str:
        """Normalize OUI to format XX:XX:XX (uppercase, colon-separated)."""
        # Remove all non-hex characters
        oui_clean = re.sub(r'[^0-9A-Fa-f]', '', oui)

        # Take first 6 hex digits (24-bit OUI)
        if len(oui_clean) < 6:
            return None

        oui_clean = oui_clean[:6].upper()

        # Format as XX:XX:XX
        return f"{oui_clean[0:2]}:{oui_clean[2:4]}:{oui_clean[4:6]}"

    def clean_vendor_name(self, name: str) -> str:
        """Clean and normalize vendor name."""
        if not name:
            return "Unknown"

        # Remove extra whitespace
        name = ' '.join(name.split())

        # Remove common suffixes that add noise
        name = re.sub(r',?\s*(Inc\.?|LLC|Ltd\.?|GmbH|AG|Corp\.?|Corporation|Co\.?)$', '', name, flags=re.IGNORECASE)

        # Capitalize properly
        return name.strip()

    def fetch_url(self, url: str, source_name: str) -> str:
        """Fetch content from URL with error handling."""
        self.log(f"Fetching {source_name} from {url}")

        try:
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (AirJack Vendor Updater)'})
            with urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
                self.log(f"Successfully fetched {source_name} ({len(content)} bytes)")
                return content
        except (URLError, HTTPError) as e:
            print(f"[!] Error fetching {source_name}: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"[!] Unexpected error fetching {source_name}: {e}", file=sys.stderr)
            return None

    def parse_ieee_csv(self, content: str, source_name: str):
        """Parse IEEE CSV format (oui.csv, mam.csv, oui36.csv, iab.csv)."""
        if not content:
            return

        self.log(f"Parsing IEEE CSV: {source_name}")
        count = 0

        lines = content.strip().split('\n')
        reader = csv.reader(lines)

        # Skip header if present
        header = next(reader, None)

        for row in reader:
            if len(row) < 2:
                continue

            oui_raw = row[1].strip() if len(row) > 1 else row[0].strip()
            vendor_raw = row[2].strip() if len(row) > 2 else "Unknown"

            oui = self.normalize_oui(oui_raw)
            if not oui:
                continue

            vendor = self.clean_vendor_name(vendor_raw)

            # Only add if not exists or is better quality
            if oui not in self.vendors or len(vendor) > len(self.vendors[oui]):
                self.vendors[oui] = vendor
                count += 1

        self.log(f"Added {count} entries from {source_name}")
        self.sources_processed.add(source_name)

    def parse_nmap_format(self, content: str, source_name: str):
        """Parse Nmap nmap-mac-prefixes format."""
        if not content:
            return

        self.log(f"Parsing Nmap format: {source_name}")
        count = 0

        for line in content.strip().split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Format: AABBCC VendorName
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue

            oui_raw, vendor_raw = parts[0], parts[1]

            oui = self.normalize_oui(oui_raw)
            if not oui:
                continue

            vendor = self.clean_vendor_name(vendor_raw)

            if oui not in self.vendors or len(vendor) > len(self.vendors[oui]):
                self.vendors[oui] = vendor
                count += 1

        self.log(f"Added {count} entries from {source_name}")
        self.sources_processed.add(source_name)

    def parse_wireshark_manuf(self, content: str, source_name: str):
        """Parse Wireshark manuf format."""
        if not content:
            return

        self.log(f"Parsing Wireshark manuf format: {source_name}")
        count = 0

        for line in content.strip().split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Format: AA:BB:CC<tab>ShortName<tab>LongName
            # or:     AA:BB:CC<tab>VendorName
            parts = line.split('\t')
            if len(parts) < 2:
                continue

            oui_raw = parts[0].strip()
            # Prefer long name if available, otherwise short name
            vendor_raw = parts[2].strip() if len(parts) > 2 and parts[2].strip() else parts[1].strip()

            oui = self.normalize_oui(oui_raw)
            if not oui:
                continue

            vendor = self.clean_vendor_name(vendor_raw)

            if oui not in self.vendors or len(vendor) > len(self.vendors[oui]):
                self.vendors[oui] = vendor
                count += 1

        self.log(f"Added {count} entries from {source_name}")
        self.sources_processed.add(source_name)

    def load_config(self) -> configparser.ConfigParser:
        """Load configuration file."""
        if not os.path.exists(self.config_file):
            print(f"[!] Config file not found: {self.config_file}", file=sys.stderr)
            sys.exit(1)

        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config

    def process_sources(self):
        """Process all sources from configuration file."""
        config = self.load_config()

        if 'sources' not in config:
            print("[!] No [sources] section in config file", file=sys.stderr)
            sys.exit(1)

        for source_name, url in config['sources'].items():
            url = url.strip()
            if not url:
                continue

            self.log(f"Processing source: {source_name}")

            content = self.fetch_url(url, source_name)
            if not content:
                continue

            # Detect format and parse accordingly
            if 'ieee.org' in url and url.endswith('.csv'):
                self.parse_ieee_csv(content, source_name)
            elif 'nmap' in url or 'mac-prefixes' in source_name.lower():
                self.parse_nmap_format(content, source_name)
            elif 'wireshark' in url or 'manuf' in source_name.lower():
                self.parse_wireshark_manuf(content, source_name)
            else:
                # Try to auto-detect
                if ',' in content[:1000]:  # Likely CSV
                    self.parse_ieee_csv(content, source_name)
                elif '\t' in content[:1000]:  # Likely Wireshark manuf
                    self.parse_wireshark_manuf(content, source_name)
                else:  # Default to Nmap format
                    self.parse_nmap_format(content, source_name)

    def save_database(self):
        """Save merged vendor database to JSON file."""
        self.log(f"Saving {len(self.vendors)} vendors to {self.output_file}")

        # Create metadata
        metadata = {
            "_metadata": {
                "generated": datetime.now().isoformat(),
                "total_entries": len(self.vendors),
                "sources": list(self.sources_processed),
                "format": "OUI -> Vendor Name (XX:XX:XX format)"
            }
        }

        # Merge metadata with vendors
        output_data = {**metadata, **self.vendors}

        # Write JSON with nice formatting
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False, sort_keys=True)

        print(f"[+] Successfully saved {len(self.vendors)} vendors to {self.output_file}")
        print(f"[+] Sources processed: {', '.join(self.sources_processed)}")

    def run(self):
        """Main execution flow."""
        print(f"[*] OUI/MAC Vendor Database Updater")
        print(f"[*] Config: {self.config_file}")
        print(f"[*] Output: {self.output_file}")
        print()

        self.process_sources()

        if not self.vendors:
            print("[!] No vendors found from any source", file=sys.stderr)
            sys.exit(1)

        self.save_database()


def main():
    parser = argparse.ArgumentParser(
        description="Update OUI/MAC vendor database from multiple sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Use default config and output
  %(prog)s -c custom.conf                     # Use custom config file
  %(prog)s -o vendors.json -v                 # Custom output with verbose mode
  %(prog)s -c sources.conf -o db.json -v      # Full custom
        """
    )

    parser.add_argument('-c', '--config',
                        default='vendor-sources.conf',
                        help='Configuration file with source URLs (default: vendor-sources.conf)')
    parser.add_argument('-o', '--output',
                        default='oui-vendors.json',
                        help='Output JSON file (default: oui-vendors.json)')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Enable verbose output')

    args = parser.parse_args()

    updater = VendorUpdater(args.config, args.output, args.verbose)
    updater.run()


if __name__ == '__main__':
    main()
