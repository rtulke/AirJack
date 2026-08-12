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
import ssl
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Set
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class VendorUpdater:
    """Handles fetching and merging MAC vendor data from multiple sources."""

    def __init__(self, config_file: str, output_file: str, verbose: bool = False, insecure: bool = False):
        self.config_file = config_file
        self.output_file = output_file
        self.verbose = verbose
        self.insecure = insecure
        self.vendors: Dict[str, str] = {}   # 24-bit OUI (XX:XX:XX) -> Vendor name
        self.prefixes: Dict[str, str] = {}  # 28/36-bit sub-block (hex nibbles) -> Vendor name
        self.sources_processed: Set[str] = set()

    def log(self, message: str):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}")

    def normalize_nibbles(self, prefix: str, bits: int) -> str:
        """Return the first `bits`-worth of hex nibbles (uppercase) of a prefix.

        `bits` must be one of 24/28/36 (the IEEE registration granularities).
        Returns None if the prefix does not carry enough hex digits.
        """
        clean = re.sub(r'[^0-9A-Fa-f]', '', prefix).upper()
        nibbles = bits // 4  # 24->6, 28->7, 36->9
        if len(clean) < nibbles:
            return None
        return clean[:nibbles]

    def normalize_oui(self, oui: str) -> str:
        """Normalize a 24-bit OUI to XX:XX:XX (uppercase, colon-separated)."""
        nibbles = self.normalize_nibbles(oui, 24)
        if not nibbles:
            return None
        return f"{nibbles[0:2]}:{nibbles[2:4]}:{nibbles[4:6]}"

    def store_entry(self, nibbles: str, vendor: str) -> bool:
        """Store a vendor keyed by a hex-nibble prefix.

        6 nibbles (24-bit) go into self.vendors under the colon form XX:XX:XX;
        7/9 nibbles (28/36-bit sub-blocks) go into self.prefixes keyed by the
        raw nibble string (its length encodes the mask). On collision the
        longer, more descriptive vendor name wins.
        """
        if not nibbles:
            return False
        if len(nibbles) == 6:
            key = f"{nibbles[0:2]}:{nibbles[2:4]}:{nibbles[4:6]}"
            table = self.vendors
        else:
            key = nibbles
            table = self.prefixes
        if key not in table or len(vendor) > len(table[key]):
            table[key] = vendor
            return True
        return False

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

    def is_local_source(self, url: str) -> bool:
        """True if the source points at a local file rather than a URL."""
        return url.startswith('file:') or '://' not in url

    def read_local_file(self, url: str, source_name: str) -> str:
        """Read a local source file.

        A ``file:`` scheme is honored; a bare relative path is resolved against
        the directory of the config file so custom lists live next to it.
        """
        path = url[7:] if url.startswith('file://') else url[5:] if url.startswith('file:') else url
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(os.path.abspath(self.config_file)), path)
        self.log(f"Reading {source_name} from local file {path}")
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.log(f"Successfully read {source_name} ({len(content)} bytes)")
            return content
        except OSError as e:
            print(f"[!] Error reading {source_name} ({path}): {e}", file=sys.stderr)
            return None

    def fetch_url(self, url: str, source_name: str) -> str:
        """Fetch content from URL with error handling."""
        self.log(f"Fetching {source_name} from {url}")

        ctx = ssl._create_unverified_context() if self.insecure else None

        try:
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (AirJack Vendor Updater)'})
            with urlopen(req, timeout=30, context=ctx) as response:
                content = response.read().decode('utf-8', errors='ignore')
                self.log(f"Successfully fetched {source_name} ({len(content)} bytes)")
                return content
        except ssl.SSLError as e:
            if not self.insecure:
                print(f"[!] SSL error fetching {source_name}: {e}", file=sys.stderr)
                print(f"[!] Try running with -k/--insecure to skip certificate verification", file=sys.stderr)
            else:
                print(f"[!] SSL error fetching {source_name}: {e}", file=sys.stderr)
            return None
        except (URLError, HTTPError) as e:
            if not self.insecure and 'CERTIFICATE' in str(e).upper():
                print(f"[!] SSL certificate error fetching {source_name}: {e}", file=sys.stderr)
                print(f"[!] Try running with -k/--insecure to skip certificate verification", file=sys.stderr)
            else:
                print(f"[!] Error fetching {source_name}: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"[!] Unexpected error fetching {source_name}: {e}", file=sys.stderr)
            return None

    def parse_ieee_csv(self, content: str, source_name: str, bits: int = 24):
        """Parse IEEE CSV format.

        `bits` is the registration granularity of the file: 24 for oui.csv
        (MA-L), 28 for mam.csv (MA-M), 36 for oui36.csv (MA-S) and iab.csv.
        The Assignment column carries exactly that many hex digits, so keeping
        the full prefix (instead of truncating to 24 bit) lets distinct
        sub-block owners coexist instead of colliding on a shared 24-bit OUI.
        """
        if not content:
            return

        self.log(f"Parsing IEEE CSV: {source_name} ({bits}-bit)")
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

            nibbles = self.normalize_nibbles(oui_raw, bits)
            if not nibbles:
                continue

            vendor = self.clean_vendor_name(vendor_raw)

            if self.store_entry(nibbles, vendor):
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

            nibbles = self.normalize_nibbles(oui_raw, 24)
            if not nibbles:
                continue

            vendor = self.clean_vendor_name(vendor_raw)

            if self.store_entry(nibbles, vendor):
                count += 1

        self.log(f"Added {count} entries from {source_name}")
        self.sources_processed.add(source_name)

    def parse_wireshark_manuf(self, content: str, source_name: str):
        """Parse Wireshark manuf format.

        Handles the sub-block mask suffix (e.g. ``00:1B:C5:00:00/36``). Only the
        IEEE granularities 24/28/36 bit are kept; prefixes with any other mask
        are skipped so the lookup stays a clean longest-prefix match.
        """
        if not content:
            return

        self.log(f"Parsing Wireshark manuf format: {source_name}")
        count = 0
        skipped_mask = 0

        for line in content.strip().split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Format: PREFIX[/MASK]<tab>ShortName[<tab>LongName]
            parts = line.split('\t')
            if len(parts) < 2:
                continue

            prefix_raw = parts[0].strip()

            # Extract the mask; entries without one are 24-bit OUIs.
            if '/' in prefix_raw:
                addr, mask_raw = prefix_raw.split('/', 1)
                try:
                    bits = int(mask_raw.strip())
                except ValueError:
                    continue
            else:
                addr, bits = prefix_raw, 24

            if bits not in (24, 28, 36):
                skipped_mask += 1
                continue

            # Prefer long name if available, otherwise short name
            vendor_raw = parts[2].strip() if len(parts) > 2 and parts[2].strip() else parts[1].strip()

            nibbles = self.normalize_nibbles(addr, bits)
            if not nibbles:
                continue

            vendor = self.clean_vendor_name(vendor_raw)

            if self.store_entry(nibbles, vendor):
                count += 1

        if skipped_mask:
            self.log(f"Skipped {skipped_mask} entries with non-24/28/36-bit masks")
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

            if self.is_local_source(url):
                content = self.read_local_file(url, source_name)
            else:
                content = self.fetch_url(url, source_name)
            if not content:
                continue

            # Detect format and parse accordingly
            if 'ieee.org' in url and url.endswith('.csv'):
                # Registration granularity is implied by the IEEE file:
                # oui.csv=24 (MA-L), mam.csv/oui28=28 (MA-M), oui36/iab=36 (MA-S/IAB).
                low = url.lower()
                if 'oui36' in low or '/iab/' in low or 'iab.csv' in low:
                    bits = 36
                elif 'oui28' in low or 'mam' in low:
                    bits = 28
                else:
                    bits = 24
                self.parse_ieee_csv(content, source_name, bits)
            elif 'nmap' in url or 'mac-prefixes' in source_name.lower() or 'custom' in source_name.lower():
                # Local custom overrides use the simple "PREFIX Vendor" Nmap format.
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
        total = len(self.vendors) + len(self.prefixes)
        self.log(f"Saving {total} vendors "
                 f"({len(self.vendors)} 24-bit, {len(self.prefixes)} sub-block) "
                 f"to {self.output_file}")

        # Create metadata
        metadata = {
            "_metadata": {
                "generated": datetime.now().isoformat(),
                "total_entries": total,
                "oui24_entries": len(self.vendors),
                "sub_block_entries": len(self.prefixes),
                "sources": list(self.sources_processed),
                "format": ("24-bit OUIs at top level as 'XX:XX:XX' -> Vendor; "
                           "28/36-bit sub-blocks under '_prefixes' keyed by hex "
                           "nibbles (length encodes the mask)")
            }
        }

        # Merge metadata with 24-bit vendors; sub-blocks live under _prefixes.
        output_data = {**metadata, **self.vendors}
        output_data["_prefixes"] = dict(sorted(self.prefixes.items()))

        # Write JSON with nice formatting
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False, sort_keys=True)

        print(f"[+] Successfully saved {total} vendors "
              f"({len(self.vendors)} 24-bit + {len(self.prefixes)} sub-block) to {self.output_file}")
        print(f"[+] Sources processed: {', '.join(self.sources_processed)}")

    def run(self):
        """Main execution flow."""
        print(f"[*] OUI/MAC Vendor Database Updater")
        print(f"[*] Config: {self.config_file}")
        print(f"[*] Output: {self.output_file}")
        print()

        self.process_sources()

        if not self.vendors and not self.prefixes:
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
    parser.add_argument('-k', '--insecure',
                        action='store_true',
                        help='Skip SSL certificate verification (useful behind proxies with self-signed certs)')

    args = parser.parse_args()

    updater = VendorUpdater(args.config, args.output, args.verbose, args.insecure)
    updater.run()


if __name__ == '__main__':
    main()
