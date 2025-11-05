#!/usr/bin/env python3
"""
Wi‑Fi AP Security Scanner (passive)

Detects WLAN security characteristics without associating to the AP by
sniffing beacon and probe response frames (and optionally observing EAPOL
handshakes if they happen on-air). Reports:
  • SSID / BSSID
  • WPA/WPA2/WPA3/OWE vs WEP/Open (based on RSN & WPA IEs)
  • Pairwise & group ciphers
  • AKM suites (PSK, 802.1X, SAE, FT, OWE, …)
  • PMF/802.11w: capable/required
  • 802.11r presence (via FT AKMs)
  • Whether a 4‑Way Handshake was OBSERVED (passively) for that BSSID

Requirements:
  • Linux with a wireless interface in monitor mode (e.g. wlan0mon)
  • Python 3.8+
  • scapy 2.5+  (pip install scapy)

Usage examples:
  sudo ./wifi_ap_security_scanner.py -i wlan0mon -t 30
  sudo ./wifi_ap_security_scanner.py -i wlan0mon --eapol --channel 36 -t 60
  ./wifi_ap_security_scanner.py -r capture.pcap

Notes:
  • This tool is passive. It does not transmit or attempt to authenticate.
  • "Handshake observed" becomes true only if a client happens to (re)connect
    while you are listening — this is informational and not required to
    assess AP capabilities.
  • For best results, scan several tens of seconds across relevant channels.
"""
from __future__ import annotations
import argparse
import binascii
import os
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.all import (  # type: ignore
        Dot11,
        Dot11Beacon,
        Dot11ProbeResp,
        Dot11Elt,
        EAPOL,
        RadioTap,
        sniff,
        rdpcap,
    )
except Exception as e:  # pragma: no cover
    print("[!] Failed to import scapy. Install with: pip install scapy", file=sys.stderr)
    raise

# Try to import CoreWLAN for macOS support
COREWLAN_AVAILABLE = False
if sys.platform == 'darwin':
    try:
        import CoreWLAN
        import CoreLocation
        COREWLAN_AVAILABLE = True
    except ImportError:
        pass  # CoreWLAN not available, will fall back to Scapy

# ------------------------------
# ANSI Color Codes
# ------------------------------
class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Signal strength colors
    STRONG_SIGNAL = '\033[92m'  # Green (>-60dBm)
    MEDIUM_SIGNAL = '\033[93m'  # Yellow (>-80dBm)
    WEAK_SIGNAL = '\033[91m'    # Red (<-80dBm)

    # Security colors
    WPA3 = '\033[92m'           # Green - most secure
    WPA2 = '\033[96m'           # Cyan - secure
    WPA = '\033[93m'            # Yellow - less secure
    WEP = '\033[91m'            # Red - insecure
    OPEN = '\033[91m'           # Red - insecure
    OWE = '\033[92m'            # Green - enhanced open

    # Feature colors
    VENDOR = '\033[95m'         # Magenta
    SSID = '\033[96m'           # Cyan
    BSSID = '\033[94m'          # Blue

    # Visibility colors
    GRAY = '\033[90m'           # Gray - for invisible/offline APs
    DIM = '\033[2m'             # Dim text

# ------------------------------
# Helpers: Suite decoding
# ------------------------------
IEEE_OUI = b"\x00\x0F\xAC"  # 00-0F-AC
MS_OUI = b"\x00\x50\xF2"    # 00-50-F2 (legacy WPA v1 vendor IE)
WPS_OUI = b"\x00\x50\xF2\x04"  # WPS Vendor IE

# Load vendor OUI database from external JSON file
def load_vendor_oui() -> Dict[str, str]:
    """Load vendor OUI database from vendor_oui.json file."""
    vendor_db = {}

    # Try to load from JSON file
    json_path = os.path.join(os.path.dirname(__file__), 'vendor_oui.json')

    if os.path.exists(json_path):
        try:
            import json
            with open(json_path, 'r') as f:
                data = json.load(f)
                vendor_db = data.get('vendors', {})
        except Exception as e:
            print(f"[!] Warning: Could not load vendor_oui.json: {e}", file=sys.stderr)

    # Fallback to minimal built-in database if file not found
    if not vendor_db:
        vendor_db = {
            "00:0C:43": "MediaTek",
            "08:55:31": "Ubiquiti",
            "0C:8E:29": "Cisco Meraki",
            "18:A6:F7": "TP-Link",
            "2C:91:AB": "TP-Link",
            "84:A1:D1": "Sagemcom",
            "A0:B5:49": "Cisco Meraki",
            "B8:27:EB": "Raspberry Pi",
        }

    return vendor_db

# Load vendor database at module load time
VENDOR_OUI = load_vendor_oui()

CIPHER_TYPES = {
    # Per IEEE 802.11 (subset of the most common values)
    0: "USE-GROUP",
    1: "WEP-40",
    2: "TKIP",
    3: "WRAP",
    4: "CCMP-128",
    5: "WEP-104",
    6: "BIP-CMAC-128",   # management frame integrity (group mgmt)
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
}

AKM_TYPES = {
    # OUI 00-0F-AC (standards)
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",       # 802.11r FT over 802.1X
    4: "FT-PSK",          # 802.11r FT over PSK
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE",             # WPA3-Personal
    9: "FT-SAE",          # WPA3-Personal with FT
    11: "802.1X-SuiteB-128",
    12: "802.1X-SuiteB-192",
    13: "802.1X-FT-SHA384",
    18: "OWE",            # Enhanced Open
    # There are more; unknown values will be shown as numeric
}

# ------------------------------
# NEW: Helper functions
# ------------------------------

def colorize_rssi(rssi: Optional[int]) -> str:
    """Colorize RSSI value based on signal strength."""
    if rssi is None:
        return "-"

    rssi_str = f"{rssi}dBm"

    if rssi > -60:
        # Green for strong signal
        return f"{Colors.STRONG_SIGNAL}{rssi_str}{Colors.ENDC}"
    elif rssi > -80:
        # Yellow for moderate signal
        return f"{Colors.MEDIUM_SIGNAL}{rssi_str}{Colors.ENDC}"
    else:
        # Red for weak signal
        return f"{Colors.WEAK_SIGNAL}{rssi_str}{Colors.ENDC}"


def colorize_security(sec_type: str) -> str:
    """Colorize security type based on security level."""
    if "WPA3" in sec_type:
        return f"{Colors.WPA3}{sec_type}{Colors.ENDC}"
    elif "WPA2" in sec_type:
        return f"{Colors.WPA2}{sec_type}{Colors.ENDC}"
    elif "WPA" in sec_type:
        return f"{Colors.WPA}{sec_type}{Colors.ENDC}"
    elif sec_type == "WEP":
        return f"{Colors.WEP}{sec_type}{Colors.ENDC}"
    elif sec_type == "Open":
        return f"{Colors.OPEN}{sec_type}{Colors.ENDC}"
    elif sec_type == "OWE":
        return f"{Colors.OWE}{sec_type}{Colors.ENDC}"
    else:
        return sec_type


def colorize_vendor(vendor: str) -> str:
    """Colorize vendor name."""
    return f"{Colors.VENDOR}{vendor}{Colors.ENDC}"


def colorize_ssid(ssid: str, hidden: bool = False) -> str:
    """Colorize SSID."""
    if hidden:
        return f"{Colors.WARNING}<hidden>{Colors.ENDC}"
    return f"{Colors.SSID}{ssid}{Colors.ENDC}"


def colorize_bssid(bssid: str) -> str:
    """Colorize BSSID."""
    return f"{Colors.BSSID}{bssid}{Colors.ENDC}"


def get_vendor(bssid: str) -> str:
    """Lookup vendor from BSSID OUI."""
    oui = bssid[:8].upper()
    return VENDOR_OUI.get(oui, "Unknown")


def get_band(channel: Optional[int]) -> Optional[str]:
    """Determine frequency band from channel number."""
    if channel is None:
        return None
    if channel <= 14:
        return "2.4 GHz"
    elif channel <= 177:
        return "5 GHz"
    return "6 GHz"


def parse_wps_ie(payload: bytes) -> Dict:
    """Parse WPS vendor IE (ID 221, OUI 00:50:F2:04).
    Returns dict with: enabled, locked, version, config_methods
    """
    out = {"enabled": False, "locked": None, "version": None, "config_methods": None}
    try:
        if len(payload) < 4:
            return out
        if payload[:4] != WPS_OUI:
            return out

        out["enabled"] = True
        pos = 4

        # WPS uses TLV format: Type(2) + Length(2) + Value(Length)
        while pos + 4 <= len(payload):
            wps_type = struct.unpack(">H", payload[pos:pos+2])[0]
            wps_len = struct.unpack(">H", payload[pos+2:pos+4])[0]
            pos += 4

            if pos + wps_len > len(payload):
                break

            wps_value = payload[pos:pos+wps_len]
            pos += wps_len

            # Type 0x1044 = WPS State
            if wps_type == 0x1044 and wps_len == 1:
                # 1 = Not configured, 2 = Configured
                state = wps_value[0]
                out["locked"] = (state == 2)

            # Type 0x104A = Version
            elif wps_type == 0x104A and wps_len == 1:
                ver = wps_value[0]
                out["version"] = f"{ver >> 4}.{ver & 0x0F}"

            # Type 0x1008 = Config Methods
            elif wps_type == 0x1008 and wps_len == 2:
                methods = struct.unpack(">H", wps_value)[0]
                out["config_methods"] = methods

    except Exception:
        pass
    return out

@dataclass
class APInfo:
    bssid: str
    ssid: str = ""
    channel: Optional[int] = None
    privacy_bit: bool = False
    rsn_present: bool = False
    wpa1_present: bool = False
    group_cipher: Optional[str] = None
    pairwise_ciphers: Set[str] = field(default_factory=set)
    akms: Set[str] = field(default_factory=set)
    pmf_capable: Optional[bool] = None
    pmf_required: Optional[bool] = None
    ft_present: bool = False
    owe_present: bool = False
    handshake_observed: bool = False
    # NEW FIELDS
    rssi: Optional[int] = None
    vendor: Optional[str] = None
    wps_enabled: bool = False
    wps_locked: Optional[bool] = None
    wps_version: Optional[str] = None
    hidden: bool = False
    band: Optional[str] = None
    channel_width: Optional[int] = None
    rrm_enabled: bool = False  # 802.11k
    bss_transition: bool = False  # 802.11v
    beacon_interval: Optional[int] = None
    deauth_count: int = 0
    disassoc_count: int = 0
    # Tracking fields
    ap_id: Optional[int] = None  # Unique ID assigned at discovery
    first_seen: Optional[float] = None  # Timestamp when first discovered
    last_seen: Optional[float] = None  # Timestamp when last seen
    currently_visible: bool = True  # Whether AP is visible in current scan

    def security_label(self) -> str:
        """Return simplified, user-friendly security label."""
        if self.rsn_present:
            # Determine security type based on AKMs
            if "SAE" in self.akms or "FT-SAE" in self.akms:
                if "PSK" in self.akms or "FT-PSK" in self.akms:
                    return "WPA3-Transition"
                return "WPA3-Personal"
            elif any(a.startswith("802.1X") or a == "FT-802.1X" or "SHA256" in a for a in self.akms):
                return "WPA2-Enterprise"
            elif "OWE" in self.akms:
                return "OWE"
            elif "PSK" in self.akms or "FT-PSK" in self.akms:
                return "WPA2-Personal"
            else:
                return "WPA2"
        elif self.wpa1_present:
            return "WPA"
        else:
            if self.privacy_bit:
                return "WEP"
            return "Open"

# ------------------------------
# IE parsing
# ------------------------------

def _parse_suite(selector: bytes) -> Tuple[str, int]:
    """Return (OUI_string, suite_type)."""
    if len(selector) != 4:
        return (binascii.hexlify(selector).decode(), -1)
    oui = selector[:3]
    stype = selector[3]
    return (":".join(f"{b:02x}" for b in oui), stype)


def _cipher_name(oui: bytes, stype: int) -> str:
    if oui == IEEE_OUI:
        return CIPHER_TYPES.get(stype, f"UNKNOWN({stype})")
    elif oui == MS_OUI and stype == 2:
        return "TKIP"  # legacy mapping
    return f"OUI-{binascii.hexlify(oui).decode()}:{stype}"


def _akm_name(oui: bytes, stype: int) -> str:
    if oui == IEEE_OUI:
        return AKM_TYPES.get(stype, f"AKM-{stype}")
    return f"OUI-{binascii.hexlify(oui).decode()}:{stype}"


def parse_rsn_ie(payload: bytes) -> Dict:
    """Parse RSN (ID 48) information element.
    Returns a dict with keys: group_cipher, pairwise_ciphers (set), akms (set),
    pmf_capable(bool|None), pmf_required(bool|None), group_mgmt_cipher(optional)
    """
    out = {
        "group_cipher": None,
        "pairwise_ciphers": set(),
        "akms": set(),
        "pmf_capable": None,
        "pmf_required": None,
        "group_mgmt_cipher": None,
    }
    try:
        # Minimum: version(2) + group cipher(4) + pairwise count(2)
        if len(payload) < 8:
            return out
        pos = 0
        version, = struct.unpack_from("<H", payload, pos)
        pos += 2
        if version != 1:
            return out
        # Group cipher
        gc_sel = payload[pos:pos+4]
        pos += 4
        oui, stype = gc_sel[:3], gc_sel[3]
        out["group_cipher"] = _cipher_name(oui, stype)
        # Pairwise cipher list
        (pc_count,) = struct.unpack_from("<H", payload, pos)
        pos += 2
        for _ in range(pc_count):
            sel = payload[pos:pos+4]
            pos += 4
            out["pairwise_ciphers"].add(_cipher_name(sel[:3], sel[3]))
        # AKM list
        if pos + 2 <= len(payload):
            (akm_count,) = struct.unpack_from("<H", payload, pos)
            pos += 2
            for _ in range(akm_count):
                sel = payload[pos:pos+4]
                pos += 4
                out["akms"].add(_akm_name(sel[:3], sel[3]))
        # RSN Capabilities (2 bytes) — contains PMF bits
        if pos + 2 <= len(payload):
            (rsn_caps,) = struct.unpack_from("<H", payload, pos)
            pos += 2
            # Per Cisco/IEEE: bit6 = MFPR (required), bit7 = MFPC (capable)
            out["pmf_required"] = bool(rsn_caps & (1 << 6))
            out["pmf_capable"] = bool(rsn_caps & (1 << 7))
        # PMKID count + list (optional)
        if pos + 2 <= len(payload):
            (pmkid_count,) = struct.unpack_from("<H", payload, pos)
            pos += 2 + (16 * pmkid_count)
        # Group Management Cipher (optional)
        if pos + 4 <= len(payload):
            sel = payload[pos:pos+4]
            out["group_mgmt_cipher"] = _cipher_name(sel[:3], sel[3])
    except Exception:
        pass
    return out


def parse_wpa1_vendor_ie(payload: bytes) -> Dict:
    """Parse old WPA v1 vendor IE (ID 221, OUI 00:50:F2, type=1)."""
    out = {"present": False, "akms": set(), "pairwise_ciphers": set(), "group_cipher": None}
    try:
        # Expect: OUI(3) + type(1) == 1 + version(2) + group(4) + pairwise count(2) + list + akm count(2) + list
        if len(payload) < 8:
            return out
        if payload[:3] != MS_OUI or payload[3] != 1:
            return out
        pos = 4
        version, = struct.unpack_from("<H", payload, pos)
        pos += 2
        if version != 1:
            return out
        sel = payload[pos:pos+4]
        pos += 4
        out["group_cipher"] = _cipher_name(sel[:3], sel[3])
        (pc_count,) = struct.unpack_from("<H", payload, pos)
        pos += 2
        for _ in range(pc_count):
            sel = payload[pos:pos+4]
            pos += 4
            out["pairwise_ciphers"].add(_cipher_name(sel[:3], sel[3]))
        if pos + 2 <= len(payload):
            (akm_count,) = struct.unpack_from("<H", payload, pos)
            pos += 2
            for _ in range(akm_count):
                sel = payload[pos:pos+4]
                pos += 4
                out["akms"].add(_akm_name(sel[:3], sel[3]))
        out["present"] = True
    except Exception:
        pass
    return out

# ------------------------------
# Sniffing / Processing
# ------------------------------

def extract_channel(pkt) -> Optional[int]:
    # Try DS Parameter Set (ID 3) first; for 5/6GHz vendors often include HT/VHT/HE ops IEs, which we skip here.
    ch = None
    elt = pkt.firstlayer()
    while elt and isinstance(elt, Dot11Elt):
        if elt.ID == 3 and elt.len == 1:
            ch = elt.info[0]
            break
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return ch


def process_mgmt_frame(pkt, aps: Dict[str, APInfo]):
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return
    bssid = pkt[Dot11].addr3 or pkt[Dot11].addr2
    if not bssid:
        return
    if bssid not in aps:
        aps[bssid] = APInfo(bssid=bssid, vendor=get_vendor(bssid))
    ap = aps[bssid]

    # NEW: Extract RSSI from RadioTap
    if pkt.haslayer(RadioTap):
        try:
            if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                rssi = pkt[RadioTap].dBm_AntSignal
                # Update RSSI (keep strongest signal)
                if ap.rssi is None or rssi > ap.rssi:
                    ap.rssi = rssi
        except Exception:
            pass

    # SSID & channel
    ssid = None
    channel = extract_channel(pkt)

    # NEW: Extract beacon interval
    if pkt.haslayer(Dot11Beacon):
        try:
            ap.beacon_interval = pkt[Dot11Beacon].beacon_interval
        except Exception:
            pass

    elt = pkt[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0:  # SSID
            try:
                ssid = elt.info.decode(errors="ignore")
                # NEW: Detect hidden SSID
                if ssid == "" or len(elt.info) == 0:
                    ap.hidden = True
            except Exception:
                ssid = ""
                ap.hidden = True

        elif elt.ID == 48:  # RSN
            ap.rsn_present = True
            rsn = parse_rsn_ie(bytes(elt.info))
            ap.group_cipher = rsn.get("group_cipher") or ap.group_cipher
            ap.pairwise_ciphers.update(rsn.get("pairwise_ciphers", []))
            ap.akms.update(rsn.get("akms", []))
            ap.pmf_capable = rsn.get("pmf_capable")
            ap.pmf_required = rsn.get("pmf_required")
            if "OWE" in ap.akms:
                ap.owe_present = True
            if any(a.startswith("FT-") for a in ap.akms):
                ap.ft_present = True

        elif elt.ID == 70:  # RRM Enabled Capabilities (802.11k)
            ap.rrm_enabled = True

        elif elt.ID == 127:  # Extended Capabilities (contains 802.11v BSS Transition)
            try:
                if len(elt.info) >= 3:
                    # Bit 19 (byte 2, bit 3) = BSS Transition
                    ap.bss_transition = bool(elt.info[2] & 0x08)
            except Exception:
                pass

        elif elt.ID == 61:  # HT Operation (channel width for 2.4/5GHz)
            try:
                if len(elt.info) >= 1:
                    # Bit 2 of byte 1: 0=20MHz, 1=40MHz
                    ap.channel_width = 40 if (elt.info[1] & 0x04) else 20
            except Exception:
                pass

        elif elt.ID == 192:  # VHT Operation (80/160MHz for 5GHz)
            try:
                if len(elt.info) >= 1:
                    ch_width = elt.info[0]
                    if ch_width == 1:
                        ap.channel_width = 80
                    elif ch_width in [2, 3]:
                        ap.channel_width = 160
            except Exception:
                pass

        elif elt.ID == 221:  # Vendor specific
            payload = bytes(elt.info)

            # Check for WPA v1
            wpa = parse_wpa1_vendor_ie(payload)
            if wpa.get("present"):
                ap.wpa1_present = True
                ap.group_cipher = ap.group_cipher or wpa.get("group_cipher")
                ap.pairwise_ciphers.update(wpa.get("pairwise_ciphers", []))
                ap.akms.update(wpa.get("akms", []))

            # NEW: Check for WPS
            wps = parse_wps_ie(payload)
            if wps.get("enabled"):
                ap.wps_enabled = True
                ap.wps_locked = wps.get("locked")
                ap.wps_version = wps.get("version")

        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None

    ap.channel = ap.channel or channel
    # NEW: Set band based on channel
    if ap.channel:
        ap.band = get_band(ap.channel)

    # Capability privacy bit (WEP indicator if RSN/WPA absent)
    cap = None
    if pkt.haslayer(Dot11Beacon):
        cap = pkt[Dot11Beacon].cap
    elif pkt.haslayer(Dot11ProbeResp):
        cap = pkt[Dot11ProbeResp].cap
    if cap is not None:
        ap.privacy_bit = bool(cap & 0x0010)

    if ssid is not None:
        ap.ssid = ssid


def process_eapol(pkt, aps: Dict[str, APInfo]):
    # Mark handshake observed for BSSID if we see EAPOL-Key frames
    if not pkt.haslayer(EAPOL):
        return
    # Guess the BSSID as the transmitter or receiver if they are AP MACs
    # In infrastructure BSS, addr2 is transmitter, addr1 is receiver, addr3 is BSSID.
    bssid = pkt[Dot11].addr3
    if bssid and bssid in aps:
        aps[bssid].handshake_observed = True


def process_deauth_disassoc(pkt, aps: Dict[str, APInfo]):
    """Count deauth and disassociation frames (potential attack indicator)."""
    if not pkt.haslayer(Dot11):
        return

    # Type 0 = Management, Subtype 12 = Deauth, Subtype 10 = Disassoc
    if pkt.type == 0:
        bssid = pkt[Dot11].addr3
        if bssid and bssid in aps:
            if pkt.subtype == 12:  # Deauth
                aps[bssid].deauth_count += 1
            elif pkt.subtype == 10:  # Disassoc
                aps[bssid].disassoc_count += 1


# ------------------------------
# CLI
# ------------------------------

def clear_screen():
    """Clear the terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')


def move_cursor_up(lines: int):
    """Move terminal cursor up by N lines."""
    print(f"\033[{lines}A", end='')


def clear_line():
    """Clear current line in terminal."""
    print("\033[2K", end='')


def save_cursor_position():
    """Save current cursor position."""
    print("\033[s", end='', flush=True)


def restore_cursor_position():
    """Restore saved cursor position."""
    print("\033[u", end='', flush=True)


def get_report_line_count(aps: Dict[str, APInfo]) -> int:
    """Calculate how many lines the report will occupy."""
    if not aps:
        return 1  # "No APs discovered."

    # Header lines: timestamp (1) + blank (1) + separator (1) + header (1) + separator (1) = 5
    # AP entries: len(aps)
    # Footer: separator (1) + blank (1) + Total APs (1) + WPS (1) + PMF (1) + WPA3 (1) + Hidden (1) = 7
    # Potential deauth warning: 1 (if present)

    base_lines = 5 + len(aps) + 7

    # Check if deauth warning will be shown
    deauth_aps = [ap for ap in aps.values() if ap.deauth_count > 10]
    if deauth_aps:
        base_lines += 1

    return base_lines


def print_report(aps: Dict[str, APInfo], show_timestamp: bool = False, show_ids: bool = False):
    if not aps:
        print("No APs discovered.")
        return

    # Sort by AP ID (if available), otherwise by RSSI
    if show_ids:
        sorted_aps = sorted(aps.items(), key=lambda kv: (kv[1].ap_id or 9999, -(kv[1].rssi or -100)))
    else:
        sorted_aps = sorted(aps.items(), key=lambda kv: (-(kv[1].rssi or -100), kv[1].ssid, kv[0]))

    # Show timestamp if in permanent mode
    if show_timestamp:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{Colors.BOLD}Last updated: {Colors.OKCYAN}{timestamp}{Colors.ENDC}")

    print("\n" + "="*127)
    if show_ids:
        print(f"{Colors.BOLD}{'ID':<4}  {'BSSID':<17}  {'RSSI':<7}  {'Ch':<3}  {'Band':<8}  {'SSID':<22}  {'Vendor':<14}  {'Security':<16}  {'Features'}{Colors.ENDC}")
    else:
        print(f"{Colors.BOLD}{'BSSID':<17}  {'RSSI':<7}  {'Ch':<3}  {'Band':<8}  {'SSID':<24}  {'Vendor':<16}  {'Security':<18}  {'Features'}{Colors.ENDC}")
    table_width = 127 if show_ids else 120
    print("="*table_width)

    for bssid, ap in sorted_aps:
        # Check if AP is currently visible - if not, gray out the entire line
        is_visible = getattr(ap, 'currently_visible', True)  # Default to True for backward compatibility
        gray_prefix = Colors.GRAY if not is_visible else ""
        gray_suffix = Colors.ENDC if not is_visible else ""

        # ID display (if enabled)
        if show_ids:
            if is_visible:
                id_str = f"{Colors.BOLD}{Colors.WARNING}{ap.ap_id:<3}{Colors.ENDC}" if ap.ap_id else f"{Colors.WARNING}?{Colors.ENDC}  "
            else:
                id_str = f"{Colors.GRAY}{ap.ap_id:<3}{Colors.ENDC}" if ap.ap_id else f"{Colors.GRAY}?{Colors.ENDC}  "
            id_padding = 4 + len(id_str) - 3  # Account for ANSI codes

        # Colorize BSSID
        if is_visible:
            bssid_colored = colorize_bssid(bssid)
        else:
            bssid_colored = f"{Colors.GRAY}{bssid}{Colors.ENDC}"

        # Colorize RSSI
        if is_visible:
            rssi_colored = colorize_rssi(ap.rssi)
        else:
            rssi_plain = f"{ap.rssi}dBm" if ap.rssi else "-"
            rssi_colored = f"{Colors.GRAY}{rssi_plain}{Colors.ENDC}"

        # Basic info - gray out if not visible
        if is_visible:
            ch_str = str(ap.channel) if ap.channel else "-"
            band_str = ap.band or "-"
        else:
            ch_str = f"{Colors.GRAY}{ap.channel if ap.channel else '-'}{Colors.ENDC}"
            band_str = f"{Colors.GRAY}{ap.band or '-'}{Colors.ENDC}"

        # SSID with proper truncation and colorization
        ssid_max_len = 22 if show_ids else 24
        if is_visible:
            if ap.hidden:
                ssid_display = colorize_ssid("", hidden=True)
                ssid_padding = ssid_max_len
            elif len(ap.ssid) > ssid_max_len:
                ssid_truncated = ap.ssid[:ssid_max_len-3] + "..."
                ssid_display = colorize_ssid(ssid_truncated)
                ssid_padding = ssid_max_len
            else:
                ssid_display = colorize_ssid(ap.ssid)
                ssid_padding = ssid_max_len + len(ssid_display) - len(ap.ssid)
        else:
            # Gray out SSID for invisible APs
            if ap.hidden:
                ssid_text = "<hidden>"
            elif len(ap.ssid) > ssid_max_len:
                ssid_text = ap.ssid[:ssid_max_len-3] + "..."
            else:
                ssid_text = ap.ssid
            ssid_display = f"{Colors.GRAY}{ssid_text}{Colors.ENDC}"
            ssid_padding = ssid_max_len + len(ssid_display) - len(ssid_text)

        # Vendor with proper truncation and colorization
        vendor_max_len = 14 if show_ids else 16
        if is_visible:
            if ap.vendor and len(ap.vendor) > vendor_max_len:
                vendor_truncated = ap.vendor[:vendor_max_len-3] + "..."
                vendor_display = colorize_vendor(vendor_truncated)
                vendor_padding = vendor_max_len
            else:
                vendor_text = ap.vendor or "Unknown"
                vendor_display = colorize_vendor(vendor_text)
                vendor_padding = vendor_max_len + len(vendor_display) - len(vendor_text)
        else:
            # Gray out vendor for invisible APs
            if ap.vendor and len(ap.vendor) > vendor_max_len:
                vendor_text = ap.vendor[:vendor_max_len-3] + "..."
            else:
                vendor_text = ap.vendor or "Unknown"
            vendor_display = f"{Colors.GRAY}{vendor_text}{Colors.ENDC}"
            vendor_padding = vendor_max_len + len(vendor_display) - len(vendor_text)

        # Security label - colorized
        sec = ap.security_label()
        if is_visible:
            sec_colored = colorize_security(sec)
        else:
            sec_colored = f"{Colors.GRAY}{sec}{Colors.ENDC}"
        sec_max_len = 16 if show_ids else 18
        sec_padding = sec_max_len + len(sec_colored) - len(sec)

        # Features column
        features = []
        if is_visible:
            if ap.wps_enabled:
                wps_status = f"{Colors.FAIL}🔓WPS{Colors.ENDC}" if ap.wps_locked is False else f"{Colors.WARNING}WPS{Colors.ENDC}"
                features.append(wps_status)
            if ap.pmf_required:
                features.append(f"{Colors.OKGREEN}PMF:req{Colors.ENDC}")
            elif ap.pmf_capable:
                features.append(f"{Colors.OKCYAN}PMF:cap{Colors.ENDC}")
            if ap.ft_present:
                features.append(f"{Colors.OKCYAN}FT{Colors.ENDC}")
            if ap.rrm_enabled:
                features.append(f"{Colors.OKCYAN}RRM{Colors.ENDC}")
            if ap.bss_transition:
                features.append(f"{Colors.OKCYAN}BSS-T{Colors.ENDC}")
            if ap.channel_width:
                features.append(f"{Colors.OKBLUE}{ap.channel_width}MHz{Colors.ENDC}")
            if ap.handshake_observed:
                features.append(f"{Colors.OKGREEN}4WH{Colors.ENDC}")
            if ap.deauth_count > 10:
                features.append(f"{Colors.FAIL}⚠️DA:{ap.deauth_count}{Colors.ENDC}")
        else:
            # Gray out features for invisible APs
            if ap.wps_enabled:
                wps_status = "🔓WPS" if ap.wps_locked is False else "WPS"
                features.append(f"{Colors.GRAY}{wps_status}{Colors.ENDC}")
            if ap.pmf_required:
                features.append(f"{Colors.GRAY}PMF:req{Colors.ENDC}")
            elif ap.pmf_capable:
                features.append(f"{Colors.GRAY}PMF:cap{Colors.ENDC}")
            if ap.ft_present:
                features.append(f"{Colors.GRAY}FT{Colors.ENDC}")
            if ap.rrm_enabled:
                features.append(f"{Colors.GRAY}RRM{Colors.ENDC}")
            if ap.bss_transition:
                features.append(f"{Colors.GRAY}BSS-T{Colors.ENDC}")
            if ap.channel_width:
                features.append(f"{Colors.GRAY}{ap.channel_width}MHz{Colors.ENDC}")
            if ap.handshake_observed:
                features.append(f"{Colors.GRAY}4WH{Colors.ENDC}")
            if ap.deauth_count > 10:
                features.append(f"{Colors.GRAY}⚠️DA:{ap.deauth_count}{Colors.ENDC}")

        features_str = " ".join(features) if features else "-"

        # Calculate BSSID padding for ANSI codes
        bssid_padding = 17 + len(bssid_colored) - len(bssid)

        # Calculate RSSI padding - simpler approach
        rssi_plain = f"{ap.rssi}dBm" if ap.rssi else "-"
        rssi_padding = 7 + len(rssi_colored) - len(rssi_plain)

        # Calculate channel and band padding for ANSI codes
        if is_visible:
            ch_padding = 3
            band_padding = 8
        else:
            ch_plain = str(ap.channel) if ap.channel else "-"
            band_plain = ap.band or "-"
            ch_padding = 3 + len(ch_str) - len(ch_plain)
            band_padding = 8 + len(band_str) - len(band_plain)

        # Print line with or without ID
        if show_ids:
            print(f"{id_str:<{id_padding}}  {bssid_colored:<{bssid_padding}}  {rssi_colored:<{rssi_padding}}  {ch_str:<{ch_padding}}  {band_str:<{band_padding}}  {ssid_display:<{ssid_padding}}  {vendor_display:<{vendor_padding}}  {sec_colored:<{sec_padding}}  {features_str}")
        else:
            print(f"{bssid_colored:<{bssid_padding}}  {rssi_colored:<{rssi_padding}}  {ch_str:<{ch_padding}}  {band_str:<{band_padding}}  {ssid_display:<{ssid_padding}}  {vendor_display:<{vendor_padding}}  {sec_colored:<{sec_padding}}  {features_str}")

    print("="*table_width)
    print(f"\n{Colors.BOLD}Total APs: {Colors.OKGREEN}{len(aps)}{Colors.ENDC}")

    wps_count = sum(1 for ap in aps.values() if ap.wps_enabled)
    pmf_count = sum(1 for ap in aps.values() if ap.pmf_required)
    wpa3_count = sum(1 for ap in aps.values() if 'SAE' in ap.akms)
    hidden_count = sum(1 for ap in aps.values() if ap.hidden)

    print(f"  • WPS enabled: {Colors.WARNING if wps_count > 0 else Colors.OKGREEN}{wps_count}{Colors.ENDC}")
    print(f"  • PMF required: {Colors.OKGREEN if pmf_count > 0 else Colors.WARNING}{pmf_count}{Colors.ENDC}")
    print(f"  • WPA3: {Colors.OKGREEN if wpa3_count > 0 else Colors.WARNING}{wpa3_count}{Colors.ENDC}")
    print(f"  • Hidden SSID: {Colors.OKCYAN}{hidden_count}{Colors.ENDC}")

    deauth_aps = [ap for ap in aps.values() if ap.deauth_count > 10]
    if deauth_aps:
        print(f"  • {Colors.FAIL}⚠️ Potential attacks detected: {len(deauth_aps)} APs with excessive deauth frames{Colors.ENDC}")


def scan_with_corewlan(timeout: int) -> Dict[str, APInfo]:
    """Scan for WiFi networks using macOS CoreWLAN (no monitor mode needed)."""
    if not COREWLAN_AVAILABLE:
        print("[!] CoreWLAN not available")
        return {}

    print(f"[*] Scanning with CoreWLAN for {timeout}s...")
    aps: Dict[str, APInfo] = {}

    try:
        # Get WiFi client and interface
        client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
        interface = client.interface()

        if not interface:
            print("[!] No WiFi interface found")
            return {}

        # Perform scan
        networks, error = interface.scanForNetworksWithName_error_(None, None)

        if error:
            print(f"[!] Scan error: {error}")
            return {}

        if not networks or len(networks) == 0:
            print("[!] No networks found")
            return {}

        print(f"[*] Found {len(networks)} networks")

        # Process each network
        for network in networks:
            bssid = network.bssid()
            if not bssid:
                continue

            ssid = network.ssid() or ""
            channel = network.wlanChannel().channelNumber() if network.wlanChannel() else None
            rssi = network.rssiValue()

            # Get vendor from BSSID
            vendor = get_vendor(bssid)

            # Create AP info
            ap = APInfo(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                rssi=rssi,
                vendor=vendor,
                hidden=(ssid == ""),
                band=get_band(channel) if channel else None
            )

            # Parse security settings from CoreWLAN
            # WPA/WPA2/WPA3 detection
            if hasattr(network, 'supportsSecurity_'):
                # Check for different security types
                if network.supportsSecurity_(CoreWLAN.kCWSecurityWPA2Personal):
                    ap.rsn_present = True
                    ap.akms.add("PSK")
                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPA2Enterprise):
                    ap.rsn_present = True
                    ap.akms.add("802.1X")
                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPAPersonal):
                    ap.wpa1_present = True
                    ap.akms.add("PSK")
                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPAEnterprise):
                    ap.wpa1_present = True
                    ap.akms.add("802.1X")
                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPA3Personal):
                    ap.rsn_present = True
                    ap.akms.add("SAE")
                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPA3Enterprise):
                    ap.rsn_present = True
                    ap.akms.add("802.1X-SHA256")

            # Check for WEP or Open
            if network.supportsSecurity_(CoreWLAN.kCWSecurityWEP):
                ap.privacy_bit = True
            elif network.supportsSecurity_(CoreWLAN.kCWSecurityNone):
                ap.privacy_bit = False

            # Get information elements data if available
            if hasattr(network, 'informationElementData'):
                ie_data = network.informationElementData()
                if ie_data:
                    # Parse IEs for additional info (WPS, PMF, etc.)
                    # This would require parsing the raw IE data
                    pass

            aps[bssid] = ap

    except Exception as e:
        print(f"[!] CoreWLAN scan error: {e}")

    return aps


def sniff_live(iface: str, timeout: int, observe_eapol: bool, channel: Optional[int] = None) -> Dict[str, APInfo]:
    aps: Dict[str, APInfo] = {}

    def _cb(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype in (8, 5):  # Beacon or ProbeResp
                process_mgmt_frame(pkt, aps)
            if observe_eapol and pkt.haslayer(EAPOL):
                process_eapol(pkt, aps)
            # NEW: Track deauth/disassoc frames
            if pkt.type == 0 and pkt.subtype in (10, 12):
                process_deauth_disassoc(pkt, aps)

    # Optionally, you can lock to a channel externally (iw set channel)
    print(f"[*] Sniffing on {iface} for {timeout}s…")
    try:
        sniff(iface=iface, prn=_cb, store=False, timeout=timeout)
    except PermissionError:
        print(f"\n[!] ERROR: Permission denied on interface '{iface}'")
        print(f"[!] Try running with sudo: sudo python3 {sys.argv[0]} -i {iface}")
        sys.exit(1)
    except OSError as e:
        if "No such device" in str(e):
            print(f"\n[!] ERROR: Interface '{iface}' not found")
            print(f"[!] Make sure the interface exists and is in monitor mode")
            print(f"[!] List available interfaces with: ip link show")
        else:
            print(f"\n[!] ERROR: Cannot access interface '{iface}': {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n[*] Capture interrupted by user")
    except Exception as e:
        print(f"\n[!] ERROR: Unexpected error during capture: {e}")
        sys.exit(1)
    return aps


def read_pcap(path: str, observe_eapol: bool) -> Dict[str, APInfo]:
    aps: Dict[str, APInfo] = {}

    # Validate file exists
    if not os.path.isfile(path):
        print(f"\n[!] ERROR: PCAP file not found: {path}")
        print(f"[!] Please check the file path and try again")
        sys.exit(1)

    # Check file extension
    if not path.endswith(('.pcap', '.pcapng', '.cap')):
        print(f"\n[!] WARNING: File '{path}' may not be a valid PCAP file")
        print(f"[!] Expected extensions: .pcap, .pcapng, .cap")

    print(f"[*] Reading {path}…")
    try:
        packets = rdpcap(path)
        if len(packets) == 0:
            print(f"[!] WARNING: PCAP file is empty (0 packets)")
            return aps

        print(f"[*] Processing {len(packets)} packets…")
        for pkt in packets:
            if pkt.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype in (8, 5):
                    process_mgmt_frame(pkt, aps)
                if observe_eapol and pkt.haslayer(EAPOL):
                    process_eapol(pkt, aps)
                # NEW: Track deauth/disassoc frames
                if pkt.type == 0 and pkt.subtype in (10, 12):
                    process_deauth_disassoc(pkt, aps)
    except FileNotFoundError:
        print(f"\n[!] ERROR: PCAP file not found: {path}")
        sys.exit(1)
    except PermissionError:
        print(f"\n[!] ERROR: Permission denied reading file: {path}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] ERROR: Failed to read PCAP file: {e}")
        print(f"[!] Make sure the file is a valid PCAP/PCAPNG file")
        sys.exit(1)

    return aps


def enable_monitor_mode(iface: str) -> bool:
    """Enable monitor mode on interface (cross-platform)."""
    import subprocess

    print(f"\n[*] Attempting to enable monitor mode on {iface}...")

    try:
        if sys.platform == 'darwin':  # macOS
            # macOS: Monitor mode requires special drivers or tools
            # Standard macOS doesn't support traditional monitor mode anymore
            print(f"[!] Native monitor mode is not supported on modern macOS")
            print(f"[!] Options:")
            print(f"    1. Use Wireshark with Remote Packet Capture (requires admin)")
            print(f"    2. Install nexmon drivers (for supported devices)")
            print(f"    3. Use a USB WiFi adapter with Linux drivers")
            print(f"\n[*] Attempting basic channel hopping mode...")

            # Try to at least disconnect from network
            airport_paths = [
                '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
                '/usr/sbin/airport'
            ]

            for airport_path in airport_paths:
                if os.path.exists(airport_path):
                    print(f"[*] Disassociating from current network...")
                    result = subprocess.run(['sudo', airport_path, '-z'],
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        print(f"[+] Disconnected from network")
                    break

            print(f"\n[!] macOS does not support true monitor mode via standard tools")
            print(f"[*] You can capture WiFi traffic with Wireshark or similar tools")
            return False

        elif sys.platform.startswith('linux'):  # Linux
            # Check if airmon-ng is available
            if os.path.exists('/usr/sbin/airmon-ng') or os.path.exists('/usr/local/sbin/airmon-ng'):
                print(f"[*] Using airmon-ng to enable monitor mode...")
                result = subprocess.run(['sudo', 'airmon-ng', 'start', iface],
                                      capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    # airmon-ng typically creates a new interface (e.g., wlan0mon)
                    output = result.stdout
                    if 'monitor mode enabled' in output.lower() or 'mon' in output:
                        print(f"[+] Monitor mode enabled")
                        # Try to extract the new interface name
                        for line in output.split('\n'):
                            if 'monitor mode' in line.lower() and 'enabled on' in line.lower():
                                print(f"[*] {line.strip()}")
                        return True
                    else:
                        print(f"[!] airmon-ng output: {output}")
                        return False
                else:
                    print(f"[!] airmon-ng failed: {result.stderr}")
                    return False
            else:
                # Try manual method using iwconfig
                print(f"[*] airmon-ng not found, trying manual method...")

                # First, bring interface down
                subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                             capture_output=True, timeout=10)

                # Try iwconfig method
                result = subprocess.run(['sudo', 'iwconfig', iface, 'mode', 'monitor'],
                                      capture_output=True, text=True, timeout=10)

                # Bring interface back up
                subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                             capture_output=True, timeout=10)

                if result.returncode == 0:
                    print(f"[+] Monitor mode enabled on {iface}")
                    return True
                else:
                    # Try iw command as fallback
                    subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                                 capture_output=True, timeout=10)
                    result = subprocess.run(['sudo', 'iw', 'dev', iface, 'set', 'type', 'monitor'],
                                          capture_output=True, text=True, timeout=10)
                    subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                                 capture_output=True, timeout=10)

                    if result.returncode == 0:
                        print(f"[+] Monitor mode enabled on {iface}")
                        return True
                    else:
                        print(f"[!] Failed to enable monitor mode: {result.stderr}")
                        return False

    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out")
        return False
    except Exception as e:
        print(f"[!] Error enabling monitor mode: {e}")
        return False


def disable_monitor_mode(iface: str) -> bool:
    """Disable monitor mode on interface (cross-platform)."""
    import subprocess

    print(f"\n[*] Disabling monitor mode on {iface}...")

    try:
        if sys.platform == 'darwin':  # macOS
            # macOS doesn't have true monitor mode to disable
            print(f"[*] No monitor mode to disable on macOS")
            print(f"[*] You may need to reconnect to your WiFi network manually")
            return True

        elif sys.platform.startswith('linux'):  # Linux
            # Check if airmon-ng is available
            if os.path.exists('/usr/sbin/airmon-ng') or os.path.exists('/usr/local/sbin/airmon-ng'):
                print(f"[*] Using airmon-ng to disable monitor mode...")
                result = subprocess.run(['sudo', 'airmon-ng', 'stop', iface],
                                      capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    print(f"[+] Monitor mode disabled")
                    return True
                else:
                    print(f"[!] airmon-ng failed: {result.stderr}")

            # Try manual method
            print(f"[*] Reverting to managed mode...")

            # Bring interface down
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                         capture_output=True, timeout=10)

            # Try iwconfig method
            result = subprocess.run(['sudo', 'iwconfig', iface, 'mode', 'managed'],
                                  capture_output=True, text=True, timeout=10)

            # Bring interface back up
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                         capture_output=True, timeout=10)

            if result.returncode == 0:
                print(f"[+] Managed mode restored on {iface}")
                return True
            else:
                # Try iw command as fallback
                subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                             capture_output=True, timeout=10)
                result = subprocess.run(['sudo', 'iw', 'dev', iface, 'set', 'type', 'managed'],
                                      capture_output=True, text=True, timeout=10)
                subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                             capture_output=True, timeout=10)

                if result.returncode == 0:
                    print(f"[+] Managed mode restored on {iface}")
                    return True
                else:
                    print(f"[!] Failed to disable monitor mode: {result.stderr}")
                    return False

    except Exception as e:
        print(f"[!] Error disabling monitor mode: {e}")
        return False


def check_monitor_mode(iface: str) -> bool:
    """Check if interface is in monitor mode."""
    import subprocess

    try:
        if sys.platform == 'darwin':  # macOS
            result = subprocess.run(['ifconfig', iface],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return 'monitor' in result.stdout.lower()
        elif sys.platform.startswith('linux'):
            result = subprocess.run(['iwconfig', iface],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return 'Mode:Monitor' in result.stdout
    except Exception:
        pass

    return False


def permanent_scan_mode(interval: int, observe_eapol: bool, iface: Optional[str] = None, channel: Optional[int] = None):
    """
    Permanent scan mode - continuously scan and update results in real-time.
    Maintains a pool of APs and updates display as networks come and go.

    Args:
        interval: Scan and display refresh interval in seconds (used for both scanning and display updates)
        observe_eapol: Whether to observe EAPOL frames
        iface: Interface to use (for Linux monitor mode)
        channel: Channel hint
    """
    import time
    import datetime
    import threading

    # AP pool - continuously updated
    ap_pool: Dict[str, APInfo] = {}
    ap_pool_lock = threading.Lock()
    scan_active = threading.Event()
    scan_active.set()

    # ID management
    next_ap_id = 1
    ap_id_lock = threading.Lock()

    previous_line_count = 0
    first_display = True
    last_change_time = datetime.datetime.now()  # When AP pool actually changed
    last_scan_time = datetime.datetime.now()    # When last scan completed
    last_scan_duration = 0.0  # Duration of last scan in seconds

    print(f"{Colors.BOLD}{Colors.OKGREEN}[*] Continuous scan mode activated{Colors.ENDC}")
    print(f"[*] Scan and display interval: every {interval}s")
    print(f"[*] Press Ctrl+C to exit\n")
    time.sleep(1)

    # Display update function
    def update_display():
        """Update the terminal display with current AP pool."""
        nonlocal previous_line_count, first_display

        # Get snapshot of current AP pool
        with ap_pool_lock:
            current_aps = dict(ap_pool)

        # Build output in a string buffer
        import io
        output_buffer = io.StringIO()

        # Redirect stdout temporarily to capture output
        import sys as sys_module
        old_stdout = sys_module.stdout
        sys_module.stdout = output_buffer

        try:
            # Display header
            print(f"{Colors.BOLD}=== AirDetect Continuous Scan Mode ==={Colors.ENDC}")
            scan_duration_str = f"{last_scan_duration:.2f}s" if last_scan_duration > 0 else "N/A"
            # Only show "last change" if it differs from scan time (more than 2 seconds difference)
            time_diff = abs((last_scan_time - last_change_time).total_seconds())
            if time_diff > 2:
                print(f"APs tracked: {len(current_aps)} - Scanned: {last_scan_time.strftime('%H:%M:%S')} ({scan_duration_str}) - Last change: {last_change_time.strftime('%H:%M:%S')}")
            else:
                print(f"APs tracked: {len(current_aps)} - Scanned: {last_scan_time.strftime('%H:%M:%S')} ({scan_duration_str})")

            # Display results
            if len(current_aps) == 0:
                print(f"\n{Colors.WARNING}[!] No access points detected yet... (scanning){Colors.ENDC}")
            else:
                print_report(current_aps, show_timestamp=False, show_ids=True)

            # Show status
            print(f"\n{Colors.OKCYAN}[*] Scanning continuously... Updates every {interval}s (Ctrl+C to exit){Colors.ENDC}")
        finally:
            sys_module.stdout = old_stdout

        # Get the complete output and strip trailing newlines
        output = output_buffer.getvalue().rstrip('\n')

        # Count actual lines
        output_lines = output.split('\n')
        current_line_count = len(output_lines)

        # Clear previous output (except on first display)
        if not first_display and previous_line_count > 0:
            # Move cursor up to start of previous output
            sys_module.stdout.write(f"\033[{previous_line_count}A")
            sys_module.stdout.flush()

        # Clear from cursor to end of screen, then print new output
        sys_module.stdout.write("\033[0J")  # Clear from cursor to end of screen
        sys_module.stdout.write(output)
        sys_module.stdout.write('\n')  # Add exactly ONE newline at the end
        sys_module.stdout.flush()

        # Store line count for next iteration
        previous_line_count = current_line_count
        first_display = False

    # Background scanning thread for CoreWLAN (or continuous Scapy)
    def background_scanner():
        """Background thread that continuously scans and updates display."""
        nonlocal ap_pool, last_change_time, last_scan_time, last_scan_duration
        import sys as sys_module  # Import locally to avoid scope issues

        # For CoreWLAN, we need a separate client instance for thread safety
        if sys_module.platform == 'darwin' and COREWLAN_AVAILABLE:
            try:
                client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
                interface = client.interface()
                if not interface:
                    print(f"[!] Background scanner: No WiFi interface found")
                    return
            except Exception as e:
                print(f"[!] Background scanner: CoreWLAN init failed: {e}")
                return

        while scan_active.is_set():
            try:
                if sys_module.platform == 'darwin' and COREWLAN_AVAILABLE:
                    # CoreWLAN: Quick scan using thread-local interface
                    scan_start = time.time()
                    networks, error = interface.scanForNetworksWithName_error_(None, None)
                    scan_end = time.time()

                    # Calculate scan duration and update timestamps
                    last_scan_duration = scan_end - scan_start
                    last_scan_time = datetime.datetime.now()

                    if error:
                        # Ignore "Resource busy" errors (happens during concurrent scans)
                        if "16" not in str(error):  # Error code 16 = EBUSY
                            print(f"[!] Background scan error: {error}")
                    elif networks:
                        # Mark all APs as not visible before this scan
                        with ap_pool_lock:
                            for ap in ap_pool.values():
                                ap.currently_visible = False

                        new_aps = {}
                        for network in networks:
                            bssid = network.bssid()
                            if not bssid:
                                continue

                            ssid = network.ssid() or ""
                            channel = network.wlanChannel().channelNumber() if network.wlanChannel() else None
                            rssi = network.rssiValue()
                            vendor = get_vendor(bssid)

                            ap = APInfo(
                                bssid=bssid,
                                ssid=ssid,
                                channel=channel,
                                rssi=rssi,
                                vendor=vendor,
                                hidden=(ssid == ""),
                                band=get_band(channel) if channel else None
                            )

                            # Parse security
                            if hasattr(network, 'supportsSecurity_'):
                                if network.supportsSecurity_(CoreWLAN.kCWSecurityWPA2Personal):
                                    ap.rsn_present = True
                                    ap.akms.add("PSK")
                                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPA2Enterprise):
                                    ap.rsn_present = True
                                    ap.akms.add("802.1X")
                                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPAPersonal):
                                    ap.wpa1_present = True
                                    ap.akms.add("PSK")
                                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPAEnterprise):
                                    ap.wpa1_present = True
                                    ap.akms.add("802.1X")
                                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPA3Personal):
                                    ap.rsn_present = True
                                    ap.akms.add("SAE")
                                elif network.supportsSecurity_(CoreWLAN.kCWSecurityWPA3Enterprise):
                                    ap.rsn_present = True
                                    ap.akms.add("802.1X-SHA256")

                            if network.supportsSecurity_(CoreWLAN.kCWSecurityWEP):
                                ap.privacy_bit = True
                            elif network.supportsSecurity_(CoreWLAN.kCWSecurityNone):
                                ap.privacy_bit = False

                            new_aps[bssid] = ap

                        # Merge into pool
                        pool_changed = False
                        with ap_pool_lock:
                            # Check for visibility changes (APs that disappeared)
                            for existing_ap in ap_pool.values():
                                if existing_ap.currently_visible and existing_ap.bssid not in new_aps:
                                    pool_changed = True
                                    break

                            for bssid, ap in new_aps.items():
                                current_time = time.time()
                                if bssid in ap_pool:
                                    old_ap = ap_pool[bssid]
                                    # Check if AP was invisible and is now visible again
                                    if not old_ap.currently_visible:
                                        pool_changed = True
                                    # Keep existing ID and first_seen
                                    ap.ap_id = old_ap.ap_id
                                    ap.first_seen = old_ap.first_seen
                                    # Update last_seen
                                    ap.last_seen = current_time
                                    # Mark as currently visible
                                    ap.currently_visible = True
                                    # Keep the strongest RSSI seen
                                    if ap.rssi and old_ap.rssi:
                                        ap.rssi = max(ap.rssi, old_ap.rssi)
                                    # Merge other properties
                                    ap.handshake_observed = ap.handshake_observed or old_ap.handshake_observed
                                    ap.deauth_count += old_ap.deauth_count
                                    ap.disassoc_count += old_ap.disassoc_count
                                else:
                                    # New AP - assign ID
                                    pool_changed = True
                                    with ap_id_lock:
                                        nonlocal next_ap_id
                                        ap.ap_id = next_ap_id
                                        next_ap_id += 1
                                    ap.first_seen = current_time
                                    ap.last_seen = current_time
                                    # New APs are visible
                                    ap.currently_visible = True
                                ap_pool[bssid] = ap

                        # Update change time if pool changed
                        if pool_changed:
                            last_change_time = datetime.datetime.now()

                        # Update display immediately after scan
                        update_display()

                    time.sleep(interval)  # Wait between CoreWLAN scans

                elif iface:
                    # Scapy: Continuous packet capture
                    # Use callback to update pool in real-time
                    def packet_callback(pkt):
                        if not scan_active.is_set():
                            return

                        temp_aps = {}
                        if pkt.haslayer(Dot11):
                            if pkt.type == 0 and pkt.subtype in (8, 5):  # Beacon or ProbeResp
                                process_mgmt_frame(pkt, temp_aps)
                            if observe_eapol and pkt.haslayer(EAPOL):
                                process_eapol(pkt, temp_aps)
                            if pkt.type == 0 and pkt.subtype in (10, 12):
                                process_deauth_disassoc(pkt, temp_aps)

                        # Merge into main pool
                        if temp_aps:
                            pool_changed = False
                            with ap_pool_lock:
                                for bssid, ap in temp_aps.items():
                                    current_time = time.time()
                                    if bssid in ap_pool:
                                        old_ap = ap_pool[bssid]
                                        # Keep existing ID and first_seen
                                        ap.ap_id = old_ap.ap_id
                                        ap.first_seen = old_ap.first_seen
                                        # Update last_seen
                                        ap.last_seen = current_time
                                        if ap.rssi and old_ap.rssi:
                                            ap.rssi = max(ap.rssi, old_ap.rssi)
                                        ap.handshake_observed = ap.handshake_observed or old_ap.handshake_observed
                                        ap.deauth_count += old_ap.deauth_count
                                    else:
                                        # New AP - assign ID
                                        pool_changed = True
                                        with ap_id_lock:
                                            nonlocal next_ap_id
                                            ap.ap_id = next_ap_id
                                            next_ap_id += 1
                                        ap.first_seen = current_time
                                        ap.last_seen = current_time
                                    ap_pool[bssid] = ap

                            # Update timestamps (outside of loop but inside lock is ok here)
                            last_scan_time = datetime.datetime.now()
                            if pool_changed:
                                last_change_time = last_scan_time

                    # Continuous sniff
                    sniff(iface=iface, prn=packet_callback, store=False, stop_filter=lambda x: not scan_active.is_set())

            except Exception as e:
                if scan_active.is_set():  # Only print if not shutting down
                    print(f"\n[!] Background scanner error: {e}")
                break

    # Start background scanner (now also handles display)
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    try:
        # Main thread just waits for Ctrl+C
        scanner_thread.join()

    except KeyboardInterrupt:
        print(f"\n\n{Colors.OKGREEN}[*] Continuous scan mode stopped by user{Colors.ENDC}")
        print(f"Total APs discovered: {len(ap_pool)}")
    finally:
        # Stop background scanner
        scan_active.clear()
        scanner_thread.join(timeout=2)


def list_interfaces():
    """List all available wireless interfaces on the system."""
    print("[*] Scanning for wireless interfaces...\n")

    interfaces = []

    try:
        # Try using scapy's get_if_list
        from scapy.arch import get_if_list
        all_ifaces = get_if_list()

        # Filter for wireless interfaces
        for iface in all_ifaces:
            # Check if it's a wireless interface by checking for common patterns
            if 'wlan' in iface.lower() or 'wifi' in iface.lower() or 'en' in iface.lower():
                # Try to get more info using iwconfig or airport on macOS
                mode = "Unknown"
                status = "Unknown"

                # Check if interface is in monitor mode
                if 'mon' in iface.lower():
                    mode = "Monitor"
                else:
                    mode = "Managed"

                interfaces.append({
                    'name': iface,
                    'mode': mode,
                    'status': status
                })

        # Also try to get info from system commands
        if sys.platform == 'darwin':  # macOS
            import subprocess
            try:
                # Use networksetup to get WiFi interface info
                result = subprocess.run(['networksetup', '-listallhardwareports'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    wifi_interfaces_from_system = []

                    for i, line in enumerate(lines):
                        if 'Wi-Fi' in line or 'AirPort' in line:
                            # Next lines contain Device info
                            if i + 1 < len(lines):
                                device_line = lines[i + 1]
                                if 'Device:' in device_line:
                                    iface_name = device_line.split('Device:')[1].strip()
                                    wifi_interfaces_from_system.append(iface_name)

                    # Update or add WiFi interfaces with proper type
                    for wifi_iface in wifi_interfaces_from_system:
                        existing = next((x for x in interfaces if x['name'] == wifi_iface), None)
                        if existing:
                            existing['status'] = 'WiFi Adapter'
                        else:
                            interfaces.append({
                                'name': wifi_iface,
                                'mode': 'Managed',
                                'status': 'WiFi Adapter'
                            })

                    # Remove non-WiFi en interfaces from list
                    interfaces = [i for i in interfaces if i['name'] in wifi_interfaces_from_system or 'mon' in i['name'].lower() or 'wlan' in i['name'].lower()]

            except Exception:
                pass

        elif sys.platform.startswith('linux'):  # Linux
            import subprocess
            try:
                # Use iwconfig to list wireless interfaces
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'IEEE 802.11' in line or 'ESSID' in line:
                            iface_name = line.split()[0]
                            if iface_name and not any(x['name'] == iface_name for x in interfaces):
                                # Check mode
                                if 'Mode:Monitor' in line:
                                    mode = 'Monitor'
                                else:
                                    mode = 'Managed'

                                interfaces.append({
                                    'name': iface_name,
                                    'mode': mode,
                                    'status': 'Available'
                                })
            except Exception:
                pass

    except Exception as e:
        print(f"[!] Error scanning interfaces: {e}")
        return

    # Display results
    if not interfaces:
        print("[!] No wireless interfaces found")
        print("[!] Make sure you have a WiFi adapter installed")
        if sys.platform.startswith('linux'):
            print("[*] Try: iwconfig  # to list wireless interfaces")
        elif sys.platform == 'darwin':
            print("[*] Try: networksetup -listallhardwareports")
    else:
        print("="*70)
        print(f"{'Interface':<20} {'Mode':<15} {'Status'}")
        print("="*70)
        for iface in interfaces:
            print(f"{iface['name']:<20} {iface['mode']:<15} {iface['status']}")
        print("="*70)
        print(f"\nTotal interfaces found: {len(interfaces)}")

        # Show hints
        monitor_ifaces = [i for i in interfaces if i['mode'] == 'Monitor']
        if monitor_ifaces:
            print(f"\n[*] Monitor mode interfaces: {', '.join([i['name'] for i in monitor_ifaces])}")
            print(f"[*] Use with: sudo python3 {sys.argv[0]} -i {monitor_ifaces[0]['name']}")
        else:
            print("\n[!] No monitor mode interfaces found")
            if sys.platform.startswith('linux'):
                print("[*] Enable monitor mode with: sudo airmon-ng start wlan0")
            elif sys.platform == 'darwin':
                print("[*] macOS requires special tools for monitor mode")
                print("[*] Check: https://github.com/seemoo-lab/nexmon")


def main():
    p = argparse.ArgumentParser(description="Passive Wi‑Fi AP security analyzer (beacons/probe responses/optional EAPOL)")
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("-i", "--iface", help="Monitor‑mode interface (e.g. wlan0mon)")
    src.add_argument("-r", "--read", help="Read from pcap instead of live capture")
    src.add_argument("-l", "--list-interfaces", action="store_true", help="List all available wireless interfaces and exit")
    p.add_argument("-t", "--timeout", type=int, default=30, help="Sniffing duration in seconds (non-permanent mode only)")
    p.add_argument("-I", "--interval", type=int, default=5, help="Scan and display refresh interval in seconds (permanent mode only, default: 5s)")
    p.add_argument("--eapol", action="store_true", help="Also mark if a 4‑Way Handshake was observed (EAPOL frames)")
    p.add_argument("--channel", type=int, help="Hint: channel to scan (set with iw/airmon externally; this is informational only)")
    p.add_argument("-p", "--permanent", action="store_true", help="Continuous scan mode - maintains AP pool and updates display in real-time")

    args = p.parse_args()

    # Handle list-interfaces
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # Now require either -i or -r if not listing
    # Exception: macOS with CoreWLAN doesn't need -i
    if not args.iface and not args.read:
        if sys.platform == 'darwin' and COREWLAN_AVAILABLE:
            # macOS with CoreWLAN can scan without interface argument
            pass
        else:
            p.error("one of the arguments -i/--iface -r/--read is required")
            sys.exit(1)

    # Validate timeout value
    if args.timeout and args.timeout <= 0:
        print(f"[!] ERROR: Timeout must be a positive number (got: {args.timeout})")
        sys.exit(1)

    # Validate interval
    if args.interval and args.interval <= 0:
        print(f"[!] ERROR: Interval must be a positive number (got: {args.interval})")
        sys.exit(1)

    # Permanent mode not allowed with pcap file
    if args.permanent and args.read:
        print(f"[!] ERROR: Permanent mode (-p) cannot be used with pcap file (-r)")
        sys.exit(1)

    monitor_enabled_by_us = False

    try:
        if args.read:
            # PCAP file mode
            aps = read_pcap(args.read, args.eapol)
            if len(aps) == 0:
                print("\n[!] No access points detected")
                print("[!] Possible reasons:")
                print("    • PCAP file contains no 802.11 beacon/probe response frames")
                print("    • PCAP was captured on a non-WiFi interface")
            else:
                print_report(aps)

        elif args.permanent:
            # Permanent scan mode
            if sys.platform == 'darwin' and COREWLAN_AVAILABLE:
                print(f"[*] macOS detected - using CoreWLAN (no monitor mode required)")
                permanent_scan_mode(args.interval, args.eapol)
            else:
                # Linux - check monitor mode first
                if not check_monitor_mode(args.iface):
                    print(f"\n[!] Interface '{args.iface}' is not in monitor mode")
                    print(f"[?] Do you want to enable monitor mode on {args.iface}? (y/n): ", end='', flush=True)
                    response = input().strip().lower()

                    if response == 'y':
                        if enable_monitor_mode(args.iface):
                            monitor_enabled_by_us = True
                            print(f"[*] Monitor mode enabled. Starting permanent scan...")
                        else:
                            print(f"[!] Could not enable monitor mode automatically.")
                            if sys.platform.startswith('linux'):
                                print(f"[*] Try manually:")
                                print(f"    sudo airmon-ng start {args.iface}")
                            sys.exit(1)
                    else:
                        print("[!] Monitor mode is required for live capture. Exiting.")
                        sys.exit(0)

                permanent_scan_mode(args.interval, args.eapol, args.iface, args.channel)

        else:
            # Single scan mode
            if sys.platform == 'darwin' and COREWLAN_AVAILABLE:
                print(f"[*] macOS detected - using CoreWLAN (no monitor mode required)")
                aps = scan_with_corewlan(args.timeout)
            else:
                # Linux or macOS without CoreWLAN: Use Scapy (requires monitor mode)
                # Check if interface is in monitor mode before sniffing
                if not check_monitor_mode(args.iface):
                    print(f"\n[!] Interface '{args.iface}' is not in monitor mode")

                    # Ask user if they want to enable monitor mode
                    print(f"[?] Do you want to enable monitor mode on {args.iface}? (y/n): ", end='', flush=True)
                    response = input().strip().lower()

                    if response == 'y':
                        if enable_monitor_mode(args.iface):
                            monitor_enabled_by_us = True
                            print(f"[*] Monitor mode enabled. Starting capture...")
                        else:
                            print(f"[!] Could not enable monitor mode automatically.")
                            if sys.platform.startswith('linux'):
                                print(f"[*] Try manually:")
                                print(f"    sudo airmon-ng start {args.iface}")
                            sys.exit(1)
                    else:
                        print("[!] Monitor mode is required for live capture. Exiting.")
                        sys.exit(0)

                aps = sniff_live(args.iface, args.timeout, args.eapol, args.channel)

            if len(aps) == 0:
                print("\n[!] No access points detected")
                print("[!] Possible reasons:")
                print(f"    • No WiFi traffic on the current channel")
                print(f"    • Timeout ({args.timeout}s) too short")
                print(f"    • Try increasing timeout with -t option")
            else:
                print_report(aps)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"\n[!] FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup: Disable monitor mode if we enabled it
        if monitor_enabled_by_us and args.iface:
            print(f"\n[?] Disable monitor mode on {args.iface}? (y/n): ", end='', flush=True)
            try:
                response = input().strip().lower()
                if response == 'y':
                    disable_monitor_mode(args.iface)
                    print(f"[*] You can now use WiFi normally.")
                else:
                    print(f"[*] Monitor mode still active on {args.iface}")
                    if sys.platform.startswith('linux'):
                        print(f"[*] To disable later: sudo airmon-ng stop {args.iface}")
                        print(f"[*] Or: sudo iwconfig {args.iface} mode managed")
            except (KeyboardInterrupt, EOFError):
                print(f"\n[*] Keeping monitor mode active on {args.iface}")


if __name__ == "__main__":
    main()

