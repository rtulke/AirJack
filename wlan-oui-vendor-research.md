# OUI/MAC Vendor Data – Sources & Integration for WLAN Scanners
*As of: 05.11.2025, 11:54 (Europe/Zurich)*

This guide aggregates **official IEEE sources**, **curated/manually maintained datasets** (Wireshark, Nmap, arp‑scan, Aircrack‑NG), **APIs**, and **libraries** (Python, Go, Node) for integrating OUI/MAC vendor data into WLAN scanner tools. Also included: notes on **Vendor‑Specific IEs** (WPA/RSN/WMM/WPS) and **MAC randomization (U/L bit)**.

---

## 1) Official IEEE Sources (Registration Authority)

IEEE provides machine-readable datasets. For full coverage, mirror and merge **all** of the following CSVs regularly:

- **MA‑L (OUI / 24‑Bit)** – CSV  
  https://standards-oui.ieee.org/oui/oui.csv
- **MA‑M (MAM / 28‑Bit)** – CSV  
  https://standards-oui.ieee.org/oui28/mam.csv
- **MA‑S (OUI‑36 / 36‑Bit)** – CSV  
  https://standards-oui.ieee.org/oui36/oui36.csv
- **IAB (36‑Bit, Altbestand)** – CSV  
  https://standards-oui.ieee.org/iab/iab.csv
- **Portalübersicht**  
  https://standards-oui.ieee.org/

**Note (U/L bit & EUI terminology):**  
- IEEE FAQ on EUI/OUI/CID: https://standards.ieee.org/faqs/regauth/  
- IEEE tutorial (U/L bit, I/G bit): https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/eui.pdf

---

## 2) Wireshark (manuf) & Tools

- **Wireshark „manuf“ (Herstellerauflösung)** – Beschreibung & Dump‑Hinweis  
  https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html  
  > Tip: `tshark -G manuf` prints the compiled state in `manuf` format.
- **Wireshark OUI‑Lookup (Web)**  
  https://www.wireshark.org/tools/oui-lookup.html
- **Wireshark News (manuf aus Build‑Verzeichnis)**  
  https://www.wireshark.org/news/20231025.html  
  (Download‑Pfad wird dort referenziert; üblich ist *download/automated/data/manuf*.)

**Example: export `manuf`**

```bash
tshark -G manuf > manuf.txt
```

---

## 3) Nmap (nmap‑mac‑prefixes)

- **Datenfile in SVN (aktuell gehalten)**  
  https://svn.nmap.org/nmap/nmap-mac-prefixes
- **Handbuchkapitel / Dateipfade**  
  https://nmap.org/book/nmap-mac-prefixes.html  
  https://nmap.org/book/data-files.html

**Example: update file (Linux/Kali):**
```bash
sudo curl -L -o /usr/share/nmap/nmap-mac-prefixes \
  https://svn.nmap.org/nmap/nmap-mac-prefixes
```

---

## 4) arp‑scan (`get-oui`) & Debian/Ubuntu `ieee-data`

- **Manpage `get-oui` (Ubuntu)**  
  https://manpages.ubuntu.com/manpages/bionic/man1/get-oui.1.html  
  https://manpages.debian.org/unstable/arp-scan/get-oui.1.en.html
- **Debian Paket `ieee-data`**  
  https://packages.debian.org/sid/ieee-data  
  Beispiel‑Inhalt: https://sources.debian.org/src/ieee-data/20180805.1/oui36.txt/
- **Change/bug‑Hinweise zu URL‑Umstellungen**  
  https://bugs.debian.org/908623  
  https://bugs.launchpad.net/bugs/1796047

**Example: update and generate for arp‑scan**
```bash
sudo update-ieee-data && sudo get-oui
# erzeugt /usr/share/arp-scan/ieee-oui.txt
```

---

## 5) Aircrack‑NG (airodump‑ng‑oui‑update)

- **Airodump‑NG Doku**  
  https://www.aircrack-ng.org/doku.php?id=airodump-ng
- **Manpage airodump‑ng‑oui‑update**  
  https://man.archlinux.org/man/airodump-ng-oui-update.8.en  
  (weitere Hinweise: https://www.kali.org/tools/aircrack-ng/)

**Example:**
```bash
sudo airodump-ng-oui-update
# Aktualisiert die lokale OUI-Datenbasis für airodump-ng
```

---

## 6) APIs & Online Services (for quick lookups/enrichment)

> For production scanners prefer **local, versioned mirrors** of the IEEE CSVs. Online APIs are good for ad‑hoc checks/enrichment.

- **macaddress.io** – API & Doku  
  https://macaddress.io/  
  https://macaddress.io/api  
  https://macaddress.io/api/documentation  
  https://macaddress.io/api/documentation/output-format
- **MACVendors.com** – API  
  https://macvendors.com/  
  https://macvendors.com/api
- **macvendors.co** – API  
  https://macvendors.co/  
  https://macvendors.co/api

---

## 7) Libraries

### Python
- **`manuf` (Wireshark manuf‑Parser)**  
  https://github.com/coolbho3k/manuf

### Go
- **`github.com/endobit/oui`** (aus IEEE CSV generiert)  
  https://pkg.go.dev/github.com/endobit/oui
- **`github.com/klauspost/oui`**  
  https://github.com/klauspost/oui

### JavaScript/Node
- **`oui-data` (JSON‑Paket, regelmäßig aktualisiert)**  
  https://github.com/silverwind/oui-data  
  CDN‑Beispiel: https://unpkg.com/oui-data/

---

## 8) 802.11 Vendor‑Specific IEs (WPA/RSN/WMM/WPS)

- **WPA IE (Vendor‑Specific, Element ID 221, OUI 00:50:F2)**  
  https://www.hitchhikersguidetolearning.com/2017/09/17/wpa-information-element/  
  Beispiel‑Decode mit OUI 00:50:f2: https://stackoverflow.com/q/65731968
- **RSN IE (Element ID 48, OUI 00:0F:AC)**  
  Aruba TechDocs (AKM‑Suite‑Selector): https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/modes/

This is relevant when your scanner passively parses **IEs in Beacons/Probe Responses** and needs to derive vendor/features from **vendor OUIs**.

---

## 9) MAC Randomization & U/L Bit

- **Wikipedia – MAC Address (U/L‑Bit Erklärung)**  
  https://en.wikipedia.org/wiki/MAC_address
- **IEEE Tutorial (I/G & U/L Bits)**  
  https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/eui.pdf

**Quick rule for locally administered MACs (LAA):**  
The **U/L bit = 1** (second LSB of the first octet). Hex second nibble ∈ {{2, 6, A, E}}.

---

## 10) Parsing Tips & Pipeline

- **Merge data sources:** normalize `oui.csv` (24b), `mam.csv` (28b), `oui36.csv` (36b), `iab.csv` (36b) into **one format** (e.g., JSON) and resolve via **prefix trie** or **longest-prefix match**.
- **Mind differences:** Wireshark *manuf* and Nmap *nmap‑mac‑prefixes* are **curated** derivatives. On conflicts, treat **IEEE** as source of truth.
- **Reproducibility:** version snapshots (timestamp, SHA256) and document update interval (e.g., daily/weekly).

**Mini‑Beispiel (Shell):**
```bash
# 1) CSVs ziehen
curl -O https://standards-oui.ieee.org/oui/oui.csv
curl -O https://standards-oui.ieee.org/oui28/mam.csv
curl -O https://standards-oui.ieee.org/oui36/oui36.csv
curl -O https://standards-oui.ieee.org/iab/iab.csv

# 2) (Optional) Wireshark/Nmap als Zusatzquellen
# (Webtool-Link hier nur als Referenz; für maschinelle Nutzung nutze manuf Dump oder CSVs)
curl -L -o nmap-mac-prefixes https://svn.nmap.org/nmap/nmap-mac-prefixes

# 3) Build your own JSON (e.g., with Python) and use it in the tool
```

---

## 11) All referenced links (compact)

**IEEE / basics**
- https://standards-oui.ieee.org/  
- https://standards-oui.ieee.org/oui/oui.csv  
- https://standards-oui.ieee.org/oui28/mam.csv  
- https://standards-oui.ieee.org/oui36/oui36.csv  
- https://standards-oui.ieee.org/iab/iab.csv  
- https://standards.ieee.org/faqs/regauth/  
- https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/eui.pdf  
- https://en.wikipedia.org/wiki/MAC_address

**Wireshark**
- https://www.wireshark.org/tools/oui-lookup.html  
- https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html  
- https://www.wireshark.org/news/20231025.html

**Nmap**
- https://svn.nmap.org/nmap/nmap-mac-prefixes  
- https://nmap.org/book/nmap-mac-prefixes.html  
- https://nmap.org/book/data-files.html

**arp‑scan / ieee‑data (Debian/Ubuntu)**
- https://manpages.ubuntu.com/manpages/bionic/man1/get-oui.1.html  
- https://manpages.debian.org/unstable/arp-scan/get-oui.1.en.html  
- https://packages.debian.org/sid/ieee-data  
- https://sources.debian.org/src/ieee-data/20180805.1/oui36.txt/  
- https://bugs.debian.org/908623  
- https://bugs.launchpad.net/bugs/1796047

**Aircrack‑NG**
- https://www.aircrack-ng.org/doku.php?id=airodump-ng  
- https://man.archlinux.org/man/airodump-ng-oui-update.8.en  
- https://www.kali.org/tools/aircrack-ng/

**APIs / Services**
- https://macaddress.io/  
- https://macaddress.io/api  
- https://macaddress.io/api/documentation  
- https://macaddress.io/api/documentation/output-format  
- https://macvendors.com/  
- https://macvendors.com/api  
- https://macvendors.co/  
- https://macvendors.co/api

**Libraries**
- https://github.com/coolbho3k/manuf  
- https://pkg.go.dev/github.com/endobit/oui  
- https://github.com/klauspost/oui  
- https://github.com/silverwind/oui-data  
- https://unpkg.com/oui-data/

**802.11 IEs (WPA/RSN)**
- https://www.hitchhikersguidetolearning.com/2017/09/17/wpa-information-element/  
- https://stackoverflow.com/questions/65731968/how-to-get-wifi-security-keywpa-wpa2-ess-of-scanned-networks-using-nl80211-b  
- https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/modes/

---

**License/Compliance note:** Check usage terms of each data source/tool (especially IEEE data, API TOS). For production distribution, prefer **local mirrors** of the IEEE CSVs incl. source/version documentation.
