# OUI/MAC Vendor Daten – Quellen & Integration für WLAN‑Scanner
*Stand: 05.11.2025, 11:54 (Europe/Zurich)*

Dieser Leitfaden bündelt **offizielle IEEE‑Quellen**, **kuratierte/manuell gepflegte Datenbestände** (Wireshark, Nmap, arp‑scan, Aircrack‑NG), **APIs**, sowie **Bibliotheken** (Python, Go, Node) für die Integration von OUI/MAC‑Vendor‑Daten in WLAN‑Scanner‑Tools. Außerdem enthalten: Hinweise zu **Vendor‑Specific IEs** (WPA/RSN/WMM/WPS) und **MAC‑Randomisierung (U/L‑Bit)**.

---

## 1) Offizielle IEEE‑Quellen (Registration Authority)

Die IEEE stellt die Datensätze maschinenlesbar bereit. Für vollständige Abdeckung solltest du **alle** folgenden CSVs periodisch spiegeln und zusammenführen:

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

**Hinweis (U/L‑Bit & EUI‑Begriffe):**  
- IEEE FAQ zur EUI/OUI/CID: https://standards.ieee.org/faqs/regauth/  
- IEEE Tutorial (U/L‑Bit, I/G‑Bit): https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/eui.pdf

---

## 2) Wireshark (manuf) & Tools

- **Wireshark „manuf“ (Herstellerauflösung)** – Beschreibung & Dump‑Hinweis  
  https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html  
  > Tipp: `tshark -G manuf` gibt den kompilierten Stand im `manuf`‑Format aus.
- **Wireshark OUI‑Lookup (Web)**  
  https://www.wireshark.org/tools/oui-lookup.html
- **Wireshark News (manuf aus Build‑Verzeichnis)**  
  https://www.wireshark.org/news/20231025.html  
  (Download‑Pfad wird dort referenziert; üblich ist *download/automated/data/manuf*.)

**Beispiel: `manuf` exportieren**

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

**Beispiel: Datei aktualisieren (Linux/Kali):**
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

**Beispiel: aktualisieren und für arp‑scan generieren**
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

**Beispiel:**
```bash
sudo airodump-ng-oui-update
# Aktualisiert die lokale OUI-Datenbasis für airodump-ng
```

---

## 6) APIs & Online‑Dienste (für Schnellabfragen/Enrichment)

> Für produktive Scanner bevorzuge **lokale, versionierte Spiegel** der IEEE‑CSVs. Online‑APIs eignen sich gut für Ad‑hoc‑Checks/Enrichment.

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

## 7) Programmbibliotheken

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

Diese Infos sind relevant, wenn dein Scanner **IEs in Beacons/Probe Responses** passiv auswertet und Hersteller/Features aus **Vendor‑OUIs** ableiten soll.

---

## 9) MAC‑Randomisierung & U/L‑Bit

- **Wikipedia – MAC Address (U/L‑Bit Erklärung)**  
  https://en.wikipedia.org/wiki/MAC_address
- **IEEE Tutorial (I/G & U/L Bits)**  
  https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/eui.pdf

**Kurzmerkregel für lokal vergebene MACs (LAA):**  
Das **U/L‑Bit = 1** (zweites LSB des ersten Oktetts). Hex‑Zweitziffer ∈ {{2, 6, A, E}}.

---

## 10) Parsing‑Tipps & Pipeline

- **Datenquellen zusammenführen:** `oui.csv` (24b), `mam.csv` (28b), `oui36.csv` (36b), `iab.csv` (36b) in **ein Format** normalisieren (z. B. JSON) und per **Präfix‑Trie** oder **Longest‑Prefix‑Match** auflösen.
- **Differenzen beachten:** Wireshark *manuf* und Nmap *nmap‑mac‑prefixes* sind **kuratierte** Ableitungen. Bei Konflikten gilt **IEEE** als Quelle der Wahrheit.
- **Reproduzierbarkeit:** Versioniere Snapshot‑Stände (Zeitstempel, SHA256) und dokumentiere Update‑Intervall (z. B. täglich/wöchentlich).

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

# 3) Eigenes JSON bauen (z. B. mit Python) und im Tool verwenden
```

---

## 11) Alle verwendeten Links (kompakt)

**IEEE / Grundlagen**
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

**APIs / Dienste**
- https://macaddress.io/  
- https://macaddress.io/api  
- https://macaddress.io/api/documentation  
- https://macaddress.io/api/documentation/output-format  
- https://macvendors.com/  
- https://macvendors.com/api  
- https://macvendors.co/  
- https://macvendors.co/api

**Bibliotheken**
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

**Lizenz/Compliance‑Hinweis:** Prüfe die Nutzungsbedingungen der jeweiligen Datenquellen/Tools (v. a. IEEE‑Daten, API‑TOS). Für produktive Distribution empfiehlt sich das **lokale Spiegeln** der IEEE‑CSVs inkl. Quell‑/Versions‑Dokumentation.
