# WiFi Scanner

A lightweight C application for scanning and displaying nearby WiFi networks with detailed security information.

## Features

- Scan nearby WiFi networks using Linux nl80211/cfg80211
- Display SSID, BSSID (MAC), vendor, channel, and signal strength
- Detect security type: Open, WEP, WPA, WPA2, WPA3
- Show cipher type: CCMP, TKIP, GCMP, etc.
- Detect WiFi band: 2.4 GHz, 5 GHz, 6 GHz
- MAC vendor lookup from OUI database (573 vendors)
- Human-readable table output or JSON format
- Sort networks by signal strength
- Show hidden SSIDs
- Configurable scan timeout
- Display scan duration
- Automatic fallback to cached results when interface is busy
- **Auto-detect interfaces** - lists all wireless interfaces with IP if none specified

## Requirements

- Linux with wireless interface
- libnl3 development libraries
- C compiler (gcc)
- Root privileges (required for WiFi scanning)

### Installing Dependencies

**Fedora/RHEL:**
```bash
sudo dnf install libnl3-devel
```

**Debian/Ubuntu:**
```bash
sudo apt install libnl-3-dev libnl-genl-3-dev
```

## Building

```bash
cd wifi-scanner
make
```

## Usage

### Auto-Detect Interface

If no interface is specified, the program will list all available wireless interfaces with their IP addresses:

```bash
sudo ./wifi-scanner

  Available wireless interfaces:

  [1] wlp2s0  (192.168.1.100)

  Select interface [1-1]: 1
```

### Basic Scan

```bash
sudo ./wifi-scanner -i wlan0
```

### Sort by Signal Strength

```bash
sudo ./wifi-scanner -i wlan0 --sort
```

### Custom Timeout (in milliseconds)

```bash
sudo ./wifi-scanner -i wlan0 --timeout 3000
```

### JSON Output (for scripting)

```bash
sudo ./wifi-scanner -i wlan0 -j
```

### Combined Options

```bash
sudo ./wifi-scanner -i wlan0 --sort --timeout 4000
```

### Help

```bash
./wifi-scanner --help
```

## Output Format

### Human-Readable Table

```
  WiFi Networks on wlp2s0
  ─────────────────────────────────────────────────────────────────────────────────────────────────────
   SSID                 Vendor        BSSID               Security    Band      Cipher   Ch   Signal
  ─────────────────────────────────────────────────────────────────────────────────────────────────────
   HomeWiFi             TP-Link       AA:BB:CC:DD:EE:FF  WPA2       2.4 GHz   CCMP      6    85% ●●●●●
   Office5G             Huawei        11:22:33:44:55:66  WPA2       5 GHz     CCMP     36    72% ●●●●○
   Guest                Unknown       77:88:99:00:AA:BB  Open       2.4 GHz   None      1    45% ●●●○○
  ─────────────────────────────────────────────────────────────────────────────────────────────────────
   3 networks found

  Scan completed in 5150 ms
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| SSID | Network name (or `<hidden>` if not broadcasting) |
| Vendor | Manufacturer from MAC OUI lookup |
| BSSID | Access point MAC address (XX:XX:XX:XX:XX:XX) |
| Security | Encryption type (Open, WEP, WPA, WPA2, WPA3) |
| Band | WiFi frequency band (2.4 GHz, 5 GHz, 6 GHz) |
| Cipher | Encryption cipher (CCMP, TKIP, GCMP, etc.) |
| Ch | WiFi channel number |
| Signal | Signal strength as percentage and visual bar |

### Signal Strength Guide

| Percentage | Quality | Visual |
|-----------|---------|--------|
| 80-100% | Excellent | ●●●●● |
| 60-79% | Good | ●●●●○ |
| 40-59% | Fair | ●●●○○ |
| 20-39% | Weak | ●●○○○ |
| 0-19% | Poor | ●○○○○ |

### WiFi Bands

| Band | Frequency | Channels |
|------|-----------|----------|
| 2.4 GHz | 2400-2500 MHz | 1-14 |
| 5 GHz | 5150-5900 MHz | 36-165 |
| 6 GHz | 5925-7125 MHz | 1-233 |

## Project Structure

```
wifi-scanner/
├── src/
│   ├── main.c       # Entry point, CLI parsing
│   ├── scanner.c     # nl80211 netlink scanning, vendor lookup
│   ├── scanner.h     # Scanner types and API
│   ├── parser.c     # IE parsing for security
│   ├── parser.h     # Parser API
│   ├── display.c    # Output formatting
│   └── display.h    # Display API
├── docs/
│   ├── ARCHITECTURE.md    # Code architecture
│   ├── API.md            # API documentation
│   └── SECURITY_DETECTION.md # Security detection details
├── Makefile
└── README.md
```

## Architecture

The scanner uses the nl80211 netlink interface to communicate with the Linux kernel's cfg80211 subsystem:

1. **Scanner Module** - Opens netlink socket, sends NL80211_CMD_TRIGGER_SCAN, receives results, performs vendor lookup, band detection
2. **Parser Module** - Parses Information Elements (IEs) to extract security info
3. **Display Module** - Formats output as table or JSON

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture.

## Security Detection

The scanner detects security by parsing:
- **RSN IE (Element 48)** - Used by WPA2/WPA3 networks
- **WPA Vendor IE (Element 221)** - Used by legacy WPA networks
- **Privacy bit** - Determines WEP vs Open

See [docs/SECURITY_DETECTION.md](docs/SECURITY_DETECTION.md) for detailed algorithm.

## Vendor Lookup

The scanner includes a built-in OUI (Organizationally Unique Identifier) database with 573 entries to identify manufacturers from MAC addresses. Supported vendors include:

- Apple, Intel, Dell, HP
- Cisco, Netgear, Linksys, Asus
- TP-Link, Huawei, Xiaomi, Honor
- Google, Microsoft, D-Link
- Tenda, Mercusys, and many more

## Error Handling

### Interface Busy

If the interface is busy (connected to a network), the scanner will automatically use cached scan results:

```
Note: Using cached scan results (interface is busy)
```

To force a new scan, disconnect first:
```bash
sudo nmcli dev disconnect wlan0
```

## License

MIT License

## Author

Created as a demonstration of nl80211 programming in C.
