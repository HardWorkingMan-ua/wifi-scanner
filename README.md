# WiFi Scanner

A lightweight C application for scanning and displaying nearby WiFi networks with detailed security information.

## Features

- Scan nearby WiFi networks using Linux nl80211/cfg80211
- Display SSID, BSSID (MAC), channel, and signal strength
- Detect security type: Open, WEP, WPA, WPA2, WPA3
- Show cipher type: CCMP, TKIP, GCMP, etc.
- Human-readable table output or JSON format
- Sort networks by signal strength
- Show hidden SSIDs
- Display scan duration

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

### Basic Scan

```bash
sudo ./wifi-scanner -i wlan0
```

### Sort by Signal Strength

```bash
sudo ./wifi-scanner -i wlan0 --sort
```

### JSON Output (for scripting)

```bash
sudo ./wifi-scanner -i wlan0 -j
```

### Help

```bash
./wifi-scanner --help
```

## Output Format

### Human-Readable Table

```
  WiFi Networks on wlp2s0
  ────────────────────────────────────────────────────────────────────────────────
   SSID                 BSSID               Security    Cipher   Ch   Signal
  ────────────────────────────────────────────────────────────────────────────────
   HomeWiFi             AA:BB:CC:DD:EE:FF  WPA2       CCMP      6    85% ●●●●●
   Guest                77:88:99:00:AA:BB  Open       None      1    45% ●●●○○
  ────────────────────────────────────────────────────────────────────────────────
   2 networks found

  Scan completed in 2150 ms
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| SSID | Network name (or `<hidden>` if not broadcasting) |
| BSSID | Access point MAC address (XX:XX:XX:XX:XX:XX) |
| Security | Encryption type (Open, WEP, WPA, WPA2, WPA3) |
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

## Project Structure

```
wifi-scanner/
├── src/
│   ├── main.c       # Entry point, CLI parsing
│   ├── scanner.c    # nl80211 netlink scanning
│   ├── scanner.h    # Scanner types and API
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

1. **Scanner Module** - Opens netlink socket, sends NL80211_CMD_TRIGGER_SCAN, receives results
2. **Parser Module** - Parses Information Elements (IEs) to extract security info
3. **Display Module** - Formats output as table or JSON

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture.

## Security Detection

The scanner detects security by parsing:
- **RSN IE (Element 48)** - Used by WPA2/WPA3 networks
- **WPA Vendor IE (Element 221)** - Used by legacy WPA networks
- **Privacy bit** - Determines WEP vs Open

See [docs/SECURITY_DETECTION.md](docs/SECURITY_DETECTION.md) for detailed algorithm.

## License

MIT License

## Author

Created as a demonstration of nl80211 programming in C.
