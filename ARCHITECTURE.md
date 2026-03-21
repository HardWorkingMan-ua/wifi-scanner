# Architecture Documentation

## Overview

The WiFi Scanner is a modular C application that uses Linux's nl80211 netlink interface to discover and analyze nearby wireless networks. The application is divided into four main modules, each with a specific responsibility.

## Module Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                         main.c                                   │
│              CLI parsing, timing, sorting                        │
└─────────────────────────────────────────────────────────────────┘
                    │                    │
                    ▼                    ▼
┌─────────────────────────┐  ┌─────────────────────────┐
│      scanner.c          │  │      parser.c         │
│  nl80211 netlink ops   │──▶│   IE parsing         │
│  Scan triggering       │  │   Security detection  │
│  Result collection     │  └─────────────────────────┘
└─────────────────────────┘                │
                                        ▼
                            ┌─────────────────────────┐
                            │      display.c         │
                            │   Table/JSON output   │
                            └─────────────────────────┘
```

## Scanner Module (scanner.c)

### Purpose
Handles all communication with the Linux kernel via netlink sockets using the nl80211 generic netlink family.

### Key Components

#### 1. Socket Initialization (`scanner_init`)
```c
int scanner_init(scanner_ctx_t *ctx, const char *iface)
```
- Allocates a netlink socket
- Connects to NETLINK_GENERIC family
- Resolves nl80211 family ID using genl_ctrl_resolve()
- Gets interface index using if_nametoindex()
- Sets socket buffer size to 8192 bytes

#### 2. Scan Triggering (`scanner_scan`)
```
┌─────────────────┐
│ NL80211_CMD_TRIGGER_SCAN │
│   └─ NL80211_ATTR_IFINDEX     │  (target interface)
│   └─ NL80211_ATTR_SCAN_SSIDS  │  (wildcard scan)
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ Wait ~2 seconds │  (for scan to complete)
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ NL80211_CMD_GET_SCAN │  (NLM_F_DUMP)
└─────────────────┘
         │
         ▼
┌─────────────────────────────┐
│ Parse each BSS entry        │
│ via scan_callback()         │
└─────────────────────────────┘
```

#### 3. Callback System

The scanner uses libnl's callback mechanism to process messages:

- **`scan_callback()`** - Called for each BSS entry received. Parses:
  - BSSID (MAC address)
  - Signal strength (dBm)
  - Frequency → Channel conversion
  - Information Elements (IEs) for security
  - Capability flags (privacy bit)

- **`ack_callback()`** - Called when acknowledgment is received for trigger scan

- **`finish_handler()`** - Called when dump is complete

- **`error_handler()`** - Called on errors

#### 4. Information Elements Handling

The scanner checks two IE sources:
1. `NL80211_BSS_INFORMATION_ELEMENTS` - IEs from probe responses
2. `NL80211_BSS_BEACON_IES` - IEs from beacons

This dual-source approach ensures networks are detected even if they only broadcast beacons without responding to probe requests.

### Context Structure

```c
typedef struct {
    char iface_name[IFNAME_SIZE];    // Interface name (e.g., "wlan0")
    int iface_index;                 // Interface index from kernel
    struct nl_sock *sock;           // Netlink socket
    int nl80211_id;                 // nl80211 family ID
    wifi_network_t networks[MAX_NETWORKS];  // Results buffer
    int network_count;               // Number of networks found
} scanner_ctx_t;
```

## Parser Module (parser.c)

### Purpose
Parses raw Information Element (IE) data to extract security information.

### Information Elements

IEs are variable-length TLV (Type-Length-Value) structures:

```
┌────────┬────────┬─────────────────┐
│  Type  │ Length │     Value       │
│ (1 B)  │ (1 B)  │  (Length B)    │
└────────┴────────┴─────────────────┘
```

#### Key IEs for Security

| Element ID | Name | Used For |
|-----------|------|----------|
| 0 | SSID | Network name |
| 48 | RSN | WPA2/WPA3 security |
| 221 | Vendor Specific (WPA) | Legacy WPA |

### Parsing Flow (`parse_ies_raw`)

```
┌──────────────────────────────────────┐
│ Loop through all IEs                 │
│  ├─ Element 0: Extract SSID        │
│  ├─ Element 48: Store RSN pointer  │
│  └─ Element 221: Check WPA OUI     │
└──────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────┐
│ RSN IE found?                        │
│  └─ parse_rsn_ie()                  │
├──────────────────────────────────────┤
│ WPA IE found?                        │
│  └─ parse_wpa_vendor_ie()          │
├──────────────────────────────────────┤
│ Privacy bit set?                     │
│  └─ SECURITY_WEP                    │
├──────────────────────────────────────┤
│ Nothing found?                       │
│  └─ SECURITY_OPEN                   │
└──────────────────────────────────────┘
```

### RSN IE Parsing (`parse_rsn_ie`)

RSN IE structure (per IEEE 802.11):

```
┌──────────┬──────────┬──────────────┬──────────────┬──────────┐
│ Version  │ GC/PC   │ PC Count     │ PC List      │ AC Count │
│ (2 B)    │ (4 B)   │ (2 B)       │ (4×N B)     │ (2 B)   │
└──────────┴──────────┴──────────────┴──────────────┴──────────┘
     │           │                              │
     │           │                              ▼
     │           │                         ┌──────────┐
     │           │                         │ AC List  │
     │           │                         │ (4×M B)  │
     │           │                         └──────────┘
     │           ▼
     │      Cipher Suite
     │      (1=TKIP, 2=WEP40, 4=CCMP, 5=CCMP-256, 6=GCMP-256)
     │
     ▼
  Must be 1 for RSN
```

**Cipher Suite Detection:**
- Group cipher suite is extracted first
- Maps to human-readable names (CCMP, TKIP, GCMP, etc.)

**AKM Suite Detection:**
- Authentication Key Management suites determine WPA2 vs WPA3
- SAE/OWE → WPA3
- PSK → WPA2
- EAP → Enterprise WPA2

### Cipher Mappings

| Cipher ID | Name | Description |
|-----------|------|------------|
| 1 | WEP40 | 40-bit WEP (deprecated) |
| 2 | TKIP | Temporal Key Integrity Protocol |
| 4 | CCMP | AES-based Counter Mode CBC-MAC Protocol |
| 5 | CCMP-256 | 256-bit CCMP |
| 6 | GCMP | Galois/Counter Mode Protocol |
| 7 | GCMP-256 | 256-bit GCMP |

### AKM Suite Mappings

| AKM ID | Name | Security Level |
|--------|------|----------------|
| 1 | 802.1X | Enterprise |
| 2 | PSK | WPA2 |
| 4 | FT-PSK | WPA2 (Fast BSS Transition) |
| 6 | OWE | WPA3 (Opportunistic Wireless Encryption) |
| 8 | SAE | WPA3 (Simultaneous Authentication of Equals) |
| 9 | FT-SAE | WPA3 (Fast BSS Transition) |

## Display Module (display.c)

### Purpose
Formats and outputs network information in human-readable or JSON format.

### Signal Strength Calculation

Signal strength is converted from dBm to percentage:

```c
static int dbm_to_percent(int dbm) {
    if (dbm >= -50) return 100;   // Excellent
    if (dbm <= -100) return 0;   // Poor
    return 2 * (dbm + 100);      // Linear scale
}
```

| dBm Range | Percentage | Quality |
|-----------|-----------|---------|
| >= -50 | 100% | Excellent |
| -60 | 80% | Very Good |
| -70 | 60% | Good |
| -80 | 40% | Fair |
| -90 | 20% | Weak |
| <= -100 | 0% | Poor |

### Channel Calculation

Frequency to channel conversion:

```c
if (freq >= 2400 && freq <= 2500) {
    // 2.4 GHz band
    channel = (freq - 2400) / 5;
} else if (freq >= 5000 && freq <= 5900) {
    // 5 GHz band (U-NII)
    channel = (freq - 5000) / 5;
} else if (freq >= 5955 && freq <= 7115) {
    // 6 GHz band (U-NII-5,6,7,8)
    channel = (freq - 5955) / 5 + 1;
}
```

## Data Flow Summary

```
User runs: sudo ./wifi-scanner -i wlan0
                    │
                    ▼
           main.c: Parse CLI args
                    │
                    ▼
           scanner_init(): Create netlink socket
                    │
                    ▼
           scanner_scan(): Send NL80211_CMD_TRIGGER_SCAN
                    │
                    ▼
           Wait 2 seconds for scan completion
                    │
                    ▼
           Send NL80211_CMD_GET_SCAN (dump)
                    │
                    ▼
           For each BSS entry:
             scan_callback() → parse_ies_raw() → detect security
                    │
                    ▼
           display_results(): Format table
                    │
                    ▼
           Print output with timing info
```

## Key Design Decisions

1. **nl80211 over iwlib**: nl80211 provides more complete access to WiFi capabilities and is the modern standard.

2. **Dual IE sources**: Checking both `INFORMATION_ELEMENTS` and `BEACON_IES` ensures maximum network detection.

3. **Copy on get**: `scanner_get_networks_copy()` allows sorting without modifying original data.

4. **SAX-like IE parsing**: Manual byte parsing with bounds checking for maximum compatibility.

5. **No dynamic allocation in scan loop**: Pre-allocated array of MAX_NETWORKS entries for predictable memory usage.
