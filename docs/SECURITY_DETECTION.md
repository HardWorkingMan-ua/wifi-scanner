# Security Detection Algorithm

This document explains how the WiFi scanner detects and classifies wireless network security.

## WiFi Security Protocols

### Evolution of WiFi Security

| Protocol | Year | Status | Encryption | Vulnerabilities |
|---------|------|--------|------------|-----------------|
| Open | 1997 | Deprecated | None | No security |
| WEP | 1997 | Deprecated | RC4 | Easily cracked |
| WPA | 2003 | Legacy | TKIP | KRACK, weak |
| WPA2 | 2004 | Standard | CCMP/AES | KRACK, brute-force |
| WPA3 | 2018 | Current | GCMP/AES | Dragonblood (mitigated) |

## Information Elements

WiFi access points broadcast their capabilities in Information Elements (IEs) within beacons and probe responses. These are TLV (Type-Length-Value) structures:

```
┌────────┬────────┬─────────────────┐
│  Type  │ Length │     Value       │
│ 1 byte │ 1 byte │  Length bytes  │
└────────┴────────┴─────────────────┘
```

### Key IEs for Security

| Element ID | Name | Purpose |
|-----------|------|---------|
| 0 | SSID | Network name |
| 1 | Supported Rates | Data rates supported |
| 3 | DS Parameter Set | Channel (frequency) |
| 48 | RSN | Robust Security Network (WPA2/WPA3) |
| 221 | Vendor Specific | Legacy WPA |

## Detection Algorithm

```
START
  │
  ▼
┌─────────────────────────────────────┐
│ Check for RSN IE (Element ID 48)?   │
└─────────────────────────────────────┘
         │
    YES  │  NO
    ▼    │   ▼
    ┌────────────┐
    │ Parse RSN  │
    │ Determine  │
    │ WPA2/WPA3  │
    └────────────┘
         │
         ▼
    ┌─────────────────┐
    │ Check WPA IE    │──────── NO ────▶ Check Privacy Bit
    │ (Element ID 221)│
    └─────────────────┘
         │
       YES
         ▼
    ┌────────────┐
    │ Parse WPA  │
    │ Legacy WPA │
    └────────────┘
         │
         ▼
      RESULT
```

### Step 1: RSN IE Detection (WPA2/WPA3)

The RSN (Robust Security Network) IE contains:
- Version
- Group Cipher Suite
- Pairwise Cipher Suites
- AKM Suites
- Capabilities

```
RSN IE Structure:
┌─────────┬─────────────────┬──────────────────┬──────────────┐
│ Version │ Group Cipher    │ Pairwise Ciphers │ AKM Suites   │
│ (2 B)   │ Suite (4 B)    │ + Count         │ + Count     │
└─────────┴─────────────────┴──────────────────┴──────────────┘
```

### Step 2: AKM Suite Determination

The Authentication Key Management (AKM) suite determines security type:

```
AKM Detection:
┌──────────────────────────────────────────────────────────┐
│  AKM Suite Present                                       │
│                                                          │
│  SAE (0x000FAC08) or FT-SAE (0x000FAC09)               │
│      or OWE (0x000FAC06)                               │
│      └─▶ SECURITY_WPA3                                  │
│                                                          │
│  PSK (0x000FAC02) or FT-PSK (0x000FAC04)               │
│      or EAP (0x000FAC18/0x000FAC12)                     │
│      └─▶ SECURITY_WPA2                                  │
└──────────────────────────────────────────────────────────┘
```

### Step 3: WPA Vendor IE (Legacy WPA)

Legacy WPA uses a Vendor-Specific IE with Microsoft WPA OUI:

```
WPA Vendor IE:
┌─────────┬─────────┬───────────┬──────────────────┐
│ OUI     │ Type    │ Version   │ Cipher Info       │
│ (3 B)   │ (1 B)   │ (2 B)    │ ...              │
└─────────┴─────────┴───────────┴──────────────────┘
  00:50:F2   01       1
```

### Step 4: Fallback Detection

If no RSN or WPA IE is found, check the Privacy bit in the Capability field:

```
Capability Field (2 bytes):
┌────┬────┬────┬────┬────┬────┬────┬────┬─...─┐
│ ESS │ IBSS│ CF │ CF │Privacy│ ... │
│ Bit │ Bit│ Pol│ Pol│ Bit   │     │
│  0  │  1 │  2 │  3 │   4    │     │
└────┴────┴────┴────┴────┴────┴────┴─...─┘
```

- **Privacy bit = 1, no RSN/WPA**: SECURITY_WEP
- **Privacy bit = 0**: SECURITY_OPEN

## Cipher Suite Detection

### Group Cipher Suite

The group cipher (used for broadcast/multicast traffic) is the primary cipher indicator:

| Cipher ID | OUI | Name | Used By |
|-----------|-----|------|---------|
| 0x00 | - | None | Open |
| 0x01 | - | WEP-40 | WEP |
| 0x02 | - | TKIP | WPA, WPA2 |
| 0x03 | - | WRAP | Deprecated |
| 0x04 | - | CCMP | WPA2, WPA3 |
| 0x05 | IANA | CCMP-256 | WPA3 |
| 0x06 | IANA | GCMP | WPA3 |
| 0x07 | IANA | GCMP-256 | WPA3 |
| 0x08 | - | WEP-104 | WEP |

### Cipher Priority

Modern ciphers are preferred:
- GCMP-256 > GCMP > CCMP-256 > CCMP > TKIP > WEP

## Complete Detection Matrix

| RSN Present | AKM | Cipher | Security Type | Notes |
|-------------|-----|--------|--------------|-------|
| Yes | SAE/FT-SAE/OWE | Any | WPA3 | Modern secure |
| Yes | PSK/FT-PSK/EAP | CCMP/GCMP | WPA2 | Standard |
| No | WPA IE | TKIP | WPA | Legacy |
| No | No | Privacy=1 | WEP | Deprecated |
| No | No | Privacy=0 | Open | No encryption |

## Hidden Networks

Networks with hidden SSIDs:
- SSID element is empty (length = 0)
- BSS still broadcasts security information
- Display shows `<hidden>` for SSID

## Common Issues

### 1. Cipher Shows "Unknown"

**Cause:** RSN IE has non-standard cipher values.

**Solution:** Default to CCMP (most common) for RSN networks.

### 2. WPA2 Shows as Open

**Cause:** Network has no RSN or WPA IE and Privacy bit not set.

**Solution:** Network may be in the process of transitioning.

### 3. Mixed WPA/WPA2 Detection

**Cause:** Network supports multiple security modes.

**Solution:** Report highest security level detected.

## Implementation Details

### IE Parsing

```c
// Parse RSN IE
void parse_rsn_ie(wifi_network_t *net, unsigned char *ie, size_t len) {
    // Version must be 1
    unsigned short version = (ie[0] << 8) | ie[1];
    
    // Group cipher at offset 2
    unsigned short group_cipher = (ie[2] << 8) | ie[3];
    
    // AKM suites after pairwise ciphers
    // Count and iterate through AKM list
}
```

### Bounds Checking

Critical for security - always validate:
- IE length doesn't exceed buffer
- Element ID 0 and 221 have minimum lengths
- Count fields don't cause buffer overflow

## Vendor Identification

The scanner uses OUI (Organizationally Unique Identifier) lookup to identify the manufacturer of access points based on their MAC address.

### How It Works

```
MAC Address: XX:XX:XX:YY:YY:YY
                ↑
            OUI (First 3 bytes)
```

- First 3 bytes (OUI) identify the manufacturer
- Remaining 3 bytes (NIC) identify the specific device
- Database contains 573 common vendor OUIs

### Supported Vendors

The scanner includes 573 vendor entries including:

| Vendor | Description |
|--------|-------------|
| TP-Link | 18 OUI prefixes |
| Huawei | 250+ OUI prefixes |
| Xiaomi | 25+ OUI prefixes |
| Apple | 3+ OUI prefixes |
| Intel | 7+ OUI prefixes |
| Netgear | 20+ OUI prefixes |
| D-Link | 30+ OUI prefixes |
| Linksys | 8+ OUI prefixes |
| Cisco | 2+ OUI prefixes |
| Google | 6+ OUI prefixes |

## References

- IEEE 802.11-2020 (formerly 802.11-2016)
- WPA2 Specification (IEEE 802.11i-2004)
- WPA3 Specification (Wi-Fi Alliance)
- Linux Kernel nl80211.h
- IEEE OUI Registry
