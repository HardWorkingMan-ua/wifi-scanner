# API Documentation

## Data Structures

### wifi_network_t

Represents a single WiFi network discovered during scanning.

```c
typedef struct {
    char ssid[33];              // Network name (max 32 chars + null)
    char bssid[18];            // MAC address (XX:XX:XX:XX:XX:XX)
    security_type_t security;   // Security type enum
    char cipher[16];           // Cipher suite name
    int signal_dbm;            // Signal strength in dBm
    int channel;               // WiFi channel number
    int frequency_mhz;         // Frequency in MHz
} wifi_network_t;
```

**Fields:**
- `ssid`: Network name. Empty string indicates hidden network.
- `bssid`: Access point MAC address in XX:XX:XX:XX:XX:XX format.
- `security`: Enum value indicating security type.
- `cipher`: Human-readable cipher name (CCMP, TKIP, GCMP, etc.).
- `signal_dbm`: Signal strength in decibel-milliwatts. Range typically -100 to -30 dBm.
- `channel`: WiFi channel number (1-165 depending on band).
- `frequency_mhz`: Exact frequency in megahertz.

### security_type_t

Enum representing WiFi security types.

```c
typedef enum {
    SECURITY_OPEN,       // No encryption
    SECURITY_WEP,        // Wired Equivalent Privacy (deprecated)
    SECURITY_WPA,       // WiFi Protected Access (legacy)
    SECURITY_WPA2,      // WPA2 with PSK or Enterprise
    SECURITY_WPA3,      // WPA3 with SAE or OWE
    SECURITY_WPA2_WPA3, // Mixed mode (transition)
    SECURITY_UNKNOWN     // Unable to determine
} security_type_t;
```

### scanner_ctx_t

Internal context structure for the scanner.

```c
typedef struct {
    char iface_name[IFNAME_SIZE];    // Interface name
    int iface_index;                 // Interface index
    struct nl_sock *sock;          // Netlink socket
    int nl80211_id;                // nl80211 family ID
    wifi_network_t networks[MAX_NETWORKS];  // Results
    int network_count;              // Number of results
} scanner_ctx_t;
```

**Note:** This structure is opaque for external use. Access via provided functions.

---

## Scanner Functions

### scanner_init

Initializes the scanner with a specified interface.

```c
int scanner_init(scanner_ctx_t *ctx, const char *iface);
```

**Parameters:**
- `ctx`: Pointer to scanner context (must be allocated by caller)
- `iface`: Interface name (e.g., "wlan0", "wlp2s0")

**Returns:**
- `0` on success
- `-1` on failure (check stderr for error message)

**Example:**
```c
scanner_ctx_t ctx;
if (scanner_init(&ctx, "wlan0") < 0) {
    fprintf(stderr, "Failed to initialize\n");
    return 1;
}
```

---

### scanner_scan

Performs a WiFi scan and collects results.

```c
int scanner_scan(scanner_ctx_t *ctx);
```

**Parameters:**
- `ctx`: Pointer to initialized scanner context

**Returns:**
- Number of networks found (>= 0)
- `-1` on error

**Behavior:**
1. Sends NL80211_CMD_TRIGGER_SCAN to kernel
2. Waits 2 seconds for scan completion
3. Dumps all scan results
4. Parses each BSS entry for SSID, security, signal, etc.

**Note:** Requires root privileges.

**Example:**
```c
int count = scanner_scan(&ctx);
if (count < 0) {
    fprintf(stderr, "Scan failed\n");
    return 1;
}
printf("Found %d networks\n", count);
```

---

### scanner_get_networks

Gets pointer to internal results array.

```c
const wifi_network_t *scanner_get_networks(scanner_ctx_t *ctx, int *count);
```

**Parameters:**
- `ctx`: Pointer to scanner context
- `count`: Pointer to integer (receives network count)

**Returns:**
- Pointer to array of `wifi_network_t` structures
- Pointer is valid until `scanner_cleanup()` or next `scanner_scan()`

**Example:**
```c
int count;
const wifi_network_t *networks = scanner_get_networks(&ctx, &count);
for (int i = 0; i < count; i++) {
    printf("%s: %d dBm\n", networks[i].ssid, networks[i].signal_dbm);
}
```

---

### scanner_get_networks_copy

Gets a copy of results that can be modified.

```c
wifi_network_t *scanner_get_networks_copy(scanner_ctx_t *ctx, int *count);
```

**Parameters:**
- `ctx`: Pointer to scanner context
- `count`: Pointer to integer (receives network count)

**Returns:**
- Pointer to newly allocated array (must be freed by caller)
- `NULL` if no networks or allocation failure

**Example:**
```c
int count;
wifi_network_t *networks = scanner_get_networks_copy(&ctx, &count);
if (networks) {
    // Sort the copy
    qsort(networks, count, sizeof(wifi_network_t), compare_signal);
    free(networks);  // Don't forget to free!
}
```

---

### scanner_cleanup

Frees resources associated with scanner context.

```c
void scanner_cleanup(scanner_ctx_t *ctx);
```

**Parameters:**
- `ctx`: Pointer to scanner context

**Behavior:**
- Closes netlink socket
- Sets socket to NULL
- Does NOT free copied results (caller's responsibility)

**Example:**
```c
scanner_cleanup(&ctx);  // Call when done
```

---

## Parser Functions

### parse_ies_raw

Parses raw Information Elements to extract network info.

```c
void parse_ies_raw(wifi_network_t *net, unsigned char *ies, 
                   size_t ies_len, int privacy);
```

**Parameters:**
- `net`: Pointer to network structure to populate
- `ies`: Pointer to raw IE data
- `ies_len`: Length of IE data in bytes
- `privacy`: Privacy bit from capability field (0 or 1)

**Behavior:**
- Extracts SSID from Element ID 0
- Finds RSN IE (ID 48) for WPA2/WPA3
- Finds WPA Vendor IE (ID 221) for legacy WPA
- Sets `net->security` and `net->cipher`

**Note:** Usually called internally by scanner. Public for advanced use.

---

### security_to_string

Converts security type enum to human-readable string.

```c
const char *security_to_string(security_type_t sec);
```

**Parameters:**
- `sec`: Security type enum value

**Returns:**
- Pointer to static string

| Enum Value | String |
|------------|--------|
| SECURITY_OPEN | "Open" |
| SECURITY_WEP | "WEP" |
| SECURITY_WPA | "WPA" |
| SECURITY_WPA2 | "WPA2" |
| SECURITY_WPA3 | "WPA3" |
| SECURITY_WPA2_WPA3 | "WPA2/WPA3" |
| SECURITY_UNKNOWN | "Unknown" |

**Example:**
```c
printf("Security: %s\n", security_to_string(net->security));
```

---

## Complete Usage Example

```c
#include "scanner.h"
#include "display.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    
    scanner_ctx_t ctx;
    
    if (scanner_init(&ctx, argv[1]) < 0) {
        return 1;
    }
    
    printf("Scanning...\n");
    int count = scanner_scan(&ctx);
    
    if (count < 0) {
        scanner_cleanup(&ctx);
        return 1;
    }
    
    int network_count;
    wifi_network_t *networks = scanner_get_networks_copy(&ctx, &network_count);
    
    if (networks) {
        display_results(networks, network_count, argv[1]);
        free(networks);
    }
    
    scanner_cleanup(&ctx);
    return 0;
}
```

---

## Thread Safety

The scanner is NOT thread-safe:
- Do not call `scanner_scan()` from multiple threads simultaneously
- Results pointers are only valid until next scan or cleanup
- Use `scanner_get_networks_copy()` for thread-safe access

---

## Error Handling

All functions that can fail return:
- Negative value on error (`-1`)
- Positive value or zero on success (check docs)

Error messages are printed to stderr. For custom error handling, you may want to capture stderr or implement wrapper functions.
