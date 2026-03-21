#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>

#define MAX_NETWORKS 128
#define IFNAME_SIZE 32

typedef enum {
    SECURITY_OPEN,
    SECURITY_WEP,
    SECURITY_WPA,
    SECURITY_WPA2,
    SECURITY_WPA3,
    SECURITY_WPA2_WPA3,
    SECURITY_UNKNOWN
} security_type_t;

typedef struct {
    char ssid[33];
    char bssid[18];
    security_type_t security;
    char cipher[16];
    int signal_dbm;
    int channel;
    int frequency_mhz;
} wifi_network_t;

typedef struct {
    char iface_name[IFNAME_SIZE];
    int iface_index;
    struct nl_sock *sock;
    int nl80211_id;
    wifi_network_t networks[MAX_NETWORKS];
    int network_count;
} scanner_ctx_t;

int scanner_init(scanner_ctx_t *ctx, const char *iface);
void scanner_cleanup(scanner_ctx_t *ctx);
int scanner_scan(scanner_ctx_t *ctx);
const wifi_network_t *scanner_get_networks(scanner_ctx_t *ctx, int *count);
wifi_network_t *scanner_get_networks_copy(scanner_ctx_t *ctx, int *count);
void scanner_free_results(scanner_ctx_t *ctx);

#endif
