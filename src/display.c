#include "display.h"
#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static const char *signal_bar(int percent) {
    if (percent >= 80) return "●●●●●";
    if (percent >= 60) return "●●●●○";
    if (percent >= 40) return "●●●○○";
    if (percent >= 20) return "●●○○○";
    return "●○○○○";
}

static int dbm_to_percent(int dbm) {
    if (dbm >= -50) return 100;
    if (dbm <= -100) return 0;
    return 2 * (dbm + 100);
}

static void escape_json(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        if (src[i] == '"' || src[i] == '\\') {
            if (j + 2 < dst_size) {
                dst[j++] = '\\';
                dst[j++] = src[i];
            }
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

static void escape_csv(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    int has_special = 0;
    for (size_t i = 0; src[i]; i++) {
        if (src[i] == '"' || src[i] == ',') {
            has_special = 1;
            break;
        }
    }
    
    if (has_special) {
        if (j < dst_size - 1) dst[j++] = '"';
        for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
            if (src[i] == '"') {
                if (j < dst_size - 1) dst[j++] = '"';
            }
            if (j < dst_size - 1) dst[j++] = src[i];
        }
        if (j < dst_size - 1) dst[j++] = '"';
    } else {
        for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

void display_results(const wifi_network_t *networks, int count, const char *iface) {
    printf("\n");
    printf("  WiFi Networks on %s\n", iface);
    printf("  ");
    for (int i = 0; i < 100; i++) printf("─");
    printf("\n");
    printf("  %-20s %-12s %-15s %-10s %-5s %-8s %4s %s\n", 
           "SSID", "Vendor", "BSSID", "Security", "Band", "Cipher", "Ch", "Signal");
    printf("  ");
    for (int i = 0; i < 100; i++) printf("─");
    printf("\n");
    
    for (int i = 0; i < count; i++) {
        const wifi_network_t *net = &networks[i];
        const char *ssid = net->ssid[0] ? net->ssid : "<hidden>";
        const char *security = security_to_string(net->security);
        const char *band = band_to_string(net->band);
        int percent = dbm_to_percent(net->signal_dbm);
        
        printf("  %-20s %-12s %-15s %-10s %-5s %-8s %4d %3d%% %s\n",
               ssid,
               net->vendor,
               net->bssid,
               security,
               band,
               net->cipher,
               net->channel,
               percent,
               signal_bar(percent));
    }
    
    printf("  ");
    for (int i = 0; i < 100; i++) printf("─");
    printf("\n");
    printf("  %d network%s found\n\n", count, count == 1 ? "" : "s");
}

void display_json(const wifi_network_t *networks, int count, const char *iface) {
    printf("{\n");
    printf("  \"interface\": \"%s\",\n", iface);
    printf("  \"count\": %d,\n", count);
    printf("  \"networks\": [\n");
    
    for (int i = 0; i < count; i++) {
        const wifi_network_t *net = &networks[i];
        int percent = dbm_to_percent(net->signal_dbm);
        char escaped_ssid[65];
        char escaped_vendor[129];
        
        escape_json(net->ssid, escaped_ssid, sizeof(escaped_ssid));
        escape_json(net->vendor, escaped_vendor, sizeof(escaped_vendor));
        
        printf("    {\n");
        printf("      \"ssid\": \"%s\",\n", escaped_ssid);
        printf("      \"ssid_hidden\": %s,\n", net->ssid[0] ? "false" : "true");
        printf("      \"vendor\": \"%s\",\n", escaped_vendor);
        printf("      \"bssid\": \"%s\",\n", net->bssid);
        printf("      \"security\": \"%s\",\n", security_to_string(net->security));
        printf("      \"cipher\": \"%s\",\n", net->cipher);
        printf("      \"band\": \"%s\",\n", band_to_string(net->band));
        printf("      \"signal_dbm\": %d,\n", net->signal_dbm);
        printf("      \"signal_percent\": %d,\n", percent);
        printf("      \"channel\": %d,\n", net->channel);
        printf("      \"frequency_mhz\": %d\n", net->frequency_mhz);
        printf("    }%s\n", (i < count - 1) ? "," : "");
    }
    
    printf("  ]\n");
    printf("}\n");
}

int display_csv(const wifi_network_t *networks, int count, const char *iface, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing: %s\n", filename, strerror(errno));
        return -1;
    }
    
    fprintf(fp, "SSID,Vendor,BSSID,Security,Band,Cipher,Channel,Signal_dBm,Signal_percent,Frequency_MHz,Interface\n");
    
    for (int i = 0; i < count; i++) {
        const wifi_network_t *net = &networks[i];
        int percent = dbm_to_percent(net->signal_dbm);
        char escaped_ssid[256];
        char escaped_vendor[256];
        
        escape_csv(net->ssid, escaped_ssid, sizeof(escaped_ssid));
        escape_csv(net->vendor, escaped_vendor, sizeof(escaped_vendor));
        
        fprintf(fp, "%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%s\n",
                escaped_ssid,
                escaped_vendor,
                net->bssid,
                security_to_string(net->security),
                band_to_string(net->band),
                net->cipher,
                net->channel,
                net->signal_dbm,
                percent,
                net->frequency_mhz,
                iface);
    }
    
    fclose(fp);
    printf("  CSV written to %s (%d networks)\n", filename, count);
    return 0;
}
