#include "display.h"
#include "parser.h"
#include <stdio.h>
#include <string.h>

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
        
        printf("    {\n");
        printf("      \"ssid\": \"%s\",\n", net->ssid);
        printf("      \"ssid_hidden\": %s,\n", net->ssid[0] ? "false" : "true");
        printf("      \"vendor\": \"%s\",\n", net->vendor);
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
