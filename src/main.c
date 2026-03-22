#include "scanner.h"
#include "display.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i, --interface <name>  Wireless interface to use (required)\n");
    fprintf(stderr, "  -t, --timeout <ms>     Scan timeout in milliseconds (default: 2000)\n");
    fprintf(stderr, "  -s, --sort             Sort by signal strength\n");
    fprintf(stderr, "  -j, --json             Output in JSON format\n");
    fprintf(stderr, "  -h, --help             Show this help message\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s -i wlp2s0\n", prog);
    fprintf(stderr, "  %s -i wlp2s0 --sort\n", prog);
    fprintf(stderr, "  %s -i wlp2s0 -t 3000\n", prog);
}

static double time_diff_ms(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 + (end->tv_usec - start->tv_usec) / 1000.0;
}

int main(int argc, char **argv) {
    const char *iface = NULL;
    int use_json = 0;
    int sort_by_signal = 0;
    int timeout_ms = DEFAULT_TIMEOUT_MS;
    struct timeval start, end;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"timeout", required_argument, 0, 't'},
        {"sort", no_argument, 0, 's'},
        {"json", no_argument, 0, 'j'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:t:sjh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                iface = optarg;
                break;
            case 't':
                timeout_ms = atoi(optarg);
                if (timeout_ms < 500) {
                    fprintf(stderr, "Warning: Timeout too small, using 500ms minimum\n");
                    timeout_ms = 500;
                }
                if (timeout_ms > 30000) {
                    fprintf(stderr, "Warning: Timeout too large, using 30000ms maximum\n");
                    timeout_ms = 30000;
                }
                break;
            case 's':
                sort_by_signal = 1;
                break;
            case 'j':
                use_json = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (!iface) {
        fprintf(stderr, "Error: Interface not specified\n");
        print_usage(argv[0]);
        return 1;
    }
    
    scanner_ctx_t ctx;
    
    if (scanner_init(&ctx, iface) < 0) {
        fprintf(stderr, "Failed to initialize scanner\n");
        return 1;
    }
    
    ctx.timeout_ms = timeout_ms;
    
    printf("Scanning for WiFi networks on interface %s (timeout: %dms)...\n", iface, timeout_ms);
    
    gettimeofday(&start, NULL);
    int count = scanner_scan(&ctx);
    gettimeofday(&end, NULL);
    
    if (count < 0) {
        fprintf(stderr, "Scan failed\n");
        scanner_cleanup(&ctx);
        return 1;
    }
    
    double scan_time = time_diff_ms(&start, &end);
    
    int network_count;
    wifi_network_t *networks = scanner_get_networks_copy(&ctx, &network_count);
    
    if (sort_by_signal && networks) {
        for (int i = 0; i < network_count - 1; i++) {
            for (int j = i + 1; j < network_count; j++) {
                if (networks[i].signal_dbm < networks[j].signal_dbm) {
                    wifi_network_t tmp = networks[i];
                    networks[i] = networks[j];
                    networks[j] = tmp;
                }
            }
        }
    }
    
    if (use_json) {
        display_json(networks, network_count, iface);
    } else {
        display_results(networks, network_count, iface);
    }
    
    if (scan_time < 1000) {
        printf("  Scan completed in %.0f ms\n", scan_time);
    } else {
        printf("  Scan completed in %.2f seconds\n", scan_time / 1000.0);
    }
    
    free(networks);
    scanner_cleanup(&ctx);
    
    return 0;
}
