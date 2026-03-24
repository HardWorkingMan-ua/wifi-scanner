#include "scanner.h"
#include "display.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <time.h>

#define VERSION "0.0.2"

static volatile int running = 1;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\n  Stopping live scan...\n");
}

static void print_version(const char *prog) {
    printf("%s v%s\n", prog, VERSION);
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i, --interface <name>  Wireless interface to use\n");
    fprintf(stderr, "  -t, --timeout <ms>     Scan timeout in milliseconds (default: 2000)\n");
    fprintf(stderr, "  -l, --live            Live mode - continuous scanning\n");
    fprintf(stderr, "  -I, --interval <ms>   Interval between scans in live mode (default: 5000)\n");
    fprintf(stderr, "  -s, --sort             Sort by signal strength\n");
    fprintf(stderr, "  -j, --json             Output in JSON format\n");
    fprintf(stderr, "  -c, --csv <file>       Output to CSV file\n");
    fprintf(stderr, "  -v, --version          Show version\n");
    fprintf(stderr, "  -h, --help             Show this help message\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If no interface is specified, shows a list of available interfaces.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s\n", prog);
    fprintf(stderr, "  %s -i wlp2s0\n", prog);
    fprintf(stderr, "  %s -i wlp2s0 --live\n", prog);
    fprintf(stderr, "  %s -i wlp2s0 --live --interval 3000\n", prog);
    fprintf(stderr, "  %s -i wlp2s0 --csv output.csv\n", prog);
}

static double time_diff_ms(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 + (end->tv_usec - start->tv_usec) / 1000.0;
}

static int is_wireless_interface(const char *iface) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", iface);
    FILE *f = fopen(path, "r");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

static int list_interfaces(char interfaces[][IFNAME_SIZE], char ips[][16], int max) {
    struct ifaddrs *ifaddr, *ifa;
    int count = 0;
    
    if (getifaddrs(&ifaddr) == -1) {
        return 0;
    }
    
    for (ifa = ifaddr; ifa != NULL && count < max; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        
        if (is_wireless_interface(ifa->ifa_name)) {
            strncpy(interfaces[count], ifa->ifa_name, IFNAME_SIZE - 1);
            interfaces[count][IFNAME_SIZE - 1] = '\0';
            
            memset(ips[count], 0, 16);
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ips[count], 15);
            
            count++;
        }
    }
    
    freeifaddrs(ifaddr);
    return count;
}

static const char* select_interface(void) {
    char interfaces[16][IFNAME_SIZE];
    char ips[16][16];
    static char selected[IFNAME_SIZE];
    
    int count = list_interfaces(interfaces, ips, 16);
    
    if (count == 0) {
        fprintf(stderr, "No wireless interfaces found.\n");
        return NULL;
    }
    
    printf("\n  Available wireless interfaces:\n\n");
    
    for (int i = 0; i < count; i++) {
        printf("  [%d] %s", i + 1, interfaces[i]);
        if (ips[i][0]) {
            printf("  (%s)", ips[i]);
        }
        printf("\n");
    }
    
    printf("\n  Select interface [1-%d]: ", count);
    fflush(stdout);
    
    char line[256];
    if (!fgets(line, sizeof(line), stdin)) {
        return NULL;
    }
    
    int choice = atoi(line);
    if (choice < 1 || choice > count) {
        fprintf(stderr, "Invalid selection.\n");
        return NULL;
    }
    
    strncpy(selected, interfaces[choice - 1], IFNAME_SIZE - 1);
    selected[IFNAME_SIZE - 1] = '\0';
    
    return selected;
}

static void print_timestamp(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("\n  [%s]\n", buffer);
}

int main(int argc, char **argv) {
    const char *iface = NULL;
    int use_json = 0;
    int sort_by_signal = 0;
    int timeout_ms = DEFAULT_TIMEOUT_MS;
    int live_mode = 0;
    int interval_ms = 5000;
    int interface_selected = 0;
    char *csv_filename = NULL;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"timeout", required_argument, 0, 't'},
        {"live", no_argument, 0, 'l'},
        {"interval", required_argument, 0, 'I'},
        {"sort", no_argument, 0, 's'},
        {"json", no_argument, 0, 'j'},
        {"csv", required_argument, 0, 'c'},
        {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:t:I:lsjvc:h", long_options, NULL)) != -1) {
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
            case 'I':
                interval_ms = atoi(optarg);
                if (interval_ms < 1000) {
                    fprintf(stderr, "Warning: Interval too small, using 1000ms minimum\n");
                    interval_ms = 1000;
                }
                if (interval_ms > 60000) {
                    fprintf(stderr, "Warning: Interval too large, using 60000ms maximum\n");
                    interval_ms = 60000;
                }
                break;
            case 'l':
                live_mode = 1;
                break;
            case 's':
                sort_by_signal = 1;
                break;
            case 'j':
                use_json = 1;
                break;
            case 'c':
                csv_filename = optarg;
                break;
            case 'v':
                print_version(argv[0]);
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (!iface) {
        iface = select_interface();
        if (!iface) {
            return 1;
        }
        interface_selected = 1;
    }
    
    scanner_ctx_t ctx;
    
    if (scanner_init(&ctx, iface) < 0) {
        fprintf(stderr, "Failed to initialize scanner\n");
        return 1;
    }
    
    ctx.timeout_ms = timeout_ms;
    
    if (live_mode) {
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        printf("\n  Live mode enabled (interval: %dms, timeout: %dms)\n", interval_ms, timeout_ms);
        printf("  Press Ctrl+C to stop\n");
    }
    
    if (interface_selected) {
        printf("\n");
    }
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    if (live_mode) {
        print_timestamp();
        printf("  Scanning on %s...\n", iface);
    } else {
        printf("Scanning for WiFi networks on interface %s (timeout: %dms)...\n", iface, timeout_ms);
    }
    
    int count = scanner_scan(&ctx);
    gettimeofday(&end, NULL);
    
    if (count < 0) {
        scanner_cleanup(&ctx);
        return 1;
    }
    
    if (ctx.used_cached) {
        printf("  (cached)\n");
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
    } else if (csv_filename) {
        display_csv(networks, network_count, iface, csv_filename);
    } else {
        display_results(networks, network_count, iface);
    }
    
    if (scan_time < 1000) {
        printf("  Scan completed in %.0f ms\n", scan_time);
    } else {
        printf("  Scan completed in %.2f seconds\n", scan_time / 1000.0);
    }
    
    free(networks);
    
    if (!live_mode) {
        scanner_cleanup(&ctx);
        return 0;
    }
    
    while (running) {
        usleep(interval_ms * 1000);
        
        struct timeval start2, end2;
        gettimeofday(&start2, NULL);
        
        print_timestamp();
        printf("  Scanning on %s...\n", iface);
        
        int scan_result = scanner_scan(&ctx);
        gettimeofday(&end2, NULL);
        
        if (scan_result < 0) {
            if (!running) break;
            fprintf(stderr, "Scan failed, retrying in %dms...\n", interval_ms);
            continue;
        }
        
        if (ctx.used_cached) {
            printf("  (cached)\n");
        }
        
        double scan_time2 = time_diff_ms(&start2, &end2);
        
        int network_count2;
        wifi_network_t *networks2 = scanner_get_networks_copy(&ctx, &network_count2);
        
        if (sort_by_signal && networks2) {
            for (int i = 0; i < network_count2 - 1; i++) {
                for (int j = i + 1; j < network_count2; j++) {
                    if (networks2[i].signal_dbm < networks2[j].signal_dbm) {
                        wifi_network_t tmp = networks2[i];
                        networks2[i] = networks2[j];
                        networks2[j] = tmp;
                    }
                }
            }
        }
        
        if (use_json) {
            display_json(networks2, network_count2, iface);
        } else if (csv_filename) {
            display_csv(networks2, network_count2, iface, csv_filename);
        } else {
            display_results(networks2, network_count2, iface);
        }
        
        printf("  Scan completed in %.0f ms\n", scan_time2);
        
        free(networks2);
    }
    
    scanner_cleanup(&ctx);
    return 0;
}
