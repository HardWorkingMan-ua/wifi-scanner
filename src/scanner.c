#include "scanner.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <linux/nl80211.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <sys/types.h>
#include <net/if.h>

static int scan_callback(struct nl_msg *msg, void *arg);
static int finish_handler(struct nl_msg *msg, void *arg);
static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg);
static int ack_callback(struct nl_msg *msg, void *arg);
static void mac_addr_n2a(char *mac_addr, unsigned char *arg);
static wifi_band_t frequency_to_band(int freq_mhz);
static int get_scan_results(scanner_ctx_t *ctx);

#define NUM_VENDORS 573
static struct {
    const char *prefix;
    const char *name;
} oui_table[NUM_VENDORS] = {
    {"00:00:0C", "Cisco"},
    {"00:01:42", "Cisco"},
    {"00:1A:A0", "Dell"},
    {"00:14:22", "Dell"},
    {"00:50:56", "VMware"},
    {"08:00:27", "VirtualBox"},
    {"00:03:FF", "Microsoft"},
    {"00:0D:3A", "Microsoft"},
    {"00:12:5A", "Microsoft"},
    {"00:15:5D", "Microsoft"},
    {"00:17:88", "Philips"},
    {"00:1E:C2", "Apple"},
    {"3C:22:FB", "Apple"},
    {"60:F8:1D", "Apple"},
    {"00:1F:5B", "Intel"},
    {"00:1E:67", "Intel"},
    {"00:1B:21", "Intel"},
    {"00:24:D7", "Intel"},
    {"00:26:C6", "Intel"},
    {"00:26:C7", "Intel"},
    {"00:27:10", "Intel"},
    {"B4:E6:2D", "Google"},
    {"3C:5A:B4", "Google"},
    {"94:EB:2C", "Google"},
    {"F4:F5:D8", "Google"},
    {"00:1A:11", "Google"},
    {"18:D6:C7", "Google"},
    {"00:0C:29", "VMware"},
    {"B4:2E:99", "HP"},
    {"00:1E:0B", "HP"},
    {"3C:D9:2B", "HP"},
    {"00:1F:29", "Hewlett-Packard"},
    {"00:25:B3", "Hewlett-Packard"},
    {"D4:85:64", "Hewlett-Packard"},
    {"00:1A:4B", "Netgear"},
    {"00:22:3F", "Netgear"},
    {"30:46:9A", "Netgear"},
    {"C4:04:15", "Netgear"},
    {"00:18:E7", "Cameo"},
    {"00:1D:D8", "Microsoft Xbox"},
    {"7C:ED:8D", "Microsoft Xbox"},
    {"00:1D:D9", "Microsoft Xbox"},
    {"50:6A:03", "Netgear"},
    {"00:1B:2F", "Linksys"},
    {"00:14:BF", "Linksys"},
    {"20:AA:4B", "Linksys"},
    {"C0:C1:C0", "Asus"},
    {"2C:4D:54", "Asus"},
    {"00:1E:8C", "Asus"},
    {"AC:9E:17", "Asus"},
    {"14:CC:20", "TP-Link"},
    {"18:D6:C7", "TP-Link"},
    {"1C:FA:68", "TP-Link"},
    {"30:B5:C2", "TP-Link"},
    {"50:C7:BF", "TP-Link"},
    {"54:C8:0F", "TP-Link"},
    {"5C:89:9A", "TP-Link"},
    {"64:56:01", "TP-Link"},
    {"64:70:02", "TP-Link"},
    {"78:A1:06", "TP-Link"},
    {"90:F6:52", "TP-Link"},
    {"A8:57:4E", "TP-Link"},
    {"C0:25:E9", "TP-Link"},
    {"C4:6E:1F", "TP-Link"},
    {"D8:07:B6", "TP-Link"},
    {"E8:94:F6", "TP-Link"},
    {"F4:F2:6D", "TP-Link"},
    {"F8:1A:67", "TP-Link"},
    {"AC:84:C6", "TP-Link"},
    {"D8:0D:17", "TP-Link"},
    {"00:27:CD", "Tenda"},
    {"C8:3A:35", "Tenda"},
    {"4C:ED:FB", "Tenda"},
    {"78:A2:A0", "Tenda"},
    {"9C:21:6A", "Tenda"},
    {"B0:BE:76", "Tenda"},
    {"C4:6E:1F", "Tenda"},
    {"E8:FC:AF", "Tenda"},
    {"00:1F:33", "Netgear"},
    {"00:22:6B", "Netgear"},
    {"00:24:B2", "Netgear"},
    {"00:26:F2", "Netgear"},
    {"20:0C:C8", "Netgear"},
    {"28:80:88", "Netgear"},
    {"2C:B0:5D", "Netgear"},
    {"44:94:FC", "Netgear"},
    {"6C:B0:CE", "Netgear"},
    {"84:1B:5E", "Netgear"},
    {"9C:D3:6D", "Netgear"},
    {"A0:21:B7", "Netgear"},
    {"A4:2B:8C", "Netgear"},
    {"B0:7F:B9", "Netgear"},
    {"C0:FF:D4", "Netgear"},
    {"C4:04:15", "Netgear"},
    {"C8:FC:EA", "Netgear"},
    {"E0:91:F5", "Netgear"},
    {"E4:F4:C6", "Netgear"},
    {"F8:73:94", "Netgear"},
    {"00:1E:58", "D-Link"},
    {"00:1F:3C", "D-Link"},
    {"00:22:B0", "D-Link"},
    {"00:26:5A", "D-Link"},
    {"00:50:BA", "D-Link"},
    {"14:D6:4D", "D-Link"},
    {"1C:7E:E5", "D-Link"},
    {"28:10:7B", "D-Link"},
    {"34:08:04", "D-Link"},
    {"3C:1E:04", "D-Link"},
    {"5C:D9:98", "D-Link"},
    {"78:32:1B", "D-Link"},
    {"90:EE:43", "D-Link"},
    {"9C:D6:43", "D-Link"},
    {"AC:F1:DF", "D-Link"},
    {"B8:A3:86", "D-Link"},
    {"BC:F6:85", "D-Link"},
    {"C4:A8:1D", "D-Link"},
    {"C8:BE:19", "D-Link"},
    {"CC:B2:55", "D-Link"},
    {"E4:6F:13", "D-Link"},
    {"EC:22:80", "D-Link"},
    {"F0:7D:68", "D-Link"},
    {"F8:1A:67", "D-Link"},
    {"00:9A:CD", "Huawei"},
    {"00:E0:FC", "Huawei"},
    {"00:F8:1C", "Huawei"},
    {"04:02:1F", "Huawei"},
    {"04:25:C5", "Huawei"},
    {"04:33:C2", "Huawei"},
    {"04:75:03", "Huawei"},
    {"04:B0:E7", "Huawei"},
    {"04:C0:6F", "Huawei"},
    {"04:F9:38", "Huawei"},
    {"04:FE:8D", "Huawei"},
    {"08:19:A6", "Huawei"},
    {"0C:37:DC", "Huawei"},
    {"0C:96:BF", "Huawei"},
    {"10:1B:54", "Huawei"},
    {"10:44:00", "Huawei"},
    {"10:47:80", "Huawei"},
    {"10:C6:1F", "Huawei"},
    {"14:B9:68", "Huawei"},
    {"14:FE:B5", "Huawei"},
    {"18:C5:8A", "Huawei"},
    {"1C:8E:5C", "Huawei"},
    {"20:08:ED", "Huawei"},
    {"20:0B:C7", "Huawei"},
    {"20:2B:C1", "Huawei"},
    {"20:F3:A3", "Huawei"},
    {"24:09:95", "Huawei"},
    {"28:31:52", "Huawei"},
    {"28:6E:D4", "Huawei"},
    {"2C:AB:00", "Huawei"},
    {"30:10:E4", "Huawei"},
    {"30:D1:7E", "Huawei"},
    {"30:F3:35", "Huawei"},
    {"34:00:A3", "Huawei"},
    {"34:29:12", "Huawei"},
    {"34:A2:A2", "Huawei"},
    {"38:37:8B", "Huawei"},
    {"38:F8:89", "Huawei"},
    {"3C:47:11", "Huawei"},
    {"3C:DF:BD", "Huawei"},
    {"40:4D:8E", "Huawei"},
    {"40:CB:A8", "Huawei"},
    {"44:55:B1", "Huawei"},
    {"48:3C:0C", "Huawei"},
    {"48:62:76", "Huawei"},
    {"4C:1F:CC", "Huawei"},
    {"4C:54:99", "Huawei"},
    {"50:A7:2B", "Huawei"},
    {"54:39:DF", "Huawei"},
    {"54:89:98", "Huawei"},
    {"58:1F:AA", "Huawei"},
    {"58:2A:F7", "Huawei"},
    {"58:7F:66", "Huawei"},
    {"5C:4C:A9", "Huawei"},
    {"5C:7D:5E", "Huawei"},
    {"5C:C3:07", "Huawei"},
    {"60:DE:44", "Huawei"},
    {"60:E7:01", "Huawei"},
    {"64:16:F0", "Huawei"},
    {"68:89:C1", "Huawei"},
    {"6C:B7:49", "Huawei"},
    {"70:54:F5", "Huawei"},
    {"70:72:3C", "Huawei"},
    {"74:59:09", "Huawei"},
    {"74:88:2A", "Huawei"},
    {"78:D7:5F", "Huawei"},
    {"78:F5:57", "Huawei"},
    {"7C:60:97", "Huawei"},
    {"80:71:7A", "Huawei"},
    {"80:B6:86", "Huawei"},
    {"80:D0:9B", "Huawei"},
    {"80:FB:06", "Huawei"},
    {"84:46:FE", "Huawei"},
    {"84:A8:E4", "Huawei"},
    {"84:BE:52", "Huawei"},
    {"88:53:D4", "Huawei"},
    {"88:86:03", "Huawei"},
    {"8C:34:FD", "Huawei"},
    {"8C:85:90", "Huawei"},
    {"90:17:AC", "Huawei"},
    {"90:67:1C", "Huawei"},
    {"90:E2:FC", "Huawei"},
    {"94:04:9C", "Huawei"},
    {"94:77:2B", "Huawei"},
    {"98:E7:F5", "Huawei"},
    {"9C:28:EF", "Huawei"},
    {"9C:37:F4", "Huawei"},
    {"9C:52:F8", "Huawei"},
    {"9C:8B:C0", "Huawei"},
    {"A0:08:6F", "Huawei"},
    {"A0:57:E3", "Huawei"},
    {"A4:71:74", "Huawei"},
    {"A4:99:47", "Huawei"},
    {"A4:C6:4F", "Huawei"},
    {"A8:C8:3A", "Huawei"},
    {"AC:4E:91", "Huawei"},
    {"AC:61:EA", "Huawei"},
    {"AC:85:3D", "Huawei"},
    {"AC:9E:17", "Huawei"},
    {"B0:5B:67", "Huawei"},
    {"B0:E2:35", "Huawei"},
    {"B4:15:13", "Huawei"},
    {"B4:30:52", "Huawei"},
    {"B4:62:93", "Huawei"},
    {"B4:CD:27", "Huawei"},
    {"B8:BC:1B", "Huawei"},
    {"B8:D9:CE", "Huawei"},
    {"BC:25:E0", "Huawei"},
    {"BC:62:0E", "Huawei"},
    {"C4:05:28", "Huawei"},
    {"C4:09:95", "Huawei"},
    {"C4:7D:4F", "Huawei"},
    {"C4:AD:34", "Huawei"},
    {"C4:E9:84", "Huawei"},
    {"C8:0C:C8", "Huawei"},
    {"C8:51:95", "Huawei"},
    {"C8:71:F8", "Huawei"},
    {"CC:53:B5", "Huawei"},
    {"CC:8C:E2", "Huawei"},
    {"D0:03:4B", "Huawei"},
    {"D0:21:F9", "Huawei"},
    {"D0:29:C5", "Huawei"},
    {"D0:65:CA", "Huawei"},
    {"D0:7A:B5", "Huawei"},
    {"D4:61:9D", "Huawei"},
    {"D4:A1:48", "Huawei"},
    {"D4:B1:10", "Huawei"},
    {"D4:EC:0A", "Huawei"},
    {"D8:49:0B", "Huawei"},
    {"D8:C7:71", "Huawei"},
    {"DC:D2:FC", "Huawei"},
    {"E0:19:1D", "Huawei"},
    {"E0:24:7F", "Huawei"},
    {"E0:28:6D", "Huawei"},
    {"E0:97:96", "Huawei"},
    {"E0:A1:D7", "Huawei"},
    {"E0:B9:4D", "Huawei"},
    {"E4:35:C8", "Huawei"},
    {"E4:68:A3", "Huawei"},
    {"E4:77:23", "Huawei"},
    {"E4:7E:66", "Huawei"},
    {"E4:C6:3D", "Huawei"},
    {"E8:08:8B", "Huawei"},
    {"E8:CD:2D", "Huawei"},
    {"EC:23:3D", "Huawei"},
    {"EC:38:8F", "Huawei"},
    {"EC:CB:30", "Huawei"},
    {"F0:43:47", "Huawei"},
    {"F0:69:0F", "Huawei"},
    {"F4:55:9C", "Huawei"},
    {"F4:6A:67", "Huawei"},
    {"F4:C7:14", "Huawei"},
    {"F4:F1:5A", "Huawei"},
    {"F8:01:13", "Huawei"},
    {"F8:3D:FF", "Huawei"},
    {"F8:98:B9", "Huawei"},
    {"F8:E8:11", "Huawei"},
    {"FC:48:EF", "Huawei"},
    {"00:1E:10", "Huawei"},
    {"B0:5B:67", "Huawei"},
    {"00:9A:CD", "Honor"},
    {"04:33:C2", "Honor"},
    {"00:E0:FC", "Honor"},
    {"50:1A:C5", "Xiaomi"},
    {"34:80:B3", "Xiaomi"},
    {"58:44:98", "Xiaomi"},
    {"64:09:80", "Xiaomi"},
    {"64:B4:73", "Xiaomi"},
    {"68:DF:DD", "Xiaomi"},
    {"74:23:44", "Xiaomi"},
    {"78:02:F8", "Xiaomi"},
    {"84:F3:EB", "Xiaomi"},
    {"94:E9:6A", "Xiaomi"},
    {"9C:99:A0", "Xiaomi"},
    {"A4:77:33", "Xiaomi"},
    {"AC:C1:EE", "Xiaomi"},
    {"B0:E2:35", "Xiaomi"},
    {"C4:0B:CB", "Xiaomi"},
    {"C4:6E:1F", "Xiaomi"},
    {"D4:97:0B", "Xiaomi"},
    {"E8:28:45", "Xiaomi"},
    {"F0:B4:79", "Xiaomi"},
    {"F4:F5:D8", "Xiaomi"},
    {"00:1A:11", "Google"},
    {"3C:5A:B4", "Google"},
    {"94:EB:2C", "Google"},
    {"F4:F5:D8", "Google"},
    {"18:D6:C7", "Google"},
    {"B4:E6:2D", "Google"},
    {"54:60:09", "Mercusys"},
    {"30:B5:C2", "Mercusys"},
    {"50:C7:BF", "Mercusys"},
    {"64:56:01", "Mercusys"},
    {"E8:94:F6", "Mercusys"},
    {"A4:2B:B0", "Mercusys"},
    {"98:DA:C4", "Xiaomi"},
    {"04:CF:8C", "Xiaomi"},
    {"20:34:FB", "Xiaomi"},
    {"34:80:BA", "Xiaomi"},
    {"38:A3:95", "Xiaomi"},
    {"4C:63:71", "Xiaomi"},
    {"64:09:80", "Xiaomi"},
    {"74:23:44", "Xiaomi"},
    {"78:02:F8", "Xiaomi"},
    {"84:F3:EB", "Xiaomi"},
    {"8C:BE:BE", "Xiaomi"},
    {"9C:99:A0", "Xiaomi"},
    {"A4:77:33", "Xiaomi"},
    {"AC:C1:EE", "Xiaomi"},
    {"C4:0B:CB", "Xiaomi"},
    {"D4:97:0B", "Xiaomi"},
    {"E8:28:45", "Xiaomi"},
    {"F0:B4:79", "Xiaomi"},
    {"F4:F5:D8", "Xiaomi"},
    {"00:1B:2F", "Linksys"},
    {"00:14:BF", "Linksys"},
    {"20:AA:4B", "Linksys"},
    {"48:F8:B3", "Linksys"},
    {"58:6D:8F", "Linksys"},
    {"68:7F:74", "Linksys"},
    {"88:C3:97", "Linksys"},
    {"98:FC:11", "Linksys"},
    {"C0:C1:C0", "Linksys"},
    {"C8:3A:35", "Tenda"},
    {"00:27:CD", "Tenda"},
    {"4C:ED:FB", "Tenda"},
    {"78:A2:A0", "Tenda"},
    {"9C:21:6A", "Tenda"},
    {"B0:BE:76", "Tenda"},
    {"E8:FC:AF", "Tenda"},
    {"00:1F:33", "Netgear"},
    {"00:22:6B", "Netgear"},
    {"00:24:B2", "Netgear"},
    {"00:26:F2", "Netgear"},
    {"20:0C:C8", "Netgear"},
    {"28:80:88", "Netgear"},
    {"2C:B0:5D", "Netgear"},
    {"44:94:FC", "Netgear"},
    {"6C:B0:CE", "Netgear"},
    {"84:1B:5E", "Netgear"},
    {"9C:D3:6D", "Netgear"},
    {"A0:21:B7", "Netgear"},
    {"A4:2B:8C", "Netgear"},
    {"B0:7F:B9", "Netgear"},
    {"C0:FF:D4", "Netgear"},
    {"C8:FC:EA", "Netgear"},
    {"E0:91:F5", "Netgear"},
    {"E4:F4:C6", "Netgear"},
    {"F8:73:94", "Netgear"},
    {"00:1E:58", "D-Link"},
    {"00:1F:3C", "D-Link"},
    {"00:22:B0", "D-Link"},
    {"00:26:5A", "D-Link"},
    {"00:50:BA", "D-Link"},
    {"14:D6:4D", "D-Link"},
    {"1C:7E:E5", "D-Link"},
    {"28:10:7B", "D-Link"},
    {"34:08:04", "D-Link"},
    {"3C:1E:04", "D-Link"},
    {"5C:D9:98", "D-Link"},
    {"78:32:1B", "D-Link"},
    {"90:EE:43", "D-Link"},
    {"9C:D6:43", "D-Link"},
    {"AC:F1:DF", "D-Link"},
    {"B8:A3:86", "D-Link"},
    {"BC:F6:85", "D-Link"},
    {"C4:A8:1D", "D-Link"},
    {"C8:BE:19", "D-Link"},
    {"CC:B2:55", "D-Link"},
    {"E4:6F:13", "D-Link"},
    {"EC:22:80", "D-Link"},
    {"F0:7D:68", "D-Link"},
    {"F8:1A:67", "D-Link"},
    {"EC:08:6B", "D-Link"},
    {"00:24:01", "D-Link"},
    {"34:21:08", "D-Link"},
    {"5C:D9:98", "D-Link"},
    {"78:54:2C", "D-Link"},
    {"F0:7D:68", "D-Link"},
    {"C8:BE:19", "D-Link"},
    {"00:1F:3C", "D-Link"},
    {"00:22:B0", "D-Link"},
    {"00:26:5A", "D-Link"},
    {"14:D6:4D", "D-Link"},
    {"1C:7E:E5", "D-Link"},
    {"28:10:7B", "D-Link"},
    {"34:08:04", "D-Link"},
    {"3C:1E:04", "D-Link"},
    {"78:32:1B", "D-Link"},
    {"90:EE:43", "D-Link"},
    {"9C:D6:43", "D-Link"},
    {"AC:F1:DF", "D-Link"},
    {"B8:A3:86", "D-Link"},
    {"BC:F6:85", "D-Link"},
    {"C4:A8:1D", "D-Link"},
    {"CC:B2:55", "D-Link"},
    {"E4:6F:13", "D-Link"},
    {"EC:22:80", "D-Link"},
    {"EC:08:6B", "D-Link"},
    {"00:24:01", "D-Link"},
    {"34:21:08", "D-Link"},
    {"78:54:2C", "D-Link"},
    {"34:00:A3", "Huawei"},
    {"34:29:12", "Huawei"},
    {"38:37:8B", "Huawei"},
    {"38:F8:89", "Huawei"},
    {"3C:47:11", "Huawei"},
    {"3C:DF:BD", "Huawei"},
    {"40:4D:8E", "Huawei"},
    {"40:CB:A8", "Huawei"},
    {"44:55:B1", "Huawei"},
    {"48:3C:0C", "Huawei"},
    {"48:62:76", "Huawei"},
    {"4C:1F:CC", "Huawei"},
    {"4C:54:99", "Huawei"},
    {"50:A7:2B", "Huawei"},
    {"54:39:DF", "Huawei"},
    {"54:89:98", "Huawei"},
    {"58:1F:AA", "Huawei"},
    {"58:2A:F7", "Huawei"},
    {"58:7F:66", "Huawei"},
    {"5C:4C:A9", "Huawei"},
    {"5C:7D:5E", "Huawei"},
    {"5C:C3:07", "Huawei"},
    {"60:DE:44", "Huawei"},
    {"60:E7:01", "Huawei"},
    {"64:16:F0", "Huawei"},
    {"68:89:C1", "Huawei"},
    {"6C:B7:49", "Huawei"},
    {"70:54:F5", "Huawei"},
    {"70:72:3C", "Huawei"},
    {"74:59:09", "Huawei"},
    {"74:88:2A", "Huawei"},
    {"78:D7:5F", "Huawei"},
    {"78:F5:57", "Huawei"},
    {"7C:60:97", "Huawei"},
    {"80:71:7A", "Huawei"},
    {"80:B6:86", "Huawei"},
    {"80:D0:9B", "Huawei"},
    {"80:FB:06", "Huawei"},
    {"84:46:FE", "Huawei"},
    {"84:A8:E4", "Huawei"},
    {"84:BE:52", "Huawei"},
    {"88:53:D4", "Huawei"},
    {"88:86:03", "Huawei"},
    {"8C:34:FD", "Huawei"},
    {"8C:85:90", "Huawei"},
    {"90:17:AC", "Huawei"},
    {"90:67:1C", "Huawei"},
    {"90:E2:FC", "Huawei"},
    {"94:04:9C", "Huawei"},
    {"94:77:2B", "Huawei"},
    {"98:E7:F5", "Huawei"},
    {"9C:28:EF", "Huawei"},
    {"9C:37:F4", "Huawei"},
    {"9C:52:F8", "Huawei"},
    {"9C:8B:C0", "Huawei"},
    {"A0:08:6F", "Huawei"},
    {"A0:57:E3", "Huawei"},
    {"A4:71:74", "Huawei"},
    {"A4:99:47", "Huawei"},
    {"A4:C6:4F", "Huawei"},
    {"A8:C8:3A", "Huawei"},
    {"AC:4E:91", "Huawei"},
    {"AC:61:EA", "Huawei"},
    {"AC:85:3D", "Huawei"},
    {"AC:9E:17", "Huawei"},
    {"B0:5B:67", "Huawei"},
    {"B0:E2:35", "Huawei"},
    {"B4:15:13", "Huawei"},
    {"B4:30:52", "Huawei"},
    {"B4:62:93", "Huawei"},
    {"B4:CD:27", "Huawei"},
    {"B8:BC:1B", "Huawei"},
    {"B8:D9:CE", "Huawei"},
    {"BC:25:E0", "Huawei"},
    {"BC:62:0E", "Huawei"},
    {"C4:05:28", "Huawei"},
    {"C4:09:95", "Huawei"},
    {"C4:7D:4F", "Huawei"},
    {"C4:AD:34", "Huawei"},
    {"C4:E9:84", "Huawei"},
    {"C8:0C:C8", "Huawei"},
    {"C8:51:95", "Huawei"},
    {"C8:71:F8", "Huawei"},
    {"CC:53:B5", "Huawei"},
    {"CC:8C:E2", "Huawei"},
    {"D0:03:4B", "Huawei"},
    {"D0:21:F9", "Huawei"},
    {"D0:29:C5", "Huawei"},
    {"D0:65:CA", "Huawei"},
    {"D0:7A:B5", "Huawei"},
    {"D4:61:9D", "Huawei"},
    {"D4:A1:48", "Huawei"},
    {"D4:B1:10", "Huawei"},
    {"D4:EC:0A", "Huawei"},
    {"D8:49:0B", "Huawei"},
    {"D8:C7:71", "Huawei"},
    {"DC:D2:FC", "Huawei"},
    {"E0:19:1D", "Huawei"},
    {"E0:24:7F", "Huawei"},
    {"E0:28:6D", "Huawei"},
    {"E0:97:96", "Huawei"},
    {"E0:A1:D7", "Huawei"},
    {"E0:B9:4D", "Huawei"},
    {"E4:35:C8", "Huawei"},
    {"E4:68:A3", "Huawei"},
    {"E4:77:23", "Huawei"},
    {"E4:7E:66", "Huawei"},
    {"E4:C6:3D", "Huawei"},
    {"E8:08:8B", "Huawei"},
    {"E8:CD:2D", "Huawei"},
    {"EC:23:3D", "Huawei"},
    {"EC:38:8F", "Huawei"},
    {"EC:CB:30", "Huawei"},
    {"F0:43:47", "Huawei"},
    {"F0:69:0F", "Huawei"},
    {"F4:55:9C", "Huawei"},
    {"F4:6A:67", "Huawei"},
    {"F4:C7:14", "Huawei"},
    {"F4:F1:5A", "Huawei"},
    {"F8:01:13", "Huawei"},
    {"F8:3D:FF", "Huawei"},
    {"F8:98:B9", "Huawei"},
    {"F8:E8:11", "Huawei"},
    {"FC:48:EF", "Huawei"},
    {"50:9F:27", "Huawei"},
    {"00:9A:CD", "Huawei"},
    {"E4:68:A3", "Huawei"},
    {"A8:C8:3A", "Huawei"},
    {"20:F3:A3", "Huawei"},
    {"28:31:52", "Huawei"},
    {"28:6E:D4", "Huawei"},
    {"2C:AB:00", "Huawei"},
    {"30:10:E4", "Huawei"},
    {"30:D1:7E", "Huawei"},
    {"30:F3:35", "Huawei"},
    {"E4:7E:66", "Huawei"},
    {"C8:0C:C8", "Huawei"},
    {"10:1B:54", "Huawei"},
    {"10:44:00", "Huawei"},
    {"10:47:80", "Huawei"},
    {"10:C6:1F", "Huawei"},
    {"14:B9:68", "Huawei"},
    {"14:FE:B5", "Huawei"},
    {"18:C5:8A", "Huawei"},
    {"1C:8E:5C", "Huawei"},
    {"20:08:ED", "Huawei"},
    {"20:0B:C7", "Huawei"},
    {"20:2B:C1", "Huawei"},
    {"24:09:95", "Huawei"}
};

const char *get_vendor(const char *bssid) {
    static char unknown[] = "Unknown";
    
    for (int i = 0; i < NUM_VENDORS; i++) {
        if (strncasecmp(bssid, oui_table[i].prefix, 8) == 0) {
            return oui_table[i].name;
        }
    }
    return unknown;
}

const char *band_to_string(wifi_band_t band) {
    switch (band) {
        case BAND_2_4GHZ: return "2.4 GHz";
        case BAND_5GHZ:   return "5 GHz";
        case BAND_6GHZ:   return "6 GHz";
        default:          return "Unknown";
    }
}

static wifi_band_t frequency_to_band(int freq_mhz) {
    if (freq_mhz >= 2400 && freq_mhz <= 2500) {
        return BAND_2_4GHZ;
    } else if (freq_mhz >= 5150 && freq_mhz <= 5900) {
        return BAND_5GHZ;
    } else if (freq_mhz >= 5925 && freq_mhz <= 7125) {
        return BAND_6GHZ;
    }
    return BAND_UNKNOWN;
}

int scanner_init(scanner_ctx_t *ctx, const char *iface) {
    memset(ctx, 0, sizeof(*ctx));
    
    strncpy(ctx->iface_name, iface, IFNAME_SIZE - 1);
    ctx->iface_name[IFNAME_SIZE - 1] = '\0';
    ctx->network_count = 0;
    ctx->timeout_ms = DEFAULT_TIMEOUT_MS;
    
    ctx->sock = nl_socket_alloc();
    if (!ctx->sock) {
        fprintf(stderr, "Failed to allocate netlink socket\n");
        return -1;
    }
    
    if (nl_connect(ctx->sock, NETLINK_GENERIC)) {
        fprintf(stderr, "Failed to connect to netlink\n");
        nl_socket_free(ctx->sock);
        return -1;
    }
    
    ctx->nl80211_id = genl_ctrl_resolve(ctx->sock, "nl80211");
    if (ctx->nl80211_id < 0) {
        fprintf(stderr, "nl80211 interface not found\n");
        nl_socket_free(ctx->sock);
        return -1;
    }
    
    ctx->iface_index = if_nametoindex(iface);
    if (!ctx->iface_index) {
        fprintf(stderr, "Interface '%s' not found\n", iface);
        nl_socket_free(ctx->sock);
        return -1;
    }
    
    nl_socket_set_buffer_size(ctx->sock, 8192, 8192);
    
    return 0;
}

void scanner_cleanup(scanner_ctx_t *ctx) {
    if (ctx->sock) {
        nl_socket_free(ctx->sock);
        ctx->sock = NULL;
    }
}

int scanner_scan(scanner_ctx_t *ctx) {
    ctx->network_count = 0;
    
    int ret;
    
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        return -1;
    }
    
    genlmsg_put(msg, 0, 0, ctx->nl80211_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ctx->iface_index);
    
    struct nl_msg *ssids = nlmsg_alloc();
    nla_put(ssids, 1, 0, "");
    nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);
    nlmsg_free(ssids);
    
    ret = nl_send_auto(ctx->sock, msg);
    if (ret < 0) {
        fprintf(stderr, "Failed to send trigger scan\n");
        nlmsg_free(msg);
        return -1;
    }
    
    nlmsg_free(msg);
    
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        return -1;
    }
    
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_callback, &ret);
    
    ret = nl_recvmsgs(ctx->sock, cb);
    nl_cb_put(cb);
    
    if (ret < 0) {
        if (ret == -EBUSY || ret == -NLE_BUSY) {
            fprintf(stderr, "Note: Using cached scan results (interface is busy)\n");
        } else {
            fprintf(stderr, "Scan trigger failed: %s\n", nl_geterror(ret));
            return -1;
        }
    }
    
    usleep(ctx->timeout_ms * 1000);
    
    return get_scan_results(ctx);
}

static int get_scan_results(scanner_ctx_t *ctx) {
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate scan dump message\n");
        return -1;
    }
    
    genlmsg_put(msg, 0, 0, ctx->nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ctx->iface_index);
    
    ctx->network_count = 0;
    
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        return -1;
    }
    
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, scan_callback, ctx);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, ctx);
    nl_cb_err(cb, NL_CB_DEBUG, error_handler, NULL);
    
    int ret = nl_send_auto(ctx->sock, msg);
    if (ret < 0) {
        fprintf(stderr, "Failed to send scan dump\n");
        nl_cb_put(cb);
        nlmsg_free(msg);
        return -1;
    }
    
    nlmsg_free(msg);
    
    while (1) {
        ret = nl_recvmsgs(ctx->sock, cb);
        if (ret < 0) {
            if (ret == -NLE_INTR) {
                continue;
            }
            break;
        }
        break;
    }
    
    nl_cb_put(cb);
    
    if (ctx->network_count == 0) {
        fprintf(stderr, "No networks found. Try moving closer to access points.\n");
        return -1;
    }
    
    return ctx->network_count;
}

static int scan_callback(struct nl_msg *msg, void *arg) {
    scanner_ctx_t *ctx = (scanner_ctx_t *)arg;
    
    if (ctx->network_count >= MAX_NETWORKS) {
        return NL_SKIP;
    }
    
    wifi_network_t *net = &ctx->networks[ctx->network_count];
    memset(net, 0, sizeof(wifi_network_t));
    
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1];
    
    bss_policy[NL80211_BSS_BSSID].type = NLA_UNSPEC;
    bss_policy[NL80211_BSS_INFORMATION_ELEMENTS].type = NLA_UNSPEC;
    bss_policy[NL80211_BSS_BEACON_IES].type = NLA_UNSPEC;
    bss_policy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
    bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
    bss_policy[NL80211_BSS_STATUS].type = NLA_U32;
    bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
    
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), 
              genlmsg_attrlen(gnlh, 0), NULL);
    
    if (!tb[NL80211_ATTR_BSS]) {
        return NL_SKIP;
    }
    
    nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy);
    
    if (!bss[NL80211_BSS_BSSID]) {
        return NL_SKIP;
    }
    
    unsigned char *bssid = nla_data(bss[NL80211_BSS_BSSID]);
    mac_addr_n2a(net->bssid, bssid);
    
    strncpy(net->vendor, get_vendor(net->bssid), 63);
    net->vendor[63] = '\0';
    
    if (bss[NL80211_BSS_SIGNAL_MBM]) {
        int signal_mbm = (int)nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
        net->signal_dbm = signal_mbm / 100;
    }
    
    if (bss[NL80211_BSS_FREQUENCY]) {
        net->frequency_mhz = (int)nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        net->band = frequency_to_band(net->frequency_mhz);
        
        if (net->frequency_mhz >= 2400 && net->frequency_mhz <= 2500) {
            net->channel = (net->frequency_mhz - 2400) / 5;
            if ((net->frequency_mhz - 2400) % 5 >= 3) {
                net->channel++;
            }
        } else if (net->frequency_mhz >= 5150 && net->frequency_mhz <= 5900) {
            net->channel = (net->frequency_mhz - 5000) / 5;
        } else if (net->frequency_mhz >= 5955 && net->frequency_mhz <= 7115) {
            net->channel = (net->frequency_mhz - 5955) / 5 + 1;
        }
    } else {
        net->band = BAND_UNKNOWN;
    }
    
    int privacy = 0;
    if (bss[NL80211_BSS_CAPABILITY]) {
        uint16_t cap = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
        privacy = cap & (1 << 4);
    }
    
    unsigned char *ies = NULL;
    size_t ies_len = 0;
    
    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        ies = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        ies_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
    } else if (bss[NL80211_BSS_BEACON_IES]) {
        ies = nla_data(bss[NL80211_BSS_BEACON_IES]);
        ies_len = nla_len(bss[NL80211_BSS_BEACON_IES]);
    }
    
    if (ies && ies_len > 0) {
        parse_ies_raw(net, ies, ies_len, privacy);
    } else if (privacy) {
        net->security = SECURITY_WEP;
        strcpy(net->cipher, "WEP");
    } else {
        net->security = SECURITY_OPEN;
        strcpy(net->cipher, "None");
    }
    
    ctx->network_count++;
    return NL_SKIP;
}

static int ack_callback(struct nl_msg *msg, void *arg) {
    (void)msg;
    int *ret = (int *)arg;
    *ret = 0;
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
    (void)msg;
    (void)arg;
    return NL_STOP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {
    (void)nla;
    (void)nlerr;
    (void)arg;
    return NL_SKIP;
}

static void mac_addr_n2a(char *mac_addr, unsigned char *arg) {
    snprintf(mac_addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
}

const wifi_network_t *scanner_get_networks(scanner_ctx_t *ctx, int *count) {
    if (count) {
        *count = ctx->network_count;
    }
    return ctx->networks;
}

wifi_network_t *scanner_get_networks_copy(scanner_ctx_t *ctx, int *count) {
    if (count) {
        *count = ctx->network_count;
    }
    if (ctx->network_count == 0) {
        return NULL;
    }
    wifi_network_t *copy = malloc(ctx->network_count * sizeof(wifi_network_t));
    if (copy) {
        memcpy(copy, ctx->networks, ctx->network_count * sizeof(wifi_network_t));
    }
    return copy;
}

void scanner_free_results(scanner_ctx_t *ctx) {
    ctx->network_count = 0;
}
