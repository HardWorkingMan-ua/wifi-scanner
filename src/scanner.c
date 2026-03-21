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

int scanner_init(scanner_ctx_t *ctx, const char *iface) {
    memset(ctx, 0, sizeof(*ctx));
    
    strncpy(ctx->iface_name, iface, IFNAME_SIZE - 1);
    ctx->iface_name[IFNAME_SIZE - 1] = '\0';
    ctx->network_count = 0;
    
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
    
    int ret = nl_send_auto(ctx->sock, msg);
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
        fprintf(stderr, "Scan trigger failed: %s\n", nl_geterror(ret));
        return -1;
    }
    
    usleep(2000000);
    
    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate scan dump message\n");
        return -1;
    }
    
    genlmsg_put(msg, 0, 0, ctx->nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ctx->iface_index);
    
    ctx->network_count = 0;
    
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        return -1;
    }
    
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, scan_callback, ctx);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, ctx);
    nl_cb_err(cb, NL_CB_DEBUG, error_handler, NULL);
    
    ret = nl_send_auto(ctx->sock, msg);
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
        if (ctx->network_count > 0) {
            break;
        }
        break;
    }
    
    nl_cb_put(cb);
    
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
    
    if (bss[NL80211_BSS_SIGNAL_MBM]) {
        int signal_mbm = (int)nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
        net->signal_dbm = signal_mbm / 100;
    }
    
    if (bss[NL80211_BSS_FREQUENCY]) {
        net->frequency_mhz = (int)nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        
        if (net->frequency_mhz >= 2400 && net->frequency_mhz <= 2500) {
            net->channel = (net->frequency_mhz - 2400) / 5;
            if ((net->frequency_mhz - 2400) % 5 >= 3) {
                net->channel++;
            }
        } else if (net->frequency_mhz >= 5000 && net->frequency_mhz <= 5900) {
            net->channel = (net->frequency_mhz - 5000) / 5;
        } else if (net->frequency_mhz >= 5955 && net->frequency_mhz <= 7115) {
            net->channel = (net->frequency_mhz - 5955) / 5 + 1;
        }
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
