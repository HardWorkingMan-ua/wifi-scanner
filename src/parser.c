#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/nl80211.h>

#define WPA_OUI 0x0050f2

static void parse_rsn_ie(wifi_network_t *net, unsigned char *ie, size_t len);
static void parse_wpa_vendor_ie(wifi_network_t *net, unsigned char *ie, size_t len);

void parse_ies_raw(wifi_network_t *net, unsigned char *ies, size_t ies_len, int privacy) {
    unsigned char *ie = ies;
    unsigned char *rsn_ie = NULL;
    size_t rsn_ie_len = 0;
    unsigned char *wpa_ie = NULL;
    size_t wpa_ie_len = 0;
    int found_ssid = 0;
    
    while (ie < ies + ies_len) {
        if (ie + 2 > ies + ies_len) break;
        
        unsigned char elem_id = ie[0];
        unsigned char elem_len = ie[1];
        
        if (ie + 2 + elem_len > ies + ies_len) break;
        
        if (elem_id == 0 && !found_ssid) {
            if (elem_len <= 32) {
                memcpy(net->ssid, ie + 2, elem_len);
                net->ssid[elem_len] = '\0';
                found_ssid = 1;
            }
        } else if (elem_id == 48) {
            rsn_ie = ie + 2;
            rsn_ie_len = elem_len;
        } else if (elem_id == 221) {
            if (elem_len >= 4) {
                unsigned int oui = (ie[2] << 16) | (ie[3] << 8) | ie[4];
                if (oui == WPA_OUI) {
                    wpa_ie = ie + 2;
                    wpa_ie_len = elem_len;
                }
            }
        }
        
        ie += 2 + elem_len;
    }
    
    if (rsn_ie && rsn_ie_len > 0) {
        parse_rsn_ie(net, rsn_ie, rsn_ie_len);
    } else if (wpa_ie && wpa_ie_len > 0) {
        parse_wpa_vendor_ie(net, wpa_ie, wpa_ie_len);
    } else if (privacy) {
        net->security = SECURITY_WEP;
        strcpy(net->cipher, "WEP");
    } else {
        net->security = SECURITY_OPEN;
        strcpy(net->cipher, "None");
    }
}

static void parse_rsn_ie(wifi_network_t *net, unsigned char *ie, size_t len) {
    if (len < 2) {
        strcpy(net->cipher, "CCMP");
        net->security = SECURITY_WPA2;
        return;
    }
    
    unsigned short version = (ie[0] << 8) | ie[1];
    if (version != 1) {
        strcpy(net->cipher, "CCMP");
        net->security = SECURITY_WPA2;
        return;
    }
    
    unsigned char *ptr = ie + 2;
    size_t remaining = len - 2;
    
    if (remaining < 4) {
        strcpy(net->cipher, "CCMP");
        net->security = SECURITY_WPA2;
        return;
    }
    
    unsigned short group_cipher = (ptr[0] << 8) | ptr[1];
    switch (group_cipher) {
        case 6:  strcpy(net->cipher, "GCMP-256"); break;
        case 5:  strcpy(net->cipher, "CCMP-256"); break;
        case 4:  strcpy(net->cipher, "GCMP"); break;
        case 2:  strcpy(net->cipher, "TKIP"); break;
        default: strcpy(net->cipher, "CCMP"); break;
    }
    ptr += 4;
    remaining -= 4;
    
    if (remaining < 2) {
        net->security = SECURITY_WPA2;
        return;
    }
    unsigned short pairwise_count = (ptr[0] << 8) | ptr[1];
    ptr += 2 + (pairwise_count * 4);
    remaining -= 2 + (pairwise_count * 4);
    
    if (remaining < 2) {
        net->security = SECURITY_WPA2;
        return;
    }
    unsigned short akm_count = (ptr[0] << 8) | ptr[1];
    ptr += 2;
    remaining -= 2;
    
    int has_sae = 0, has_ft_sae = 0, has_psk = 0, has_ft_psk = 0;
    int has_owe = 0, has_eap = 0;
    
    for (int i = 0; i < akm_count && remaining >= 4; i++) {
        unsigned int akm = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        switch (akm) {
            case 0x000FAC08: has_sae = 1; break;
            case 0x000FAC09: has_ft_sae = 1; break;
            case 0x000FAC02: has_psk = 1; break;
            case 0x000FAC04: has_ft_psk = 1; break;
            case 0x000FAC18: has_eap = 1; break;
            case 0x000FAC12: has_eap = 1; break;
            case 0x000FAC06: has_owe = 1; break;
        }
        ptr += 4;
        remaining -= 4;
    }
    
    if (has_sae || has_ft_sae || has_owe) {
        net->security = SECURITY_WPA3;
    } else if (has_psk || has_ft_psk || has_eap) {
        net->security = SECURITY_WPA2;
    } else {
        net->security = SECURITY_WPA2;
    }
}

static void parse_wpa_vendor_ie(wifi_network_t *net, unsigned char *ie, size_t len) {
    if (len < 6) {
        strcpy(net->cipher, "TKIP");
        net->security = SECURITY_WPA;
        return;
    }
    
    unsigned short version = (ie[4] << 8) | ie[5];
    if (version != 1) {
        strcpy(net->cipher, "TKIP");
        net->security = SECURITY_WPA;
        return;
    }
    
    unsigned char *ptr = ie + 6;
    size_t remaining = len - 6;
    
    if (remaining < 4) {
        strcpy(net->cipher, "TKIP");
        net->security = SECURITY_WPA;
        return;
    }
    
    unsigned short group_cipher = (ptr[2] << 8) | ptr[3];
    switch (group_cipher) {
        case 4:
        case 5: strcpy(net->cipher, "CCMP"); break;
        default: strcpy(net->cipher, "TKIP"); break;
    }
    
    net->security = SECURITY_WPA;
}

const char *security_to_string(security_type_t sec) {
    switch (sec) {
        case SECURITY_OPEN:     return "Open";
        case SECURITY_WEP:     return "WEP";
        case SECURITY_WPA:     return "WPA";
        case SECURITY_WPA2:    return "WPA2";
        case SECURITY_WPA3:   return "WPA3";
        case SECURITY_WPA2_WPA3: return "WPA2/WPA3";
        case SECURITY_UNKNOWN:
        default:               return "Unknown";
    }
}
