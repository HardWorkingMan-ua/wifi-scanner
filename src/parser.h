#ifndef PARSER_H
#define PARSER_H

#include "scanner.h"
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>

void parse_ies_raw(wifi_network_t *net, unsigned char *ies, size_t ies_len, int privacy);
const char *security_to_string(security_type_t sec);

#endif
