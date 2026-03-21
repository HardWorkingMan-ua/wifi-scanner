#ifndef DISPLAY_H
#define DISPLAY_H

#include "scanner.h"

void display_results(const wifi_network_t *networks, int count, const char *iface);
void display_json(const wifi_network_t *networks, int count, const char *iface);

#endif
