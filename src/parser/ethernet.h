#ifndef ETHERNET_H
#define ETHERNET_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"
#include <net/ethernet.h>

int parse_ethernet(packet_t *pkt, const uint8_t *data, size_t len);
void format_mac(const uint8_t *mac, char *buf, size_t buflen);
int compare_mac(const uint8_t *mac1, const uint8_t *mac2);

#endif