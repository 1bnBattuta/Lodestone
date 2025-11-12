#include "ethernet.h"
#include <stdio.h>

int parse_ethernet(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct ether_header)) {
        return PARSE_TRUNCATED;
    }
    
    // Direct pointer cast - zero copy
    pkt->eth_hdr = (struct ether_header*)data;
    
    return PARSE_SUCCESS;
}

void format_mac(const uint8_t *mac, char *buf, size_t buflen) {
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int compare_mac(const uint8_t *mac1, const uint8_t *mac2) {
    return memcmp(mac1, mac2, ETH_ALEN);
}