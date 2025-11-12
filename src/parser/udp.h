#ifndef UDP_H
#define UDP_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"
#include <netinet/udp.h>

int parse_udp(packet_t *pkt, const uint8_t *data, size_t len);
int validate_udp_checksum(const struct udphdr *udp_hdr,
                          uint32_t src_ip, uint32_t dst_ip, size_t len);

#endif