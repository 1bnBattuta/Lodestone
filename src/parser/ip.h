#ifndef IP_H
#define IP_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"
#include <netinet/ip.h>
#include <arpa/inet.h>

int parse_ipv4(packet_t *pkt, const uint8_t *data, size_t len);
int validate_ip_checksum(const struct iphdr *ip_hdr);
void format_ipv4(uint32_t ip, char *buf, size_t buflen);
uint32_t parse_ipv4_addr(const char *str);

// IP fragmentation tracking
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t id;
    uint8_t protocol;
    uint16_t offset;
    uint8_t more_fragments;
} ip_frag_info_t;

int is_fragmented(const struct iphdr *ip_hdr);
int get_frag_info(const struct iphdr *ip_hdr, ip_frag_info_t *info);

#endif