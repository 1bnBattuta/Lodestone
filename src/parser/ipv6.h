#ifndef IPV6_H
#define IPV6_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"
#include <netinet/ip6.h>
#include <arpa/inet.h>

// IPv6 extensions header types
#define IPV6_EXT_HOP_BY_HOP 0 // options examined by all devicesin the path
#define IPV6_EXT_ROUTING 43 // specifies the route for a datagram
#define IPV6_EXT_FRAGMENT 44
#define IPV6_EXT_DEST_OPT 60 // Options examined only by the destination
#define IPV6_EXT_AUTH 51 
#define IPV6_EXT_ESP 50 // Carries encrypted data for secure communications
#define IPV6_EXT_NONE 59

// Ipv6 fragment header
struct ipv6_frag_hdr {
    uint8_t next_header;
    uint8_t reserved;
    uint16_t frag_off_res_m; // Fragment offest (13 bit), reserved (2 bit), M flag (1 bit)
    uint32_t identification;
}__attribute__((packed));

// IPv6 generic extension header
struct ipv6_ext_hdr {
    uint8_t next_header;
    uint8_t hdr_len;
    uint8_t data[6];
}__attribute__((packed));

// IPv6 routing header
struct ipv6_rt_hdr {
    uint8_t next_header;
    uint8_t hdr_len;
    uint8_t routing_type;
    uint8_t segments_left;
}__attribute__((packed));

int parse_ipv6(packet_t *pkt, const uint8_t *data, size_t len);
int parse_ipv6_ext_headers(packet_t *pkt, const uint8_t *data, size_t len, uint8_t *next_header, size_t *offset);
void format_ipv6(const struct in6_addr *addr, char *buf, size_t buflen);
int parse_ipv6_addr(const char *str, struct in6_addr *addr);

// IPv6 fragmentation
typedef struct {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    uint32_t id;
    uint8_t next_header;
    uint16_t offset;
    uint8_t more_fragments;
} ipv6_frag_info_t;

int is_ipv6_fragmented(const struct ipv6_frag_hdr *frag_hdr);
int get_ipv6_frag_info(const struct ipv6_frag_hdr *frag_hdr, const struct ip6_hdr *ip6_hdr, ipv6_frag_info_t *info);

#endif