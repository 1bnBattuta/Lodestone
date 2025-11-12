#include "ipv6.h"
#include <stdio.h>
#include <string.h>

int parse_ipv6(packet_t *pkt, const uint8_t *data, size_t len);
int parse_ipv6_ext_headers(packet_t *pkt, const uint8_t *data, size_t len, uint8_t *next_header, size_t *offset);
void format_ipv6(const struct in6_addr *addr, char *buf, size_t buflen);
int parse_ipv6_addr(const char *str, struct in6_addr *addr);
int is_ipv6_fragmented(const struct ipv6_frag_hdr *frag_hdr);
int get_ipv6_frag_info(const struct ipv6_frag_hdr *frag_hdr, const struct ip6_hdr *ip6_hdr, ipv6_frag_info_t *info);

int parse_ipv6(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct ip6_hdr)) {
        return PARSE_TRUNCATED;
    }

    pkt->ip6_hdr = (struct ip6_hdr*)data; 

    if (((pkt->ip6_hdr->ip6_vfc) >> 4) != 6 ) {
        return PARSE_INVALID;
    }

    // Validate payload length
    uint16_t payload_len = ntohs(pkt->ip6_hdr->ip6_plen);
    if (sizeof(struct ip6_hdr) + payload_len > len) {
        return PARSE_TRUNCATED;
    }

    return PARSE_SUCCESS;
}


int parse_ipv6_ext_headers(packet_t *pkt, const uint8_t *data, size_t len, uint8_t *next_header, size_t *offset) {
    if (!pkt || !data || !next_header || !offset) {
        return PARSE_ERROR;
    }

    struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)data;
    *next_header = ip6_hdr->ip6_nxt;
    *offset = sizeof(struct ip6_hdr);

    // PArse extension headers
    while (*offset < len) {
        switch (*next_header) {
            case IPV6_EXT_HOP_BY_HOP:
            case IPV6_EXT_DEST_OPT:
            case IPV6_EXT_ROUTING: {
                if (*offset + 2 > len) {
                    return PARSE_TRUNCATED;
                }

                struct ipv6_ext_hdr *ext_hdr = (struct ipv6_ext_hdr*)(data + *offset);
                size_t ext_len = (ext_hdr->hdr_len + 1) * 8;

                if (*offset + ext_len > len) {
                    return PARSE_TRUNCATED;
                }

                *next_header = ext_hdr->next_header;
                *offset += ext_len;                
                break;
            }
            case IPV6_EXT_FRAGMENT: {
                if (*offset + sizeof(struct ipv6_frag_hdr) > len) {
                    return PARSE_TRUNCATED;
                }

                struct ipv6_frag_hdr *frag_hdr = (struct ipv6_frag_hdr*)(data + *offset);
                *next_header = frag_hdr->next_header;
                *offset += sizeof(struct ipv6_frag_hdr);

                // Check if this is a fragment
                if (is_ipv6_fragmented(frag_hdr)) {
                    // TODO fragment handling
                }
                break;
            }
            case IPV6_EXT_AUTH: {
                if (*offset + 2 > len) {
                    return PARSE_TRUNCATED;
                }

                struct ipv6_ext_hdr *ext_hdr = (struct ipv6_ext_hdr*)(data + *offset);
                size_t ext_len = (ext_hdr->hdr_len + 2) * 4;

                if (*offset + ext_hdr > len) {
                    return PARSE_TRUNCATED;
                }

                *next_header = ext_hdr->next_header;
                *offset += ext_len;
                break;
            }
            case IPV6_EXT_ESP: {
                // ESP is encrypted, can't parse further
                return PARSE_SUCCESS;
            }
            case IPV6_EXT_NONE: return PARSE_SUCCESS;
            default: {
                // Not an extension header, this is the upper layer protocol
                return PARSE_SUCCESS;
            }
        }
    }

    return PARSE_SUCCESS;
}

void format_ipv6(const struct in6_addr *addr, char *buf, size_t buflen) {
    inet_ntop(AF_INET6, addr, buf, buflen);
}

int parse_ipv6_addr(const char *str, struct in6_addr *addr) {
    if (inet_pton(AF_INET6, str, addr) != 1) {
        return ERROR;
    }
    return SUCCESS;
}

int is_ipv6_fragmented(const struct ipv6_frag_hdr *frag_hdr) {
    uint16_t frag_off_m = ntohs(frag_hdr->frag_off_res_m);
    // Check if M flag is set of fragment offset is non-zero
    return ((frag_off_m & 0x0001) != 0) || ((frag_off_m & 0xFFF8) != 0);
}

int get_ipv6_frag_info(const struct ipv6_frag_hdr *frag_hdr, const struct ip6_hdr *ip6_hdr, ipv6_frag_info_t *info) {
    if (!frag_hdr || !ip6_hdr || !info) return ERROR;
    
    memcpy(&info->src_ip, &ip6_hdr->ip6_src, sizeof(struct in6_addr));
    memcpy(&info->dst_ip, &ip6_hdr->ip6_dst, sizeof(struct in6_addr));
    info->id = ntohs(frag_hdr->identification);
    info->next_header = frag_hdr->next_header;

    uint16_t frag_off_m = ntohs(frag_hdr->frag_off_res_m);
    info->offset = (frag_off_m & 0xFFF8) >> 3;
    info->more_fragments = (frag_off_m & 0x0001);

    return SUCCESS;
}
