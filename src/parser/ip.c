#include "ip.h"
#include "../utils/checksum.h"
#include <stdio.h>

int parse_ipv4(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct iphdr)) {
        return PARSE_TRUNCATED;
    }
    
    // Direct pointer cast
    pkt->ip_hdr = (struct iphdr*)data;
    
    // Validate version
    if (pkt->ip_hdr->version != 4) {
        return PARSE_INVALID;
    }
    
    // Validate header length
    uint8_t ip_hdr_len = pkt->ip_hdr->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > len) {
        return PARSE_INVALID;
    }
    
    // Validate total length
    uint16_t total_len = ntohs(pkt->ip_hdr->tot_len);
    if (total_len > len) {
        return PARSE_TRUNCATED;
    }
    
    // Optional: Validate checksum (can be expensive, disable for performance)
    #ifdef VALIDATE_CHECKSUMS
    if (validate_ip_checksum(pkt->ip_hdr) != SUCCESS) {
        return PARSE_INVALID;
    }
    #endif
    
    return PARSE_SUCCESS;
}

int validate_ip_checksum(const struct iphdr *ip_hdr) {
    uint16_t received_checksum = ip_hdr->check;
    
    // Create mutable copy for checksum calculation
    struct iphdr temp;
    memcpy(&temp, ip_hdr, sizeof(struct iphdr));
    temp.check = 0;
    
    uint16_t calculated = checksum_ip((uint8_t*)&temp, temp.ihl * 4);
    
    return (calculated == received_checksum) ? SUCCESS : ERROR;
}

void format_ipv4(uint32_t ip, char *buf, size_t buflen) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, buflen);
}

uint32_t parse_ipv4_addr(const char *str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) {
        return 0;
    }
    return addr.s_addr;
}

int is_fragmented(const struct iphdr *ip_hdr) {
    uint16_t frag_off = ntohs(ip_hdr->frag_off);
    return (frag_off & IP_MF) || ((frag_off & IP_OFFMASK) != 0);
}

int get_frag_info(const struct iphdr *ip_hdr, ip_frag_info_t *info) {
    if (!ip_hdr || !info) return ERROR;
    
    info->src_ip = ip_hdr->saddr;
    info->dst_ip = ip_hdr->daddr;
    info->id = ntohs(ip_hdr->id);
    info->protocol = ip_hdr->protocol;
    
    uint16_t frag_off = ntohs(ip_hdr->frag_off);
    info->offset = (frag_off & IP_OFFMASK) * 8;
    info->more_fragments = (frag_off & IP_MF) ? 1 : 0;
    
    return SUCCESS;
}