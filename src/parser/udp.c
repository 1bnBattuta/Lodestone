#include "udp.h"
#include "../utils/checksum.h"

int parse_udp(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct udphdr)) {
        return PARSE_TRUNCATED;
    }
    
    // Direct pointer cast
    pkt->udp_hdr = (struct udphdr*)data;
    
    // Validate length
    uint16_t udp_len = ntohs(pkt->udp_hdr->len);
    if (udp_len < sizeof(struct udphdr) || udp_len > len) {
        return PARSE_INVALID;
    }
    
    // Extract payload
    if (len > sizeof(struct udphdr)) {
        pkt->payload = (uint8_t*)(data + sizeof(struct udphdr));
        pkt->payload_len = len - sizeof(struct udphdr);
    } else {
        pkt->payload = NULL;
        pkt->payload_len = 0;
    }
    
    // Optional: Validate checksum (0 means no checksum in UDP)
    #ifdef VALIDATE_CHECKSUMS
    if (pkt->udp_hdr->check != 0 && pkt->ip_hdr) {
        if (validate_udp_checksum(pkt->udp_hdr, pkt->ip_hdr->saddr,
                                  pkt->ip_hdr->daddr, len) != SUCCESS) {
            return PARSE_INVALID;
        }
    }
    #endif
    
    return PARSE_SUCCESS;
}

int validate_udp_checksum(const struct udphdr *udp_hdr,
                          uint32_t src_ip, uint32_t dst_ip, size_t len) {
    uint16_t received = udp_hdr->check;
    if (received == 0) return SUCCESS; // No checksum
    
    // Create mutable copy
    uint8_t *temp = (uint8_t*)malloc(len);
    if (!temp) return ERROR;
    
    memcpy(temp, udp_hdr, len);
    ((struct udphdr*)temp)->check = 0;
    
    uint16_t calculated = checksum_tcp_udp(temp, len, src_ip, dst_ip, PROTO_UDP);
    free(temp);
    
    return (calculated == received) ? SUCCESS : ERROR;
}