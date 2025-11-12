#include "packet.h"

packet_t* packet_create(size_t max_size) {
    packet_t *pkt = (packet_t*)malloc(sizeof(packet_t));
    if (!pkt) return NULL;
    
    pkt->raw_data = (uint8_t*)malloc(max_size);
    if (!pkt->raw_data) {
        free(pkt);
        return NULL;
    }
    
    packet_reset(pkt);
    return pkt;
}

void packet_destroy(packet_t *pkt) {
    if (pkt) {
        free(pkt->raw_data);
        free(pkt);
    }
}

void packet_reset(packet_t *pkt) {
    pkt->length = 0;
    pkt->eth_hdr = NULL;
    pkt->network_hdr = NULL;
    pkt->transport_hdr = NULL;
    pkt->payload = NULL;
    pkt->payload_len = 0;
    pkt->protocol = 0;
    pkt->ip_version = 0;
}

// Basic parse - just stores data, actual parsing done by protocol modules
int packet_parse(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len > 65535) return ERROR; // Sanity check
    
    memcpy(pkt->raw_data, data, len);
    pkt->length = len;
    gettimeofday(&pkt->timestamp, NULL);
    
    return SUCCESS;
}