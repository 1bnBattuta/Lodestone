#include "arp.h"
#include <stdio.h>
#include <arpa/inet.h>

int parse_arp(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct arp_packet)) {
        return PARSE_TRUNCATED;
    }
    
    // ARP doesn't fit into our normal packet structure perfectly
    // Store pointer in payload for now
    pkt->payload = (uint8_t*)data;
    pkt->payload_len = len;
    
    return PARSE_SUCCESS;
}

const char* arp_opcode_to_string(uint16_t opcode) {
    switch (ntohs(opcode)) {
        case ARP_OP_REQUEST: return "Request";
        case ARP_OP_REPLY: return "Reply";
        default: return "Unknown";
    }
}