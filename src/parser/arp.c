#include "arp.h"
#include <stdio.h>
#include <arpa/inet.h>

int parse_arp(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct arp_packet)) {
        return PARSE_TRUNCATED;
    }
    
    pkt->arp_pkt = (struct arp_packet*)data;

    return PARSE_SUCCESS;
}

const char* arp_opcode_to_string(uint16_t opcode) {
    switch (ntohs(opcode)) {
        case ARP_OP_REQUEST: return "Request";
        case ARP_OP_REPLY: return "Reply";
        default: return "Unknown";
    }
}