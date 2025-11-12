#ifndef ARP_H
#define ARP_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"
#include <net/if_arp.h>
#include <netinet/if_ether.h>

// ARP packet structure (not always in standard headers)
struct arp_packet {
    uint16_t hw_type;           // Hardware type (Ethernet = 1)
    uint16_t proto_type;        // Protocol type (IPv4 = 0x0800)
    uint8_t hw_addr_len;        // Hardware address length (6 for MAC)
    uint8_t proto_addr_len;     // Protocol address length (4 for IPv4)
    uint16_t opcode;            // Operation (1=request, 2=reply)
    uint8_t sender_hw[6];       // Sender MAC
    uint8_t sender_proto[4];    // Sender IP
    uint8_t target_hw[6];       // Target MAC
    uint8_t target_proto[4];    // Target IP
} __attribute__((packed));

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

int parse_arp(packet_t *pkt, const uint8_t *data, size_t len);
const char* arp_opcode_to_string(uint16_t opcode);

#endif