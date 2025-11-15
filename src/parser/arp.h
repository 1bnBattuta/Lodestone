#ifndef ARP_H
#define ARP_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"

// Arp packet definition is in packet.h to avoid circular importing

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

int parse_arp(packet_t *pkt, const uint8_t *data, size_t len);
const char* arp_opcode_to_string(uint16_t opcode);

#endif