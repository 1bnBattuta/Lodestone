#ifndef ICMP_H
#define ICMP_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"
#include <netinet/ip_icmp.h>

int parse_icmp(packet_t *pkt, const uint8_t *data, size_t len);
const char* icmp_type_to_string(uint8_t type);
const char* icmp_code_to_string(uint8_t type, uint8_t code);

// ICMP types
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_SOURCE_QUENCH 4
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_PARAM_PROBLEM 12
#define ICMP_TYPE_TIMESTAMP 13
#define ICMP_TYPE_TIMESTAMP_REPLY 14

#endif