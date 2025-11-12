#ifndef ICMPV6_H
#define ICMPV6_H

#include "../utils/common.h"
#include "../utils/packet.h"
#include "parser.h"

int parse_icmpv6(packet_t *pkt, const uint8_t *data, size_t len);
const char* icmpv6_type_to_string(uint8_t type);
const char* icmpv6_code_to_string(uint8_t type, uint8_t code);

// ICMPv6 types
#define ICMPV6_TYPE_DEST_UNREACHABLE 1
#define ICMPV6_TYPE_PACKET_TOO_BIG 2
#define ICMPV6_TYPE_TIME_EXCEEDED 3
#define ICMPV6_TYPE_PARAM_PROBLEM 4
#define ICMPV6_TYPE_ECHO_REQUEST 128
#define ICMPV6_TYPE_ECHO_REPLY 129
#define ICMPV6_TYPE_ROUTER_SOLICIT 133
#define ICMPV6_TYPE_ROUTER_ADVERT 134
#define ICMPV6_TYPE_NEIGHBOR_SOLICIT 135
#define ICMPV6_TYPE_NEIGHBOR_ADVERT 136
#define ICMPV6_TYPE_REDIRECT 137

#endif