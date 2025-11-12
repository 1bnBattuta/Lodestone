#ifndef PARSER_H
#define PARSER_H

#include "../utils/common.h"
#include "../utils/packet.h"

// Parser result codes
#define PARSE_SUCCESS 0
#define PARSE_ERROR -1
#define PARSE_TRUNCATED -2
#define PARSE_INVALID -3

// Main parsing function - dispatches to protocol parsers
int parse_packet_layers(packet_t *pkt);

#endif