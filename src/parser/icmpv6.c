#include "icmpv6.h"
#include <string.h>

int parse_icmpv6(packet_t *pkt, const uint8_t *data, size_t len);
const char* icmpv6_type_to_string(uint8_t type);
const char* icmpv6_code_to_string(uint8_t type, uint8_t code);

int parse_icmpv6(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct icmp6_hdr)) {
        return PARSE_TRUNCATED;
    }

    pkt->icmp6_hdr = (struct icmp6_hdr*)data;

    // Extract payload
    if (len > sizeof(struct icmp6_hdr)) {
        pkt->payload = (uint8_t*)(data + sizeof(struct icmp6_hdr));
        pkt->payload_len = len - sizeof(struct icmp6_hdr);
    } else {
        pkt->payload = NULL;
        pkt->payload_len = 0;
    }

    return PARSE_SUCCESS;
}

const char* icmpv6_type_to_string(uint8_t type) {
    switch (type) {
        case ICMPV6_TYPE_DEST_UNREACHABLE: return "Destination Unreachable";
        case ICMPV6_TYPE_PACKET_TOO_BIG: return "Packet Too Big";
        case ICMPV6_TYPE_TIME_EXCEEDED: return "Time Exceeded";
        case ICMPV6_TYPE_PARAM_PROBLEM: return "Parameter Problem";
        case ICMPV6_TYPE_ECHO_REQUEST: return "Echo Request";
        case ICMPV6_TYPE_ECHO_REPLY: return "Echo Reply";
        case ICMPV6_TYPE_ROUTER_SOLICIT: return "Router Solicitation";
        case ICMPV6_TYPE_ROUTER_ADVERT: return "Router Advertisement";
        case ICMPV6_TYPE_NEIGHBOR_SOLICIT: return "Neighbor Solicitation";
        case ICMPV6_TYPE_NEIGHBOR_ADVERT: return "Neighbor Advertisement";
        case ICMPV6_TYPE_REDIRECT: return "Redirect";
        default: return "Unknown";
    }
}

const char* icmpv6_code_to_string(uint8_t type, uint8_t code) {
    if (type == ICMPV6_TYPE_DEST_UNREACHABLE) {
        switch (code) {
            case 0: return "No route to destination";
            case 1: return "Communication administratively prohibited";
            case 2: return "Beyond scope of source address";
            case 3: return "Address unreachable";
            case 4: return "Port unreachable";
            default: return "Unknown code";
        }
    }
    
    if (type == ICMPV6_TYPE_TIME_EXCEEDED) {
        switch (code) {
            case 0: return "Hop limit exceeded";
            case 1: return "Fragment reassembly time exceeded";
            default: return "Unknown code";
        }
    }
    
    return "";
}

