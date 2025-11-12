#include "icmp.h"
#include "../utils/checksum.h"

int parse_icmp(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct icmphdr)) {
        return PARSE_TRUNCATED;
    }
    
    // Direct pointer cast
    pkt->icmp_hdr = (struct icmphdr*)data;
    
    // Extract payload (data after ICMP header)
    if (len > sizeof(struct icmphdr)) {
        pkt->payload = (uint8_t*)(data + sizeof(struct icmphdr));
        pkt->payload_len = len - sizeof(struct icmphdr);
    } else {
        pkt->payload = NULL;
        pkt->payload_len = 0;
    }
    
    // Optional: Validate checksum
    #ifdef VALIDATE_CHECKSUMS
    uint16_t received = pkt->icmp_hdr->checksum;
    
    uint8_t *temp = (uint8_t*)malloc(len);
    if (temp) {
        memcpy(temp, data, len);
        ((struct icmphdr*)temp)->checksum = 0;
        uint16_t calculated = checksum_ip(temp, len);
        free(temp);
        
        if (calculated != received) {
            return PARSE_INVALID;
        }
    }
    #endif
    
    return PARSE_SUCCESS;
}

const char* icmp_type_to_string(uint8_t type) {
    switch (type) {
        case ICMP_TYPE_ECHO_REPLY: return "Echo Reply";
        case ICMP_TYPE_DEST_UNREACHABLE: return "Destination Unreachable";
        case ICMP_TYPE_SOURCE_QUENCH: return "Source Quench";
        case ICMP_TYPE_REDIRECT: return "Redirect";
        case ICMP_TYPE_ECHO_REQUEST: return "Echo Request";
        case ICMP_TYPE_TIME_EXCEEDED: return "Time Exceeded";
        case ICMP_TYPE_PARAM_PROBLEM: return "Parameter Problem";
        case ICMP_TYPE_TIMESTAMP: return "Timestamp";
        case ICMP_TYPE_TIMESTAMP_REPLY: return "Timestamp Reply";
        default: return "Unknown";
    }
}

const char* icmp_code_to_string(uint8_t type, uint8_t code) {
    if (type == ICMP_TYPE_DEST_UNREACHABLE) {
        switch (code) {
            case ICMP_NET_UNREACH: return "Network Unreachable";
            case ICMP_HOST_UNREACH: return "Host Unreachable";
            case ICMP_PROT_UNREACH: return "Protocol Unreachable";
            case ICMP_PORT_UNREACH: return "Port Unreachable";
            case ICMP_FRAG_NEEDED: return "Fragmentation Needed";
            case ICMP_SR_FAILED: return "Source Route Failed";
            default: return "Unknown Code";
        }
    }
    
    if (type == ICMP_TYPE_TIME_EXCEEDED) {
        switch (code) {
            case ICMP_EXC_TTL: return "TTL Exceeded";
            case ICMP_EXC_FRAGTIME: return "Fragment Reassembly Time Exceeded";
            default: return "Unknown Code";
        }
    }
    
    return "";
}