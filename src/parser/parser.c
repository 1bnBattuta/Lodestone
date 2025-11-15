#include "parser.h"
#include "ethernet.h"
#include "ip.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "icmpv6.h"
#include "arp.h"

int parse_packet_layers(packet_t *pkt) {
    if (!pkt || !pkt->raw_data || pkt->length == 0) {
        return PARSE_ERROR;
    }
    
    uint8_t *data = pkt->raw_data;
    size_t remaining = pkt->length;
    
    // Layer 2: Ethernet
    int ret = parse_ethernet(pkt, data, remaining);
    if (ret != PARSE_SUCCESS) {
        return ret;
    }
    
    // Check if we have Layer 3
    if (!pkt->eth_hdr) {
        return PARSE_SUCCESS; // Valid ethernet-only packet
    }
    
    uint16_t eth_type = ntohs(pkt->eth_hdr->ether_type);
    data += sizeof(struct ether_header); // move pointer forward
    remaining -= sizeof(struct ether_header);
    
    // Layer 3: Network layer
    switch (eth_type) {
        case ETH_TYPE_IP:
            ret = parse_ipv4(pkt, data, remaining);
            if (ret != PARSE_SUCCESS) {
                return ret;
            }
            pkt->ip_version = 4;

            if (!pkt->ip_hdr) {
                return PARSE_SUCCESS;
            }

            uint8_t ip_header_len = (pkt->ip_hdr->ihl) * 4;
            data += ip_header_len;
            remaining -= ip_header_len;
            pkt->protocol = pkt->ip_hdr->protocol;
            break;
            
        case ETH_TYPE_ARP:
            ret = parse_arp(pkt, data, remaining);
            data += sizeof(struct arp_packet);
            remaining -= sizeof(struct arp_packet);
            return ret; // ARP has no higher layers
            
        case ETH_TYPE_IPV6:
            ret = parse_ipv6(pkt, data, remaining);
            if (ret != PARSE_SUCCESS) {
                return ret;
            }
            pkt->ip_version = 6;

            // Parse extension headers
            uint8_t next_header;
            size_t offset;
            ret = parse_ipv6_ext_headers(pkt, data, remaining, &next_header, &offset);
            if (ret != PARSE_SUCCESS) {
                return ret;
            }

            data += offset;
            remaining -= offset;
            pkt->protocol = next_header;
            
        default:
            // Unknown ethernet type, but valid packet
            return PARSE_SUCCESS;
    }
    
    // Layer 4: Transport layer (only if we have IP)
    if (!pkt->ip_hdr || !pkt->ip6_hdr) {
        return PARSE_SUCCESS;
    }

    switch (pkt->protocol) {
        case PROTO_TCP:
            ret = parse_tcp(pkt, data, remaining);
            break;
            
        case PROTO_UDP:
            ret = parse_udp(pkt, data, remaining);
            break;
            
        case PROTO_ICMP:
            ret = parse_icmp(pkt, data, remaining);
            break;
        
        case IPPROTO_ICMPV6:
            if (pkt->ip_version == 6) {
                ret = parse_icmpv6(pkt, data, remaining);
            }
            break;
        
        default:
            // Unknown protocol but valid IP packet
            pkt->payload = data;
            pkt->payload_len = remaining;
            return PARSE_SUCCESS;
    }
    
    return ret;
}