#ifndef PACKET_H
#define PACKET_H

#include "common.h"
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/icmp6.h>

// Unified packet structure
typedef struct {
    uint8_t *raw_data;              // Original packet bytes
    size_t length;                  // Total packet length
    struct timeval timestamp;       // Capture timestamp
    struct ether_header *eth_hdr;   // Layer 2
    union {                         // Layer 3
        struct iphdr *ip_hdr; // IPv4
        struct ip6_hdr *ip6_hdr; // IPv6
        void *network_hdr;
    };
    union {                         // Layer 4
        struct tcphdr *tcp_hdr;
        struct udphdr *udp_hdr;
        struct icmphdr *icmp_hdr;
        struct icmp6_hdr *icmp6_hdr;
        void *transport_hdr;
    };
    uint8_t *payload;               // Payload
    size_t payload_len;
    uint8_t protocol;                // TCP/UDP/ICMP etc
    uint8_t ip_version;
} packet_t;

// Packet operations
packet_t* packet_create(size_t max_size);
void packet_destroy(packet_t *pkt);
void packet_reset(packet_t *pkt);
int packet_parse(packet_t *pkt, const uint8_t *data, size_t len);

#endif