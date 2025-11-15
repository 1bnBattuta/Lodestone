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
        struct arp_packet *arp_pkt;
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

// Packet operations
packet_t* packet_create(size_t max_size);
void packet_destroy(packet_t *pkt);
void packet_reset(packet_t *pkt);
int packet_parse(packet_t *pkt, const uint8_t *data, size_t len);

#endif