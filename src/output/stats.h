#ifndef STATS_H
#define STATS_H

#include "../utils/common.h"
#include "../utils/packet.h"
#include <stdio.h> // Fixing FILE bug

// Protocol statistics
typedef struct {
    uint64_t ethernet_packets;
    uint64_t ip_packets;
    uint64_t ipv6_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t arp_packets;
    uint64_t other_packets;
    
    uint64_t total_bytes;
    uint64_t tcp_bytes;
    uint64_t udp_bytes;
    
    // TCP flags
    uint64_t tcp_syn;
    uint64_t tcp_fin;
    uint64_t tcp_rst;
    uint64_t tcp_psh;
    uint64_t tcp_ack;
    
    // Errors
    uint64_t truncated_packets;
    uint64_t invalid_packets;
} protocol_stats_t;

// Port statistics entry
typedef struct port_stats_entry {
    uint16_t port;
    uint64_t packet_count;
    uint64_t byte_count;
    struct port_stats_entry *next;
} port_stats_entry_t;

// IP statistics entry
typedef struct ip_stats_entry {
    uint32_t ip_addr;
    uint64_t packet_count;
    uint64_t byte_count;
    struct ip_stats_entry *next;
} ip_stats_entry_t;

typedef struct {
    protocol_stats_t proto_stats;
    
    // Top talkers
    ip_stats_entry_t *ip_stats;
    port_stats_entry_t *port_stats;
    
    // Time tracking
    struct timeval start_time;
    struct timeval last_update;
    
    // Rates
    double packets_per_sec;
    double bytes_per_sec;
} stats_ctx_t;

// Statistics functions
stats_ctx_t* stats_init(void);
void stats_cleanup(stats_ctx_t *ctx);
void stats_update(stats_ctx_t *ctx, const packet_t *pkt);
void stats_calculate_rates(stats_ctx_t *ctx);
void stats_print(stats_ctx_t *ctx, FILE *output);
void stats_print_summary(stats_ctx_t *ctx, FILE *output);
void stats_print_detailed(stats_ctx_t *ctx, FILE *output);
void stats_reset(stats_ctx_t *ctx);

// Helper functions
void stats_add_ip(stats_ctx_t *ctx, uint32_t ip_addr, size_t bytes);
void stats_add_port(stats_ctx_t *ctx, uint16_t port, size_t bytes);

#endif