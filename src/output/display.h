#ifndef DISPLAY_H
#define DISPLAY_H

#include "../utils/common.h"
#include "../utils/packet.h"
#include <stdio.h>

// Display modes
typedef enum {
    DISPLAY_MODE_BRIEF,      // One line per packet
    DISPLAY_MODE_DETAILED,   // Multi-line with headers
    DISPLAY_MODE_HEX,        // Hex dump
    DISPLAY_MODE_ASCII,      // ASCII representation
    DISPLAY_MODE_FULL        // Everything
} display_mode_t;

// Color support
typedef enum {
    COLOR_RESET = 0,
    COLOR_RED,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_MAGENTA,
    COLOR_CYAN,
    COLOR_WHITE
} color_t;

typedef struct {
    display_mode_t mode;
    int use_colors;
    int show_timestamp;
    int show_raw_bytes;
    FILE *output;
} display_ctx_t;

// Display context management
display_ctx_t* display_init(display_mode_t mode, int use_colors);
void display_cleanup(display_ctx_t *ctx);
void display_set_output(display_ctx_t *ctx, FILE *output);

// Packet display functions
void display_packet(display_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num);
void display_packet_brief(display_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num);
void display_packet_detailed(display_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num);
void display_packet_hex(display_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num);

// Helper display functions
void display_ethernet_header(display_ctx_t *ctx, const struct ether_header *eth);
void display_ip_header(display_ctx_t *ctx, const struct iphdr *ip);
void display_ipv6_header(display_ctx_t *ctx, const struct ip6_hdr *ip6);
void display_tcp_header(display_ctx_t *ctx, const struct tcphdr *tcp);
void display_udp_header(display_ctx_t *ctx, const struct udphdr *udp);
void display_icmp_header(display_ctx_t *ctx, const struct icmphdr *icmp);
void display_icmpv6_header(display_ctx_t *ctx, const struct icmp6_hdr *icmp6);

// Utility functions
void display_hex_dump(display_ctx_t *ctx, const uint8_t *data, size_t len, size_t offset);
void display_ascii_dump(display_ctx_t *ctx, const uint8_t *data, size_t len);
void set_color(display_ctx_t *ctx, color_t color);
void reset_color(display_ctx_t *ctx);

#endif