#ifndef TCP_H
#define TCP_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"
#include <netinet/tcp.h>

int parse_tcp(packet_t *pkt, const uint8_t *data, size_t len);
int validate_tcp_checksum(const struct tcphdr *tcp_hdr, 
                          uint32_t src_ip, uint32_t dst_ip, size_t len);

// TCP flags helpers
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

typedef struct {
    uint8_t fin:1;
    uint8_t syn:1;
    uint8_t rst:1;
    uint8_t psh:1;
    uint8_t ack:1;
    uint8_t urg:1;
} tcp_flags_t;

void get_tcp_flags(const struct tcphdr *tcp_hdr, tcp_flags_t *flags);
void format_tcp_flags(const tcp_flags_t *flags, char *buf, size_t buflen);

// TCP options parsing
typedef struct {
    uint8_t kind;
    uint8_t length;
    uint8_t *data;
} tcp_option_t;

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_WINDOW_SCALE 3
#define TCP_OPT_SACK_PERMITTED 4
#define TCP_OPT_SACK 5
#define TCP_OPT_TIMESTAMP 8

int parse_tcp_options(const struct tcphdr *tcp_hdr, tcp_option_t *options, int max_opts);

#endif