#include "display.h"
#include "../parser/ethernet.h"
#include "../parser/ip.h"
#include "../parser/ipv6.h"
#include "../parser/tcp.h"
#include "../parser/icmp.h"
#include "../parser/icmpv6.h"
#include <time.h>
#include <arpa/inet.h>

static const char* color_codes[] = {
    "\033[0m",   // RESET
    "\033[31m",  // RED
    "\033[32m",  // GREEN
    "\033[33m",  // YELLOW
    "\033[34m",  // BLUE
    "\033[35m",  // MAGENTA
    "\033[36m",  // CYAN
    "\033[37m"   // WHITE
};

display_ctx_t* display_init(display_mode_t mode, int use_colors) {
    display_ctx_t *ctx = (display_ctx_t*)malloc(sizeof(display_ctx_t));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }
    
    ctx->mode = mode;
    ctx->use_colors = use_colors;
    ctx->show_timestamp = 1;
    ctx->show_raw_bytes = 0;
    ctx->output = stdout;
    
    return ctx;
}

void display_cleanup(display_ctx_t *ctx) {
    if (ctx) {
        free(ctx);
    }
}

void display_set_output(display_ctx_t *ctx, FILE *output) {
    if (ctx && output) {
        ctx->output = output;
    }
}

void set_color(display_ctx_t *ctx, color_t color) {
    if (ctx->use_colors && ctx->output == stdout) {
        fprintf(ctx->output, "%s", color_codes[color]);
    }
}

void reset_color(display_ctx_t *ctx) {
    if (ctx->use_colors && ctx->output == stdout) {
        fprintf(ctx->output, "%s", color_codes[COLOR_RESET]);
    }
}

void display_packet(display_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num) {
    if (!ctx || !pkt) return;
    
    switch (ctx->mode) {
        case DISPLAY_MODE_BRIEF:
            display_packet_brief(ctx, pkt, pkt_num);
            break;
        case DISPLAY_MODE_DETAILED:
            display_packet_detailed(ctx, pkt, pkt_num);
            break;
        case DISPLAY_MODE_HEX:
            display_packet_hex(ctx, pkt, pkt_num);
            break;
        case DISPLAY_MODE_FULL:
            display_packet_detailed(ctx, pkt, pkt_num);
            display_packet_hex(ctx, pkt, pkt_num);
            break;
        default:
            display_packet_brief(ctx, pkt, pkt_num);
    }
}

void display_packet_brief(display_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num) {
    FILE *out = ctx->output;
    
    // Packet number
    set_color(ctx, COLOR_CYAN);
    fprintf(out, "[%lu] ", pkt_num);
    reset_color(ctx);
    
    // Timestamp
    if (ctx->show_timestamp) {
        char time_buf[64];
        time_t sec = pkt->timestamp.tv_sec;
        struct tm *tm = localtime(&sec);
        strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);
        fprintf(out, "%s.%06ld ", time_buf, pkt->timestamp.tv_usec);
    }
    
    // Protocol and addresses
    if (pkt->ip_version == 4 && pkt->ip_hdr) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pkt->ip_hdr->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &pkt->ip_hdr->daddr, dst_ip, sizeof(dst_ip));
        
        if (pkt->tcp_hdr) {
            set_color(ctx, COLOR_GREEN);
            fprintf(out, "TCP ");
            reset_color(ctx);
            fprintf(out, "%s:%u -> %s:%u ", 
                    src_ip, ntohs(pkt->tcp_hdr->source),
                    dst_ip, ntohs(pkt->tcp_hdr->dest));
            
            // TCP flags
            tcp_flags_t flags;
            get_tcp_flags(pkt->tcp_hdr, &flags);
            char flag_str[16];
            format_tcp_flags(&flags, flag_str, sizeof(flag_str));
            set_color(ctx, COLOR_YELLOW);
            fprintf(out, "[%s] ", flag_str);
            reset_color(ctx);
            
        } else if (pkt->udp_hdr) {
            set_color(ctx, COLOR_BLUE);
            fprintf(out, "UDP ");
            reset_color(ctx);
            fprintf(out, "%s:%u -> %s:%u ", 
                    src_ip, ntohs(pkt->udp_hdr->source),
                    dst_ip, ntohs(pkt->udp_hdr->dest));
            
        } else if (pkt->icmp_hdr) {
            set_color(ctx, COLOR_MAGENTA);
            fprintf(out, "ICMP ");
            reset_color(ctx);
            fprintf(out, "%s -> %s ", src_ip, dst_ip);
            fprintf(out, "Type=%u Code=%u ", 
                    pkt->icmp_hdr->type, pkt->icmp_hdr->code);
        } else {
            set_color(ctx, COLOR_WHITE);
            fprintf(out, "IP(proto=%u) ", pkt->ip_hdr->protocol);
            reset_color(ctx);
            fprintf(out, "%s -> %s ", src_ip, dst_ip);
        }
    } else if (pkt->ip_version == 6 && pkt->ip6_hdr) {
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_dst, dst_ip, sizeof(dst_ip));
        
        if (pkt->tcp_hdr) {
            set_color(ctx, COLOR_GREEN);
            fprintf(out, "TCP6 ");
            reset_color(ctx);
            fprintf(out, "[%s]:%u -> [%s]:%u ", 
                    src_ip, ntohs(pkt->tcp_hdr->source),
                    dst_ip, ntohs(pkt->tcp_hdr->dest));
            
            tcp_flags_t flags;
            get_tcp_flags(pkt->tcp_hdr, &flags);
            char flag_str[16];
            format_tcp_flags(&flags, flag_str, sizeof(flag_str));
            set_color(ctx, COLOR_YELLOW);
            fprintf(out, "[%s] ", flag_str);
            reset_color(ctx);
            
        } else if (pkt->udp_hdr) {
            set_color(ctx, COLOR_BLUE);
            fprintf(out, "UDP6 ");
            reset_color(ctx);
            fprintf(out, "[%s]:%u -> [%s]:%u ", 
                    src_ip, ntohs(pkt->udp_hdr->source),
                    dst_ip, ntohs(pkt->udp_hdr->dest));
            
        } else if (pkt->icmp6_hdr) {
            set_color(ctx, COLOR_MAGENTA);
            fprintf(out, "ICMPv6 ");
            reset_color(ctx);
            fprintf(out, "[%s] -> [%s] Type=%u Code=%u ", 
                    src_ip, dst_ip,
                    pkt->icmp6_hdr->icmp6_type, pkt->icmp6_hdr->icmp6_code);
        }
    } else if (pkt->eth_hdr) {
        char src_mac[18], dst_mac[18];
        format_mac(pkt->eth_hdr->ether_shost, src_mac, sizeof(src_mac));
        format_mac(pkt->eth_hdr->ether_dhost, dst_mac, sizeof(dst_mac));
        
        set_color(ctx, COLOR_CYAN);
        fprintf(out, "ETH ");
        reset_color(ctx);
        fprintf(out, "%s -> %s ", src_mac, dst_mac);
    }
    
    // Length
    fprintf(out, "Len=%zu", pkt->length);
    
    // Payload size if exists
    if (pkt->payload_len > 0) {
        fprintf(out, " Payload=%zu", pkt->payload_len);
    }
    
    fprintf(out, "\n");
}

void display_packet_detailed(display_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num) {
    FILE *out = ctx->output;
    
    set_color(ctx, COLOR_CYAN);
    fprintf(out, "\n========== Packet #%lu ==========\n", pkt_num);
    reset_color(ctx);
    
    // Timestamp
    if (ctx->show_timestamp) {
        char time_buf[64];
        time_t sec = pkt->timestamp.tv_sec;
        struct tm *tm = localtime(&sec);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(out, "Time: %s.%06ld\n", time_buf, pkt->timestamp.tv_usec);
    }
    
    fprintf(out, "Total Length: %zu bytes\n", pkt->length);
    
    // Ethernet
    if (pkt->eth_hdr) {
        fprintf(out, "\n");
        display_ethernet_header(ctx, pkt->eth_hdr);
    }
    
    // IP
    if (pkt->ip_version == 4 && pkt->ip_hdr) {
        fprintf(out, "\n");
        display_ip_header(ctx, pkt->ip_hdr);
    } else if (pkt->ip_version == 6 && pkt->ip6_hdr) {
        fprintf(out, "\n");
        display_ipv6_header(ctx, pkt->ip6_hdr);
    } else if (pkt->arp_pkt) {
        fprintf(out, "\n");
        display_arp_packet(ctx, pkt->arp_pkt);
    }
    
    // Transport layer
    if (pkt->tcp_hdr) {
        fprintf(out, "\n");
        display_tcp_header(ctx, pkt->tcp_hdr);
    } else if (pkt->udp_hdr) {
        fprintf(out, "\n");
        display_udp_header(ctx, pkt->udp_hdr);
    } else if (pkt->icmp_hdr) {
        fprintf(out, "\n");
        display_icmp_header(ctx, pkt->icmp_hdr);
    } else if (pkt->icmp6_hdr) {
        fprintf(out, "\n");
        display_icmpv6_header(ctx, pkt->icmp6_hdr);
    }
    
    // Payload
    if (pkt->payload && pkt->payload_len > 0) {
        fprintf(out, "\n");
        set_color(ctx, COLOR_YELLOW);
        fprintf(out, "Payload (%zu bytes):\n", pkt->payload_len);
        reset_color(ctx);
        display_ascii_dump(ctx, pkt->payload, pkt->payload_len);
    }
    
    fprintf(out, "\n");
}

void display_ethernet_header(display_ctx_t *ctx, const struct ether_header *eth) {
    FILE *out = ctx->output;
    char src_mac[18], dst_mac[18];
    
    format_mac(eth->ether_shost, src_mac, sizeof(src_mac));
    format_mac(eth->ether_dhost, dst_mac, sizeof(dst_mac));
    
    set_color(ctx, COLOR_GREEN);
    fprintf(out, "Ethernet Header:\n");
    reset_color(ctx);
    fprintf(out, "  Source MAC: %s\n", src_mac);
    fprintf(out, "  Dest MAC: %s\n", dst_mac);
    fprintf(out, "  EtherType: 0x%04x\n", ntohs(eth->ether_type));
}

void display_ip_header(display_ctx_t *ctx, const struct iphdr *ip) {
    FILE *out = ctx->output;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));
    
    set_color(ctx, COLOR_GREEN);
    fprintf(out, "IP Header:\n");
    reset_color(ctx);
    fprintf(out, "  Version: %u\n", ip->version);
    fprintf(out, "  Header Length: %u bytes\n", ip->ihl * 4);
    fprintf(out, "  TOS: 0x%02x\n", ip->tos);
    fprintf(out, "  Total Length: %u\n", ntohs(ip->tot_len));
    fprintf(out, "  ID: %u\n", ntohs(ip->id));
    fprintf(out, "  Flags: 0x%04x\n", ntohs(ip->frag_off) >> 13);
    fprintf(out, "  Fragment Offset: %u\n", (ntohs(ip->frag_off) & 0x1FFF) * 8);
    fprintf(out, "  TTL: %u\n", ip->ttl);
    fprintf(out, "  Protocol: %u\n", ip->protocol);
    fprintf(out, "  Checksum: 0x%04x\n", ntohs(ip->check));
    fprintf(out, "  Source IP: %s\n", src_ip);
    fprintf(out, "  Dest IP: %s\n", dst_ip);
}

void display_ipv6_header(display_ctx_t *ctx, const struct ip6_hdr *ip6) {
    FILE *out = ctx->output;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, sizeof(dst_ip));
    

    set_color(ctx, COLOR_GREEN);
    fprintf(out, "IPv6 Header:\n");
    reset_color(ctx);
    fprintf(out, "  Version: 6\n");
    fprintf(out, "  Traffic Class: 0x%02x\n", (ntohl(ip6->ip6_flow) >> 20) & 0xFF);
    fprintf(out, "  Flow Label: 0x%05x\n", ntohl(ip6->ip6_flow) & 0xFFFFF);
    fprintf(out, "  Payload Length: %u\n", ntohs(ip6->ip6_plen));
    fprintf(out, "  Next Header: %u\n", ip6->ip6_nxt);
    fprintf(out, "  Hop Limit: %u\n", ip6->ip6_hlim);
    fprintf(out, "  Source IP: %s\n", src_ip);
    fprintf(out, "  Dest IP: %s\n", dst_ip);
}

void display_arp_packet(display_ctx_t *ctx, const struct arp_packet *arp){
    FILE *out = ctx->output;

    set_color(ctx, COLOR_GREEN);
    fprintf(out, "ARP Packet:\n");
    reset_color(ctx);
    fprintf(out, "  Hardware Type: %u\n", ntohs(arp->hw_type));
    fprintf(out, "  Protocol Type: %0x\n", ntohs(arp->proto_type));
    fprintf(out, "  Hardware Size: %u\n", arp->hw_addr_len);
    fprintf(out, "  Protocol Size: %u\n", arp->proto_addr_len);
    fprintf(out, "  Operation: %u\n", ntohs(arp->opcode));
    
    char src_mac[18], dst_mac[18];

    format_mac(arp->sender_hw, src_mac, sizeof(src_mac));
    format_mac(arp->target_hw, dst_mac, sizeof(dst_mac));

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &arp->sender_proto, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &arp->target_proto, dst_ip, sizeof(dst_ip));

    fprintf(out, "  Sender Hardware Address: %s\n", src_mac);
    fprintf(out, "  Sender Protocol Address: %s\n", src_ip);
    fprintf(out, "  Target Hardware Address: %s\n", dst_mac);
    fprintf(out, "  Target Protocol Address: %s\n", dst_ip);
}


void display_tcp_header(display_ctx_t *ctx, const struct tcphdr *tcp) {
    FILE *out = ctx->output;
    
    set_color(ctx, COLOR_GREEN);
    fprintf(out, "TCP Header:\n");
    reset_color(ctx);
    fprintf(out, "  Source Port: %u\n", ntohs(tcp->source));
    fprintf(out, "  Dest Port: %u\n", ntohs(tcp->dest));
    fprintf(out, "  Sequence Number: %u\n", ntohl(tcp->seq));
    fprintf(out, "  Ack Number: %u\n", ntohl(tcp->ack_seq));
    fprintf(out, "  Header Length: %u bytes\n", tcp->doff * 4);
    
    tcp_flags_t flags;
    get_tcp_flags(tcp, &flags);
    fprintf(out, "  Flags: ");
    if (flags.fin) fprintf(out, "FIN ");
    if (flags.syn) fprintf(out, "SYN ");
    if (flags.rst) fprintf(out, "RST ");
    if (flags.psh) fprintf(out, "PSH ");
    if (flags.ack) fprintf(out, "ACK ");
    if (flags.urg) fprintf(out, "URG ");
    fprintf(out, "\n");
    
    fprintf(out, "  Window: %u\n", ntohs(tcp->window));
    fprintf(out, "  Checksum: 0x%04x\n", ntohs(tcp->check));
    fprintf(out, "  Urgent Pointer: %u\n", ntohs(tcp->urg_ptr));
}

void display_udp_header(display_ctx_t *ctx, const struct udphdr *udp) {
    FILE *out = ctx->output;
    
    set_color(ctx, COLOR_GREEN);
    fprintf(out, "UDP Header:\n");
    reset_color(ctx);
    fprintf(out, "  Source Port: %u\n", ntohs(udp->source));
    fprintf(out, "  Dest Port: %u\n", ntohs(udp->dest));
    fprintf(out, "  Length: %u\n", ntohs(udp->len));
    fprintf(out, "  Checksum: 0x%04x\n", ntohs(udp->check));
}

void display_icmp_header(display_ctx_t *ctx, const struct icmphdr *icmp) {
    FILE *out = ctx->output;
    
    set_color(ctx, COLOR_GREEN);
    fprintf(out, "ICMP Header:\n");
    reset_color(ctx);
    fprintf(out, "  Type: %u (%s)\n", icmp->type, icmp_type_to_string(icmp->type));
    fprintf(out, "  Code: %u (%s)\n", icmp->code, icmp_code_to_string(icmp->type, icmp->code));
    fprintf(out, "  Checksum: 0x%04x\n", ntohs(icmp->checksum));
}

void display_icmpv6_header(display_ctx_t *ctx, const struct icmp6_hdr *icmp6) {
    FILE *out = ctx->output;
    
    set_color(ctx, COLOR_GREEN);
    fprintf(out, "ICMPv6 Header:\n");
    reset_color(ctx);
    fprintf(out, "  Type: %u (%s)\n", icmp6->icmp6_type, 
            icmpv6_type_to_string(icmp6->icmp6_type));
    fprintf(out, "  Code: %u (%s)\n", icmp6->icmp6_code,
            icmpv6_code_to_string(icmp6->icmp6_type, icmp6->icmp6_code));
    fprintf(out, "  Checksum: 0x%04x\n", ntohs(icmp6->icmp6_cksum));
}

void display_hex_dump(display_ctx_t *ctx, const uint8_t *data, size_t len, size_t offset) {
    FILE *out = ctx->output;
    
    for (size_t i = 0; i < len; i += 16) {
        // Offset
        fprintf(out, "%08zx  ", offset + i);
        
        // Hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                fprintf(out, "%02x ", data[i + j]);
            } else {
                fprintf(out, "   ");
            }
            
            if (j == 7) fprintf(out, " ");
        }
        
        fprintf(out, " |");
        
        // ASCII representation
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = data[i + j];
            fprintf(out, "%c", (c >= 32 && c <= 126) ? c : '.');
        }
        
        fprintf(out, "|\n");
    }
}

void display_ascii_dump(display_ctx_t *ctx, const uint8_t *data, size_t len) {
    FILE *out = ctx->output;
    size_t display_len = (len > 256) ? 256 : len; // Limit to first 256 bytes
    
    for (size_t i = 0; i < display_len; i++) {
        unsigned char c = data[i];
        if (c >= 32 && c <= 126) {
            fprintf(out, "%c", c);
        } else if (c == '\n') {
            fprintf(out, "\n");
        } else if (c == '\r') {
            // Skip
        } else if (c == '\t') {
            fprintf(out, "\t");
        } else {
            fprintf(out, ".");
        }
    }
    
    if (len > display_len) {
        fprintf(out, "\n... (%zu more bytes)\n", len - display_len);
    } else {
        fprintf(out, "\n");
    }
}

void display_packet_hex(display_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num) {
    FILE *out = ctx->output;
    
    set_color(ctx, COLOR_YELLOW);
    fprintf(out, "\nHex Dump of Packet #%lu:\n", pkt_num);
    reset_color(ctx);
    
    display_hex_dump(ctx, pkt->raw_data, pkt->length, 0);
}