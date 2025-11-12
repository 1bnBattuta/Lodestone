#include "stats.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

stats_ctx_t* stats_init(void) {
    stats_ctx_t *ctx = (stats_ctx_t*)calloc(1, sizeof(stats_ctx_t));
    if (!ctx) {
        perror("calloc");
        return NULL;
    }
    
    gettimeofday(&ctx->start_time, NULL);
    ctx->last_update = ctx->start_time;
    
    return ctx;
}

void stats_cleanup(stats_ctx_t *ctx) {
    if (!ctx) return;
    
    // Free IP stats
    ip_stats_entry_t *ip_entry = ctx->ip_stats;
    while (ip_entry) {
        ip_stats_entry_t *next = ip_entry->next;
        free(ip_entry);
        ip_entry = next;
    }
    
    // Free port stats
    port_stats_entry_t *port_entry = ctx->port_stats;
    while (port_entry) {
        port_stats_entry_t *next = port_entry->next;
        free(port_entry);
        port_entry = next;
    }
    
    free(ctx);
}

void stats_update(stats_ctx_t *ctx, const packet_t *pkt) {
    if (!ctx || !pkt) return;
    
    protocol_stats_t *ps = &ctx->proto_stats;
    
    // Count by protocol
    if (pkt->eth_hdr) {
        ps->ethernet_packets++;
    }
    
    if (pkt->ip_version == 4 && pkt->ip_hdr) {
        ps->ip_packets++;
        
        // Track source and destination IPs
        stats_add_ip(ctx, pkt->ip_hdr->saddr, pkt->length);
        stats_add_ip(ctx, pkt->ip_hdr->daddr, pkt->length);
    } else if (pkt->ip_version == 6 && pkt->ip6_hdr) {
        ps->ipv6_packets++;
        // IPv6 addresses are too large
        // TODO: Add tracking or maybe not ?
    }
    
    if (pkt->tcp_hdr) {
        ps->tcp_packets++;
        ps->tcp_bytes += pkt->length;
        
        // Track TCP flags
        if (pkt->tcp_hdr->syn) ps->tcp_syn++;
        if (pkt->tcp_hdr->fin) ps->tcp_fin++;
        if (pkt->tcp_hdr->rst) ps->tcp_rst++;
        if (pkt->tcp_hdr->psh) ps->tcp_psh++;
        if (pkt->tcp_hdr->ack) ps->tcp_ack++;
        
        // Track ports
        stats_add_port(ctx, ntohs(pkt->tcp_hdr->source), pkt->length);
        stats_add_port(ctx, ntohs(pkt->tcp_hdr->dest), pkt->length);
    } else if (pkt->udp_hdr) {
        ps->udp_packets++;
        ps->udp_bytes += pkt->length;
        
        // Track ports
        stats_add_port(ctx, ntohs(pkt->udp_hdr->source), pkt->length);
        stats_add_port(ctx, ntohs(pkt->udp_hdr->dest), pkt->length);
    } else if (pkt->icmp_hdr || pkt->icmp6_hdr) {
        ps->icmp_packets++;
    }
    
    ps->total_bytes += pkt->length;
    
    gettimeofday(&ctx->last_update, NULL);
}

void stats_add_ip(stats_ctx_t *ctx, uint32_t ip_addr, size_t bytes) {
    // Find existing entry
    ip_stats_entry_t *entry = ctx->ip_stats;
    while (entry) {
        if (entry->ip_addr == ip_addr) {
            entry->packet_count++;
            entry->byte_count += bytes;
            return;
        }
        entry = entry->next;
    }
    
    // Create new entry
    entry = (ip_stats_entry_t*)malloc(sizeof(ip_stats_entry_t));
    if (!entry) return;
    
    entry->ip_addr = ip_addr;
    entry->packet_count = 1;
    entry->byte_count = bytes;
    entry->next = ctx->ip_stats;
    ctx->ip_stats = entry;
}

void stats_add_port(stats_ctx_t *ctx, uint16_t port, size_t bytes) {
    // Find existing entry
    port_stats_entry_t *entry = ctx->port_stats;
    while (entry) {
        if (entry->port == port) {
            entry->packet_count++;
            entry->byte_count += bytes;
            return;
        }
        entry = entry->next;
    }
    
    // Create new entry
    entry = (port_stats_entry_t*)malloc(sizeof(port_stats_entry_t));
    if (!entry) return;
    
    entry->port = port;
    entry->packet_count = 1;
    entry->byte_count = bytes;
    entry->next = ctx->port_stats;
    ctx->port_stats = entry;
}

void stats_calculate_rates(stats_ctx_t *ctx) {
    if (!ctx) return;
    
    struct timeval now;
    gettimeofday(&now, NULL);
    
    double elapsed = (now.tv_sec - ctx->start_time.tv_sec) +
                    (now.tv_usec - ctx->start_time.tv_usec) / 1000000.0;
    
    if (elapsed > 0) {
        uint64_t total_packets = ctx->proto_stats.tcp_packets +
                                ctx->proto_stats.udp_packets +
                                ctx->proto_stats.icmp_packets +
                                ctx->proto_stats.arp_packets +
                                ctx->proto_stats.other_packets;
        
        ctx->packets_per_sec = total_packets / elapsed;
        ctx->bytes_per_sec = ctx->proto_stats.total_bytes / elapsed;
    }
}

void stats_print_summary(stats_ctx_t *ctx, FILE *output) {
    if (!ctx || !output) return;
    
    protocol_stats_t *ps = &ctx->proto_stats;
    
    stats_calculate_rates(ctx);
    
    fprintf(output, "\n========== Capture Statistics ==========\n");
    fprintf(output, "Total Packets: %lu\n", 
            ps->tcp_packets + ps->udp_packets + ps->icmp_packets + ps->arp_packets + ps->other_packets);
    fprintf(output, "Total Bytes: %lu (%.2f MB)\n", 
            ps->total_bytes, ps->total_bytes / (1024.0 * 1024.0));
    fprintf(output, "\nProtocol Distribution:\n");
    fprintf(output, "  TCP: %lu packets (%.2f MB)\n", ps->tcp_packets, ps->tcp_bytes / (1024.0 * 1024.0));
    fprintf(output, "  UDP: %lu packets (%.2f MB)\n", ps->udp_packets, ps->udp_bytes / (1024.0 * 1024.0));
    fprintf(output, "  ICMP: %lu packets\n", ps->icmp_packets);
    fprintf(output, "  ARP: %lu packets\n", ps->arp_packets);
    fprintf(output, "\nRates:\n");
    fprintf(output, "  %.2f packets/sec\n", ctx->packets_per_sec);
    fprintf(output, "  %.2f KB/sec\n", ctx->bytes_per_sec / 1024.0);
    fprintf(output, "=====================================\n\n");
}

void stats_print_detailed(stats_ctx_t *ctx, FILE *output) {
    if (!ctx || !output) return;
    
    stats_print_summary(ctx, output);
    
    protocol_stats_t *ps = &ctx->proto_stats;
    
    // TCP flags
    if (ps->tcp_packets > 0) {
        fprintf(output, "\nTCP Flags:\n");
        fprintf(output, "  SYN: %lu\n", ps->tcp_syn);
        fprintf(output, "  FIN: %lu\n", ps->tcp_fin);
        fprintf(output, "  RST: %lu\n", ps->tcp_rst);
        fprintf(output, "  PSH: %lu\n", ps->tcp_psh);
        fprintf(output, "  ACK: %lu\n", ps->tcp_ack);
    }
    
    // Top IPs (limit to 10)
    fprintf(output, "\nTop IP Addresses:\n");
    ip_stats_entry_t *ip_entry = ctx->ip_stats;
    int ip_count = 0;
    while (ip_entry && ip_count < 10) {
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = ip_entry->ip_addr;
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        
        fprintf(output, "  %s: %lu packets (%.2f MB)\n",
                ip_str, ip_entry->packet_count,
                ip_entry->byte_count / (1024.0 * 1024.0));
        
        ip_entry = ip_entry->next;
        ip_count++;
    }
    
    // Top ports (limit to 10)
    fprintf(output, "\nTop Ports:\n");
    port_stats_entry_t *port_entry = ctx->port_stats;
    int port_count = 0;
    while (port_entry && port_count < 10) {
        fprintf(output, "  Port %u: %lu packets (%.2f MB)\n",
                port_entry->port, port_entry->packet_count,
                port_entry->byte_count / (1024.0 * 1024.0));
        
        port_entry = port_entry->next;
        port_count++;
    }
    
    fprintf(output, "\n");
}

void stats_print(stats_ctx_t *ctx, FILE *output) {
    stats_print_detailed(ctx, output);
}

void stats_reset(stats_ctx_t *ctx) {
    if (!ctx) return;
    
    memset(&ctx->proto_stats, 0, sizeof(protocol_stats_t));
    
    // Free and reset IP stats
    ip_stats_entry_t *ip_entry = ctx->ip_stats;
    while (ip_entry) {
        ip_stats_entry_t *next = ip_entry->next;
        free(ip_entry);
        ip_entry = next;
    }
    ctx->ip_stats = NULL;
    
    // Free and reset port stats
    port_stats_entry_t *port_entry = ctx->port_stats;
    while (port_entry) {
        port_stats_entry_t *next = port_entry->next;
        free(port_entry);
        port_entry = next;
    }
    ctx->port_stats = NULL;
    
    gettimeofday(&ctx->start_time, NULL);
    ctx->last_update = ctx->start_time;
    ctx->packets_per_sec = 0;
    ctx->bytes_per_sec = 0;
}