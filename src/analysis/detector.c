#include "detector.h"
#include <string.h>
#include <arpa/inet.h>

detector_ctx_t* detector_init(void) {
    detector_ctx_t *ctx = (detector_ctx_t*)calloc(1, sizeof(detector_ctx_t));
    if (!ctx) {
        perror("calloc");
        return NULL;
    }
    
    ctx->port_scanners = hash_table_create(4096);
    ctx->syn_floods = hash_table_create(4096);
    ctx->arp_table = hash_table_create(1024);
    
    if (!ctx->port_scanners || !ctx->syn_floods || !ctx->arp_table) {
        detector_cleanup(ctx);
        return NULL;
    }
    
    // Set default thresholds
    ctx->port_scan_threshold = 20;      // 20 ports in time window
    ctx->syn_flood_threshold = 100;     // 100 SYNs per second
    ctx->icmp_flood_threshold = 50;     // 50 ICMP per second
    ctx->udp_flood_threshold = 100;     // 100 UDP per second
    ctx->time_window = 60;              // 60 seconds
    
    return ctx;
}

void detector_cleanup(detector_ctx_t *ctx) {
    if (!ctx) return;
    
    if (ctx->port_scanners) hash_table_destroy(ctx->port_scanners);
    if (ctx->syn_floods) hash_table_destroy(ctx->syn_floods);
    if (ctx->arp_table) hash_table_destroy(ctx->arp_table);
    
    free(ctx);
}

void detector_set_alert_callback(detector_ctx_t *ctx,
                                 void (*callback)(const alert_t*, void*),
                                 void *user_data) {
    if (ctx) {
        ctx->alert_callback = callback;
        ctx->user_data = user_data;
    }
}

void detector_process_packet(detector_ctx_t *ctx, const packet_t *pkt) {
    if (!ctx || !pkt) return;
    
    // Check for malformed packets
    detect_malformed(ctx, pkt);
    
    if (pkt->tcp_hdr) {
        // Check for port scans
        detect_port_scan(ctx, pkt);
        
        // Check for SYN floods
        if (pkt->tcp_hdr->syn) {
            detect_syn_flood(ctx, pkt);
        }
    } else if (pkt->udp_hdr) {
        // Check for UDP floods
        detect_udp_flood(ctx, pkt);
    } else if (pkt->icmp_hdr) {
        // Check for ICMP floods
        detect_icmp_flood(ctx, pkt);
    }
    
    // Check for ARP spoofing
    if (pkt->eth_hdr && ntohs(pkt->eth_hdr->ether_type) == ETH_TYPE_ARP) {
        detect_arp_spoof(ctx, pkt);
    }
}

void detect_port_scan(detector_ctx_t *ctx, const packet_t *pkt) {
    if (!ctx || !pkt || !pkt->ip_hdr || !pkt->tcp_hdr) return;
    
    // Only detect SYN scans
    if (!pkt->tcp_hdr->syn || pkt->tcp_hdr->ack) return;
    
    uint32_t src_ip = pkt->ip_hdr->saddr;
    uint16_t dst_port = pkt->tcp_hdr->dest;
    
    // Lookup or create tracker
    port_scan_tracker_t *tracker = (port_scan_tracker_t*)hash_table_lookup(
        ctx->port_scanners, &src_ip, sizeof(uint32_t));
    
    if (!tracker) {
        tracker = (port_scan_tracker_t*)calloc(1, sizeof(port_scan_tracker_t));
        if (!tracker) return;
        
        tracker->src_ip = src_ip;
        tracker->dst_ports = hash_table_create(256);
        gettimeofday(&tracker->first_seen, NULL);
        
        hash_table_insert(ctx->port_scanners, &src_ip, sizeof(uint32_t), tracker);
    }
    
    gettimeofday(&tracker->last_seen, NULL);
    
    // Add port if not seen
    if (!hash_table_lookup(tracker->dst_ports, &dst_port, sizeof(uint16_t))) {
        uint16_t *port_copy = (uint16_t*)malloc(sizeof(uint16_t));
        if (port_copy) {
            *port_copy = dst_port;
            hash_table_insert(tracker->dst_ports, &dst_port, sizeof(uint16_t), port_copy);
            tracker->port_count++;
        }
    }
    
    // Check threshold
    double elapsed = (tracker->last_seen.tv_sec - tracker->first_seen.tv_sec);
    if (elapsed < ctx->time_window && tracker->port_count >= ctx->port_scan_threshold) {
        char desc[256];
        snprintf(desc, sizeof(desc), 
                "Port scan detected: %u ports scanned in %.0f seconds",
                tracker->port_count, elapsed);
        
        detector_raise_alert(ctx, ALERT_PORT_SCAN, SEVERITY_HIGH,
                           src_ip, pkt->ip_hdr->daddr, desc);
        
        // Reset counter to avoid repeated alerts
        tracker->port_count = 0;
        gettimeofday(&tracker->first_seen, NULL);
    }
}

void detect_syn_flood(detector_ctx_t *ctx, const packet_t *pkt) {
    if (!ctx || !pkt || !pkt->ip_hdr || !pkt->tcp_hdr) return;
    
    uint32_t dst_ip = pkt->ip_hdr->daddr;
    uint16_t dst_port = pkt->tcp_hdr->dest;
    
    // Create key: IP + Port
    uint8_t key[6];
    memcpy(key, &dst_ip, sizeof(uint32_t));
    memcpy(key + sizeof(uint32_t), &dst_port, sizeof(uint16_t));
    
    syn_flood_tracker_t *tracker = (syn_flood_tracker_t*)hash_table_lookup(
        ctx->syn_floods, key, sizeof(key));
    
    struct timeval now;
    gettimeofday(&now, NULL);
    
    if (!tracker) {
        tracker = (syn_flood_tracker_t*)calloc(1, sizeof(syn_flood_tracker_t));
        if (!tracker) return;
        
        tracker->dst_ip = dst_ip;
        tracker->dst_port = dst_port;
        tracker->window_start = now;
        
        hash_table_insert(ctx->syn_floods, key, sizeof(key), tracker);
    }
    
    // Check if we need to reset window
    double elapsed = (now.tv_sec - tracker->window_start.tv_sec);
    if (elapsed >= 1.0) {
        // Check for flood in last window
        if (tracker->syn_count >= ctx->syn_flood_threshold) {
            char desc[256];
            snprintf(desc, sizeof(desc),
                    "SYN flood detected: %lu SYNs/sec to port %u",
                    tracker->syn_count, ntohs(dst_port));
            
            detector_raise_alert(ctx, ALERT_SYN_FLOOD, SEVERITY_CRITICAL,
                               pkt->ip_hdr->saddr, dst_ip, desc);
        }
        
        // Reset window
        tracker->syn_count = 0;
        tracker->syn_ack_count = 0;
        tracker->window_start = now;
    }
    
    if (pkt->tcp_hdr->syn && !pkt->tcp_hdr->ack) {
        tracker->syn_count++;
    } else if (pkt->tcp_hdr->syn && pkt->tcp_hdr->ack) {
        tracker->syn_ack_count++;
    }
}

void detect_arp_spoof(detector_ctx_t *ctx, const packet_t *pkt) {
    if (!ctx || !pkt || !pkt->payload || pkt->payload_len < 28) return;
    
    // Parse ARP packet
    const uint8_t *arp_data = pkt->payload;
    uint16_t opcode = (arp_data[6] << 8) | arp_data[7];
    
    if (opcode != 2) return; // Only check replies
    
    uint32_t sender_ip;
    uint8_t sender_mac[6];
    
    memcpy(sender_mac, arp_data + 8, 6);
    memcpy(&sender_ip, arp_data + 14, 4);
    
    // Check if we've seen this IP before with different MAC
    uint8_t *stored_mac = (uint8_t*)hash_table_lookup(
        ctx->arp_table, &sender_ip, sizeof(uint32_t));
    
    if (stored_mac) {
        if (memcmp(stored_mac, sender_mac, 6) != 0) {
            char desc[256];
            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr;
            addr.s_addr = sender_ip;
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            
            snprintf(desc, sizeof(desc),
                    "ARP spoofing detected for IP %s: MAC changed",
                    ip_str);
            
            detector_raise_alert(ctx, ALERT_ARP_SPOOF, SEVERITY_HIGH,
                               0, sender_ip, desc);
        }
    } else {
        // Store MAC for this IP
        uint8_t *mac_copy = (uint8_t*)malloc(6);
        if (mac_copy) {
            memcpy(mac_copy, sender_mac, 6);
            hash_table_insert(ctx->arp_table, &sender_ip, sizeof(uint32_t), mac_copy);
        }
    }
}

void detect_icmp_flood(detector_ctx_t *ctx, const packet_t *pkt) {
    // Simplified ICMP flood detection
    // TODO: In production, would track per-destination
    (void)ctx;
    (void)pkt;
}

void detect_udp_flood(detector_ctx_t *ctx, const packet_t *pkt) {
    // Simplified UDP flood detection
    // TODO: In production, would track per-destination
    (void)ctx;
    (void)pkt;
}

void detect_malformed(detector_ctx_t *ctx, const packet_t *pkt) {
    if (!ctx || !pkt) return;
    
    // Check for unusually large packets
    if (pkt->length > 9000) {
        char desc[256];
        snprintf(desc, sizeof(desc), "Abnormally large packet: %zu bytes", pkt->length);
        
        detector_raise_alert(ctx, ALERT_LARGE_PACKET, SEVERITY_LOW,
                           pkt->ip_hdr ? pkt->ip_hdr->saddr : 0,
                           pkt->ip_hdr ? pkt->ip_hdr->daddr : 0,
                           desc);
    }
    
    // TODO: Add more malformed packet checks here
}

void detector_raise_alert(detector_ctx_t *ctx, alert_type_t type,
                         alert_severity_t severity, uint32_t src_ip,
                         uint32_t dst_ip, const char *description) {
    if (!ctx) return;
    
    alert_t alert;
    alert.type = type;
    alert.severity = severity;
    gettimeofday(&alert.timestamp, NULL);
    alert.src_ip = src_ip;
    alert.dst_ip = dst_ip;
    strncpy(alert.description, description, sizeof(alert.description) - 1);
    alert.description[sizeof(alert.description) - 1] = '\0';
    
    ctx->total_alerts++;
    if (type < 8) {
        ctx->alerts_by_type[type]++;
    }
    
    if (ctx->alert_callback) {
        ctx->alert_callback(&alert, ctx->user_data);
    }
}

const char* alert_type_to_string(alert_type_t type) {
    switch (type) {
        case ALERT_PORT_SCAN: return "Port Scan";
        case ALERT_SYN_FLOOD: return "SYN Flood";
        case ALERT_ARP_SPOOF: return "ARP Spoofing";
        case ALERT_ICMP_FLOOD: return "ICMP Flood";
        case ALERT_UDP_FLOOD: return "UDP Flood";
        case ALERT_SUSPICIOUS_DNS: return "Suspicious DNS";
        case ALERT_LARGE_PACKET: return "Large Packet";
        case ALERT_MALFORMED_PACKET: return "Malformed Packet";
        default: return "Unknown";
    }
}

const char* alert_severity_to_string(alert_severity_t severity) {
    switch (severity) {
        case SEVERITY_INFO: return "INFO";
        case SEVERITY_LOW: return "LOW";
        case SEVERITY_MEDIUM: return "MEDIUM";
        case SEVERITY_HIGH: return "HIGH";
        case SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

void alert_print(const alert_t *alert, FILE *output) {
    if (!alert || !output) return;
    
    char timestamp[64];
    time_t sec = alert->timestamp.tv_sec;
    struct tm *tm = localtime(&sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    
    char src_ip[INET_ADDRSTRLEN] = "N/A";
    char dst_ip[INET_ADDRSTRLEN] = "N/A";
    
    if (alert->src_ip) {
        struct in_addr addr;
        addr.s_addr = alert->src_ip;
        inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip));
    }
    
    if (alert->dst_ip) {
        struct in_addr addr;
        addr.s_addr = alert->dst_ip;
        inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));
    }
    
    fprintf(output, "\n[ALERT] %s - %s\n", 
            timestamp, alert_severity_to_string(alert->severity));
    fprintf(output, "Type: %s\n", alert_type_to_string(alert->type));
    fprintf(output, "Source: %s\n", src_ip);
    fprintf(output, "Destination: %s\n", dst_ip);
    fprintf(output, "Description: %s\n", alert->description);
    fprintf(output, "\n");
}