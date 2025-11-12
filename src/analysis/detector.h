#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdio.h>
#include "../utils/common.h"
#include "../utils/packet.h"
#include "../utils/hash.h"

// Alert types
typedef enum {
    ALERT_PORT_SCAN,
    ALERT_SYN_FLOOD,
    ALERT_ARP_SPOOF,
    ALERT_ICMP_FLOOD,
    ALERT_UDP_FLOOD,
    ALERT_SUSPICIOUS_DNS,
    ALERT_LARGE_PACKET,
    ALERT_MALFORMED_PACKET
} alert_type_t;

// Alert severity
typedef enum {
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL
} alert_severity_t;

// Alert structure
typedef struct {
    alert_type_t type;
    alert_severity_t severity;
    struct timeval timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    char description[256];
} alert_t;

// Port scan tracking
typedef struct {
    uint32_t src_ip;
    hash_table_t *dst_ports;  // Ports contacted
    uint32_t port_count;
    struct timeval first_seen;
    struct timeval last_seen;
} port_scan_tracker_t;

// SYN flood tracking
typedef struct {
    uint32_t dst_ip;
    uint16_t dst_port;
    uint64_t syn_count;
    uint64_t syn_ack_count;
    struct timeval window_start;
} syn_flood_tracker_t;

// Detector context
typedef struct {
    // Tracking structures
    hash_table_t *port_scanners;
    hash_table_t *syn_floods;
    hash_table_t *arp_table;
    
    // Thresholds
    uint32_t port_scan_threshold;      // Ports per time window
    uint32_t syn_flood_threshold;      // SYNs per second
    uint32_t icmp_flood_threshold;     // ICMP per second
    uint32_t udp_flood_threshold;      // UDP per second
    uint32_t time_window;              // Detection window in seconds
    
    // Statistics
    uint64_t total_alerts;
    uint64_t alerts_by_type[8];
    
    // Alert callback
    void (*alert_callback)(const alert_t *alert, void *user_data);
    void *user_data;
} detector_ctx_t;

// Detector functions
detector_ctx_t* detector_init(void);
void detector_cleanup(detector_ctx_t *ctx);
void detector_process_packet(detector_ctx_t *ctx, const packet_t *pkt);
void detector_set_alert_callback(detector_ctx_t *ctx,
                                 void (*callback)(const alert_t*, void*),
                                 void *user_data);

// Detection functions
void detect_port_scan(detector_ctx_t *ctx, const packet_t *pkt);
void detect_syn_flood(detector_ctx_t *ctx, const packet_t *pkt);
void detect_arp_spoof(detector_ctx_t *ctx, const packet_t *pkt);
void detect_icmp_flood(detector_ctx_t *ctx, const packet_t *pkt);
void detect_udp_flood(detector_ctx_t *ctx, const packet_t *pkt);
void detect_malformed(detector_ctx_t *ctx, const packet_t *pkt);

// Alert functions
void detector_raise_alert(detector_ctx_t *ctx, alert_type_t type,
                         alert_severity_t severity, uint32_t src_ip,
                         uint32_t dst_ip, const char *description);
const char* alert_type_to_string(alert_type_t type);
const char* alert_severity_to_string(alert_severity_t severity);
void alert_print(const alert_t *alert, FILE *output);

#endif