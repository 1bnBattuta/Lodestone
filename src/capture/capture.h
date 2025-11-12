#ifndef CAPTURE_H
#define CAPTURE_H

#define __USE_MISC
#include "../utils/common.h"
#include "../utils/packet.h"
#include "../utils/buffer.h"
#include <net/if.h>

#define MAX_PACKET_SIZE 65535
#define CAPTURE_BUFFER_SIZE 1024

typedef struct {
    int sockfd;                      // Raw socket file descriptor
    char interface[IFNAMSIZ];        // Network interface name
    int ifindex;                     // Interface index
    int promiscuous;                 // Promiscuous mode flag
    int running;                     // Capture state
    ring_buffer_t *packet_queue;     // Queue for captured packets
    
    // Statistics
    uint64_t packets_captured;
    uint64_t packets_dropped;
    uint64_t bytes_captured;
} capture_ctx_t;

// Core functions
capture_ctx_t* capture_init(const char *interface, int promiscuous);
void capture_cleanup(capture_ctx_t *ctx);
int capture_start(capture_ctx_t *ctx);
void capture_stop(capture_ctx_t *ctx);
int capture_loop(capture_ctx_t *ctx, void (*callback)(packet_t*, void*), void *user_data);

// Utility functions
int capture_set_promiscuous(capture_ctx_t *ctx, int enable);
int capture_get_stats(capture_ctx_t *ctx, uint64_t *captured, uint64_t *dropped, uint64_t *bytes);

#endif