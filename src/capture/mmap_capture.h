#ifndef MMAP_CAPTURE_H
#define MMAP_CAPTURE_H

#include "../utils/common.h"
#include "../utils/packet.h"
#include "capture.h"
#include <linux/if_packet.h>
#include <net/if.h>

#define BLOCK_SIZE (1024 * 1024 * 4)  // 4MB blocks
#define FRAME_SIZE 2048                // 2KB per frame
#define BLOCK_COUNT 64                 // Total ring buffer size

typedef struct {
    int sockfd;
    char interface[IFNAMSIZ];
    int ifindex;
    
    // Memory mapped ring buffer
    void *ring_buffer;
    size_t ring_size;
    struct tpacket_req3 req;
    
    // Current position
    unsigned int block_index;
    
    // Stats
    uint64_t packets_captured;
    uint64_t packets_dropped;
    
    int running;
} mmap_capture_ctx_t;

mmap_capture_ctx_t* mmap_capture_init(const char *interface);
void mmap_capture_cleanup(mmap_capture_ctx_t *ctx);
int mmap_capture_loop(mmap_capture_ctx_t *ctx, void (*callback)(packet_t*, void*), void *user_data);

#endif