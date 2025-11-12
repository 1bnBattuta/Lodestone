#include "mmap_capture.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <poll.h>

mmap_capture_ctx_t* mmap_capture_init(const char *interface) {
    mmap_capture_ctx_t *ctx = (mmap_capture_ctx_t*)malloc(sizeof(mmap_capture_ctx_t));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }
    
    memset(ctx, 0, sizeof(mmap_capture_ctx_t));
    strncpy(ctx->interface, interface, IFNAMSIZ - 1);
    
    // Create packet socket with TPACKET_V3
    ctx->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->sockfd < 0) {
        perror("socket");
        free(ctx);
        return NULL;
    }
    
    // Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(ctx->sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(ctx->sockfd);
        free(ctx);
        return NULL;
    }
    ctx->ifindex = ifr.ifr_ifindex;
    
    // Setup TPACKET_V3
    int version = TPACKET_V3;
    if (setsockopt(ctx->sockfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("setsockopt PACKET_VERSION");
        close(ctx->sockfd);
        free(ctx);
        return NULL;
    }
    
    // Configure ring buffer
    memset(&ctx->req, 0, sizeof(ctx->req));
    ctx->req.tp_block_size = BLOCK_SIZE;
    ctx->req.tp_frame_size = FRAME_SIZE;
    ctx->req.tp_block_nr = BLOCK_COUNT;
    ctx->req.tp_frame_nr = (BLOCK_SIZE * BLOCK_COUNT) / FRAME_SIZE;
    ctx->req.tp_retire_blk_tov = 100; // 100ms timeout
    ctx->req.tp_feature_req_word = 0;
    
    if (setsockopt(ctx->sockfd, SOL_PACKET, PACKET_RX_RING, &ctx->req, sizeof(ctx->req)) < 0) {
        perror("setsockopt PACKET_RX_RING");
        close(ctx->sockfd);
        free(ctx);
        return NULL;
    }
    
    // Memory map the ring buffer
    ctx->ring_size = ctx->req.tp_block_size * ctx->req.tp_block_nr;
    ctx->ring_buffer = mmap(NULL, ctx->ring_size, PROT_READ | PROT_WRITE, 
                            MAP_SHARED | MAP_LOCKED, ctx->sockfd, 0);
    
    if (ctx->ring_buffer == MAP_FAILED) {
        perror("mmap");
        close(ctx->sockfd);
        free(ctx);
        return NULL;
    }
    
    // Bind to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ctx->ifindex;
    
    if (bind(ctx->sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        munmap(ctx->ring_buffer, ctx->ring_size);
        close(ctx->sockfd);
        free(ctx);
        return NULL;
    }
    
    ctx->block_index = 0;
    ctx->running = 1;
    
    return ctx;
}

void mmap_capture_cleanup(mmap_capture_ctx_t *ctx) {
    if (!ctx) return;
    
    ctx->running = 0;
    
    if (ctx->ring_buffer && ctx->ring_buffer != MAP_FAILED) {
        munmap(ctx->ring_buffer, ctx->ring_size);
    }
    
    if (ctx->sockfd >= 0) {
        close(ctx->sockfd);
    }
    
    free(ctx);
}

int mmap_capture_loop(mmap_capture_ctx_t *ctx, void (*callback)(packet_t*, void*), void *user_data) {
    if (!ctx || !callback) return ERROR;
    
    struct pollfd pfd;
    pfd.fd = ctx->sockfd;
    pfd.events = POLLIN;
    
    while (ctx->running) {
        // Get current block
        struct tpacket_block_desc *block = 
            (struct tpacket_block_desc*)((uint8_t*)ctx->ring_buffer + 
                                         ctx->block_index * BLOCK_SIZE);
        
        // Check if block is ready
        if ((block->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            // Block not ready, poll
            poll(&pfd, 1, 100);
            continue;
        }
        
        // Process all packets in this block
        uint32_t num_pkts = block->hdr.bh1.num_pkts;
        struct tpacket3_hdr *pkt_hdr = (struct tpacket3_hdr*)((uint8_t*)block + block->hdr.bh1.offset_to_first_pkt);
        
        for (uint32_t i = 0; i < num_pkts; i++) {
            // Get packet data
            uint8_t *pkt_data = (uint8_t*)pkt_hdr + pkt_hdr->tp_mac;
            uint32_t pkt_len = pkt_hdr->tp_snaplen;
            
            // Create packet structure
            packet_t *pkt = packet_create(MAX_PACKET_SIZE);
            if (pkt) {
                if (packet_parse(pkt, pkt_data, pkt_len) == SUCCESS) {
                    ctx->packets_captured++;
                    callback(pkt, user_data);
                } else {
                    packet_destroy(pkt);
                    ctx->packets_dropped++;
                }
            } else {
                ctx->packets_dropped++;
            }

            // Check if we should stop (callback might have set running to 0)
            if (!ctx->running) {
                // Release block back to kernel before exiting
                block->hdr.bh1.block_status = TP_STATUS_KERNEL;
                return SUCCESS;
            }
            
            // Move to next packet in block
            pkt_hdr = (struct tpacket3_hdr*)((uint8_t*)pkt_hdr + pkt_hdr->tp_next_offset);
        }
        
        // Release block back to kernel
        block->hdr.bh1.block_status = TP_STATUS_KERNEL;
        
        // Move to next block
        ctx->block_index = (ctx->block_index + 1) % ctx->req.tp_block_nr;
    }
    
    return SUCCESS;
}