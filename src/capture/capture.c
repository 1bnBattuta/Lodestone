#define __USE_MISC
#include "capture.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>

capture_ctx_t* capture_init(const char *interface, int promiscuous) {
    capture_ctx_t *ctx = (capture_ctx_t*)malloc(sizeof(capture_ctx_t));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }
    
    memset(ctx, 0, sizeof(capture_ctx_t));
    strncpy(ctx->interface, interface, IFNAMSIZ - 1);
    ctx->promiscuous = promiscuous;
    ctx->running = 0;
    
    // Create raw socket - ETH_P_ALL captures all protocols
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
    
    // Bind to specific interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ctx->ifindex;
    
    if (bind(ctx->sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(ctx->sockfd);
        free(ctx);
        return NULL;
    }
    
    // Set promiscuous mode if requested
    if (promiscuous) {
        if (capture_set_promiscuous(ctx, 1) != SUCCESS) {
            fprintf(stderr, "Warning: Failed to set promiscuous mode\n");
        }
    }
    
    // Increase socket buffer size for high traffic
    int buf_size = 16 * 1024 * 1024; // 16MB
    if (setsockopt(ctx->sockfd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
        fprintf(stderr, "Warning: Failed to increase socket buffer size\n");
    }
    
    // Set socket to non-blocking for poll usage
    int flags = 1;
    if (ioctl(ctx->sockfd, FIONBIO, &flags) < 0) {
        perror("ioctl FIONBIO");
        close(ctx->sockfd);
        free(ctx);
        return NULL;
    }
    
    // Create packet queue
    ctx->packet_queue = ring_buffer_create(CAPTURE_BUFFER_SIZE);
    if (!ctx->packet_queue) {
        close(ctx->sockfd);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void capture_cleanup(capture_ctx_t *ctx) {
    if (!ctx) return;
    
    if (ctx->running) {
        capture_stop(ctx);
    }
    
    if (ctx->promiscuous) {
        capture_set_promiscuous(ctx, 0);
    }
    
    if (ctx->sockfd >= 0) {
        close(ctx->sockfd);
    }
    
    if (ctx->packet_queue) {
        ring_buffer_destroy(ctx->packet_queue);
    }
    
    free(ctx);
}

int capture_set_promiscuous(capture_ctx_t *ctx, int enable) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ctx->interface, IFNAMSIZ - 1);
    
    // Get current flags
    if (ioctl(ctx->sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        return ERROR;
    }
    
    // Modify promiscuous flag
    if (enable) {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= ~IFF_PROMISC;
    }
    
    // Set new flags
    if (ioctl(ctx->sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        return ERROR;
    }
    
    return SUCCESS;
}

int capture_start(capture_ctx_t *ctx) {
    if (!ctx || ctx->running) {
        return ERROR;
    }
    
    ctx->running = 1;
    ctx->packets_captured = 0;
    ctx->packets_dropped = 0;
    ctx->bytes_captured = 0;
    
    return SUCCESS;
}

void capture_stop(capture_ctx_t *ctx) {
    if (ctx) {
        ctx->running = 0;
    }
}

int capture_loop(capture_ctx_t *ctx, void (*callback)(packet_t*, void*), void *user_data) {
    if (!ctx || !callback) {
        return ERROR;
    }
    
    struct pollfd pfd;
    pfd.fd = ctx->sockfd;
    pfd.events = POLLIN;
    
    uint8_t buffer[MAX_PACKET_SIZE];
    
    while (ctx->running) {
        // Poll with timeout for clean shutdown
        int ret = poll(&pfd, 1, 100); // 100ms timeout
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            return ERROR;
        }
        
        if (ret == 0) {
            // Timeout, continue to check running flag
            continue;
        }
        
        if (pfd.revents & POLLIN) {
            // Read packet - using recvfrom for timestamp precision
            struct sockaddr_ll saddr;
            socklen_t saddr_len = sizeof(saddr);
            
            ssize_t len = recvfrom(ctx->sockfd, buffer, MAX_PACKET_SIZE, 
                                   MSG_TRUNC, (struct sockaddr*)&saddr, &saddr_len);
            
            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                perror("recvfrom");
                ctx->packets_dropped++;
                continue;
            }
            
            if (len == 0) {
                continue;
            }
            
            // Check for truncated packets
            if (len > MAX_PACKET_SIZE) {
                ctx->packets_dropped++;
                continue;
            }
            
            // Create packet structure
            packet_t *pkt = packet_create(MAX_PACKET_SIZE);
            if (!pkt) {
                ctx->packets_dropped++;
                continue;
            }
            
            // Parse raw data into packet structure
            if (packet_parse(pkt, buffer, len) != SUCCESS) {
                packet_destroy(pkt);
                ctx->packets_dropped++;
                continue;
            }
            
            // Update statistics
            ctx->packets_captured++;
            ctx->bytes_captured += len;
            
            // Call user callback
            callback(pkt, user_data);
            
            // Note: callback is responsible for destroying packet or queuing it
        }
        
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "Socket error in poll\n");
            return ERROR;
        }
    }
    
    return SUCCESS;
}

int capture_get_stats(capture_ctx_t *ctx, uint64_t *captured, uint64_t *dropped, uint64_t *bytes) {
    if (!ctx) return ERROR;
    
    if (captured) *captured = ctx->packets_captured;
    if (dropped) *dropped = ctx->packets_dropped;
    if (bytes) *bytes = ctx->bytes_captured;
    
    return SUCCESS;
}