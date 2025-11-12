#include "filter.h"
#include <stdio.h>
#include <string.h>

filter_ctx_t* filter_compile(const char *filter_str, int optimize) {
    if (!filter_str || strlen(filter_str) == 0) {
        return NULL; // No filter means accept all
    }
    
    filter_ctx_t *filter = (filter_ctx_t*)malloc(sizeof(filter_ctx_t));
    if (!filter) {
        perror("malloc");
        return NULL;
    }
    
    memset(filter, 0, sizeof(filter_ctx_t));
    
    filter->filter_str = strdup(filter_str);
    if (!filter->filter_str) {
        free(filter);
        return NULL;
    }
    
    // Use libpcap to compile BPF filter
    // DLT_EN10MB = Ethernet frames
    if (pcap_compile_nopcap(MAX_PACKET_SIZE, DLT_EN10MB, 
                            &filter->compiled, filter_str, optimize, 0) < 0) {
        fprintf(stderr, "Failed to compile filter: %s\n", filter_str);
        free(filter->filter_str);
        free(filter);
        return NULL;
    }
    
    // Convert to kernel format
    filter->fprog.len = filter->compiled.bf_len;
    filter->fprog.filter = (struct sock_filter*)filter->compiled.bf_insns;
    
    return filter;
}

void filter_destroy(filter_ctx_t *filter) {
    if (!filter) return;
    
    if (filter->filter_str) {
        free(filter->filter_str);
    }
    
    pcap_freecode(&filter->compiled);
    free(filter);
}

int filter_attach(int sockfd, filter_ctx_t *filter) {
    if (sockfd < 0) return ERROR;
    
    if (!filter) {
        // No filter = accept all, detach any existing filter
        return filter_detach(sockfd);
    }
    
    // Attach BPF program to socket
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, 
                   &filter->fprog, sizeof(filter->fprog)) < 0) {
        perror("setsockopt SO_ATTACH_FILTER");
        return ERROR;
    }
    
    return SUCCESS;
}

int filter_detach(int sockfd) {
    if (sockfd < 0) return ERROR;
    
    int val = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val)) < 0) {
        perror("setsockopt SO_DETACH_FILTER");
        return ERROR;
    }
    
    return SUCCESS;
}

int filter_test_packet(filter_ctx_t *filter, const uint8_t *data, size_t len) {
    if (!filter) {
        return 1; // No filter = accept all
    }
    
    // Use libpcap's BPF filter function
    if (bpf_filter(filter->compiled.bf_insns, (u_char*)data, len, len) > 0) {
        return 1; // Packet matches filter
    }
    
    return 0; // Packet doesn't match
}