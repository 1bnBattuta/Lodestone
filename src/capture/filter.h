#ifndef FILTER_H
#define FILTER_H

#include "../utils/common.h"
#include "capture.h"
#include <linux/filter.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

typedef struct {
    struct sock_fprog fprog;         // BPF program
    struct bpf_program compiled;     // Compiled filter
    char *filter_str;                // Original filter string
} filter_ctx_t;

// Filter functions
filter_ctx_t* filter_compile(const char *filter_str, int optimize);
void filter_destroy(filter_ctx_t *filter);
int filter_attach(int sockfd, filter_ctx_t *filter);
int filter_detach(int sockfd);
int filter_test_packet(filter_ctx_t *filter, const uint8_t *data, size_t len);

#endif