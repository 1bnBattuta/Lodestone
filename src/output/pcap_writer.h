#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include "../utils/common.h"
#include "../utils/packet.h"
#include <stdio.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

// PCAP file header structure
//struct pcap_file_header {
//    uint32_t magic;           // 0xa1b2c3d4
//    uint16_t version_major;   // 2
//    uint16_t version_minor;   // 4
//    int32_t thiszone;         // GMT to local correction
//    uint32_t sigfigs;         // Timestamp accuracy
//    uint32_t snaplen;         // Max length of captured packets
//    uint32_t network;         // Data link type (1 = Ethernet)
//} __attribute__((packed));

// PCAP packet header structure
struct pcap_packet_header {
    uint32_t ts_sec;          // Timestamp seconds
    uint32_t ts_usec;         // Timestamp microseconds
    uint32_t incl_len;        // Number of octets saved
    uint32_t orig_len;        // Actual length of packet
} __attribute__((packed));

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_SNAPLEN 65535
#define PCAP_LINKTYPE_ETHERNET 1

typedef struct {
    FILE *file;
    char filename[256];
    uint64_t packets_written;
    uint64_t bytes_written;
} pcap_writer_ctx_t;

// PCAP writer functions
pcap_writer_ctx_t* pcap_writer_open(const char *filename);
void pcap_writer_close(pcap_writer_ctx_t *ctx);
int pcap_writer_write_packet(pcap_writer_ctx_t *ctx, const packet_t *pkt);
int pcap_writer_get_stats(pcap_writer_ctx_t *ctx, uint64_t *packets, uint64_t *bytes);

#endif