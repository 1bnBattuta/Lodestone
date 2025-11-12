#include "pcap_writer.h"
#include <string.h>

pcap_writer_ctx_t* pcap_writer_open(const char *filename) {
    if (!filename) return NULL;
    
    pcap_writer_ctx_t *ctx = (pcap_writer_ctx_t*)malloc(sizeof(pcap_writer_ctx_t));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }
    
    memset(ctx, 0, sizeof(pcap_writer_ctx_t));
    strncpy(ctx->filename, filename, sizeof(ctx->filename) - 1);
    
    // Open file for writing
    ctx->file = fopen(filename, "wb");
    if (!ctx->file) {
        perror("fopen");
        free(ctx);
        return NULL;
    }
    
    // Write PCAP file header
    struct pcap_file_header file_hdr;
    file_hdr.magic = PCAP_MAGIC;
    file_hdr.version_major = PCAP_VERSION_MAJOR;
    file_hdr.version_minor = PCAP_VERSION_MINOR;
    file_hdr.thiszone = 0;
    file_hdr.sigfigs = 0;
    file_hdr.snaplen = PCAP_SNAPLEN;
    file_hdr.linktype = PCAP_LINKTYPE_ETHERNET;
    
    if (fwrite(&file_hdr, sizeof(file_hdr), 1, ctx->file) != 1) {
        perror("fwrite");
        fclose(ctx->file);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void pcap_writer_close(pcap_writer_ctx_t *ctx) {
    if (!ctx) return;
    
    if (ctx->file) {
        fflush(ctx->file);
        fclose(ctx->file);
    }
    
    free(ctx);
}

int pcap_writer_write_packet(pcap_writer_ctx_t *ctx, const packet_t *pkt) {
    if (!ctx || !ctx->file || !pkt) {
        return ERROR;
    }
    
    // Write packet header
    struct pcap_packet_header pkt_hdr;
    pkt_hdr.ts_sec = pkt->timestamp.tv_sec;
    pkt_hdr.ts_usec = pkt->timestamp.tv_usec;
    pkt_hdr.incl_len = pkt->length;
    pkt_hdr.orig_len = pkt->length;
    
    if (fwrite(&pkt_hdr, sizeof(pkt_hdr), 1, ctx->file) != 1) {
        perror("fwrite packet header");
        return ERROR;
    }
    
    // Write packet data
    if (fwrite(pkt->raw_data, 1, pkt->length, ctx->file) != pkt->length) {
        perror("fwrite packet data");
        return ERROR;
    }
    
    ctx->packets_written++;
    ctx->bytes_written += pkt->length;
    
    return SUCCESS;
}

int pcap_writer_get_stats(pcap_writer_ctx_t *ctx, uint64_t *packets, uint64_t *bytes) {
    if (!ctx) return ERROR;
    
    if (packets) *packets = ctx->packets_written;
    if (bytes) *bytes = ctx->bytes_written;
    
    return SUCCESS;
}