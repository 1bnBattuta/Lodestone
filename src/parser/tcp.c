#include "tcp.h"
#include "../utils/checksum.h"
#include <stdio.h>

int parse_tcp(packet_t *pkt, const uint8_t *data, size_t len) {
    if (len < sizeof(struct tcphdr)) {
        return PARSE_TRUNCATED;
    }
    
    // Direct pointer cast
    pkt->tcp_hdr = (struct tcphdr*)data;
    
    // Validate data offset (TCP header length)
    uint8_t tcp_hdr_len = pkt->tcp_hdr->doff * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > len) {
        return PARSE_INVALID;
    }
    
    // Extract payload
    if (len > tcp_hdr_len) {
        pkt->payload = (uint8_t*)(data + tcp_hdr_len);
        pkt->payload_len = len - tcp_hdr_len;
    } else {
        pkt->payload = NULL;
        pkt->payload_len = 0;
    }
    
    // Optional: Validate checksum
    #ifdef VALIDATE_CHECKSUMS
    if (pkt->ip_hdr) {
        if (validate_tcp_checksum(pkt->tcp_hdr, pkt->ip_hdr->saddr, 
                                  pkt->ip_hdr->daddr, len) != SUCCESS) {
            return PARSE_INVALID;
        }
    }
    #endif
    
    return PARSE_SUCCESS;
}

int validate_tcp_checksum(const struct tcphdr *tcp_hdr,
                          uint32_t src_ip, uint32_t dst_ip, size_t len) {
    uint16_t received = tcp_hdr->check;
    
    // Create mutable copy
    uint8_t *temp = (uint8_t*)malloc(len);
    if (!temp) return ERROR;
    
    memcpy(temp, tcp_hdr, len);
    ((struct tcphdr*)temp)->check = 0;
    
    uint16_t calculated = checksum_tcp_udp(temp, len, src_ip, dst_ip, PROTO_TCP);
    free(temp);
    
    return (calculated == received) ? SUCCESS : ERROR;
}

void get_tcp_flags(const struct tcphdr *tcp_hdr, tcp_flags_t *flags) {
    flags->fin = tcp_hdr->fin;
    flags->syn = tcp_hdr->syn;
    flags->rst = tcp_hdr->rst;
    flags->psh = tcp_hdr->psh;
    flags->ack = tcp_hdr->ack;
    flags->urg = tcp_hdr->urg;
}

void format_tcp_flags(const tcp_flags_t *flags, char *buf, size_t buflen) {
    int pos = 0;
    
    if (flags->fin) buf[pos++] = 'F';
    if (flags->syn) buf[pos++] = 'S';
    if (flags->rst) buf[pos++] = 'R';
    if (flags->psh) buf[pos++] = 'P';
    if (flags->ack) buf[pos++] = 'A';
    if (flags->urg) buf[pos++] = 'U';
    
    buf[pos] = '\0';
    
    if (pos == 0) {
        strncpy(buf, "None", buflen);
    }
}

int parse_tcp_options(const struct tcphdr *tcp_hdr, tcp_option_t *options, int max_opts) {
    uint8_t tcp_hdr_len = tcp_hdr->doff * 4;
    if (tcp_hdr_len <= 20) {
        return 0; // No options
    }
    
    const uint8_t *opt_data = (const uint8_t*)tcp_hdr + 20;
    size_t opt_len = tcp_hdr_len - 20;
    int opt_count = 0;
    size_t offset = 0;
    
    while (offset < opt_len && opt_count < max_opts) {
        uint8_t kind = opt_data[offset];
        
        // EOL or NOP
        if (kind == TCP_OPT_EOL) {
            break;
        }
        if (kind == TCP_OPT_NOP) {
            offset++;
            continue;
        }
        
        // Other options have length field
        if (offset + 1 >= opt_len) {
            break; // Truncated
        }
        
        uint8_t length = opt_data[offset + 1];
        if (length < 2 || offset + length > opt_len) {
            break; // Invalid
        }
        
        options[opt_count].kind = kind;
        options[opt_count].length = length;
        options[opt_count].data = (uint8_t*)(opt_data + offset + 2);
        opt_count++;
        
        offset += length;
    }
    
    return opt_count;
}