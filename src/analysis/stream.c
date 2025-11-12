#include "stream.h"
#include <string.h>
#include <arpa/inet.h>

// Create stream key
static void make_stream_key(const packet_t *pkt, uint8_t *key, size_t *key_len) {
    if (!pkt->ip_hdr || !pkt->tcp_hdr) {
        *key_len = 0;
        return;
    }
    
    size_t offset = 0;
    uint32_t src_ip = pkt->ip_hdr->saddr;
    uint32_t dst_ip = pkt->ip_hdr->daddr;
    uint16_t src_port = pkt->tcp_hdr->source;
    uint16_t dst_port = pkt->tcp_hdr->dest;
    
    memcpy(key + offset, &src_ip, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(key + offset, &dst_ip, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(key + offset, &src_port, sizeof(uint16_t)); offset += sizeof(uint16_t);
    memcpy(key + offset, &dst_port, sizeof(uint16_t)); offset += sizeof(uint16_t);
    
    *key_len = offset;
}

stream_tracker_t* stream_tracker_init(void) {
    stream_tracker_t *tracker = (stream_tracker_t*)calloc(1, sizeof(stream_tracker_t));
    if (!tracker) {
        perror("calloc");
        return NULL;
    }
    
    tracker->streams = hash_table_create(16384);
    if (!tracker->streams) {
        free(tracker);
        return NULL;
    }
    
    return tracker;
}

void stream_tracker_cleanup(stream_tracker_t *tracker) {
    if (!tracker) return;
    
    if (tracker->streams) {
        hash_table_destroy(tracker->streams);
    }
    
    free(tracker);
}

void stream_tracker_set_callback(stream_tracker_t *tracker,
                                 void (*callback)(tcp_stream_t*, stream_direction_t,
                                                 const uint8_t*, size_t, void*),
                                 void *user_data) {
    if (tracker) {
        tracker->data_callback = callback;
        tracker->user_data = user_data;
    }
}

tcp_stream_t* stream_tracker_get_stream(stream_tracker_t *tracker, const packet_t *pkt) {
    if (!tracker || !pkt || !pkt->tcp_hdr) return NULL;
    
    uint8_t key[32];
    size_t key_len;
    make_stream_key(pkt, key, &key_len);
    
    if (key_len == 0) return NULL;
    
    tcp_stream_t *stream = (tcp_stream_t*)hash_table_lookup(tracker->streams, key, key_len);
    
    if (!stream) {
        // Try reverse direction
        uint8_t rev_key[32];
        size_t offset = 0;
        uint32_t dst_ip = pkt->ip_hdr->daddr;
        uint32_t src_ip = pkt->ip_hdr->saddr;
        uint16_t dst_port = pkt->tcp_hdr->dest;uint16_t src_port = pkt->tcp_hdr->source;
        
        memcpy(rev_key + offset, &dst_ip, sizeof(uint32_t)); offset += sizeof(uint32_t);
        memcpy(rev_key + offset, &src_ip, sizeof(uint32_t)); offset += sizeof(uint32_t);
        memcpy(rev_key + offset, &dst_port, sizeof(uint16_t)); offset += sizeof(uint16_t);
        memcpy(rev_key + offset, &src_port, sizeof(uint16_t)); offset += sizeof(uint16_t);
        
        stream = (tcp_stream_t*)hash_table_lookup(tracker->streams, rev_key, offset);
    }
    
    if (!stream && pkt->tcp_hdr->syn) {
        // New stream
        stream = tcp_stream_create(pkt);
        if (stream) {
            hash_table_insert(tracker->streams, key, key_len, stream);
            tracker->total_streams++;
            tracker->active_streams++;
        }
    }
    
    return stream;
}

void stream_tracker_process_packet(stream_tracker_t *tracker, const packet_t *pkt) {
    if (!tracker || !pkt || !pkt->tcp_hdr) return;
    
    tcp_stream_t *stream = stream_tracker_get_stream(tracker, pkt);
    if (!stream) return;
    
    // Determine direction
    stream_direction_t dir;
    if (pkt->ip_hdr->saddr == stream->src_ip && 
        pkt->tcp_hdr->source == stream->src_port) {
        dir = STREAM_DIR_FORWARD;
    } else {
        dir = STREAM_DIR_REVERSE;
    }
    
    // Add packet to stream
    tcp_stream_add_packet(stream, pkt, dir);
    
    // Try to reassemble data
    if (tracker->data_callback) {
        tcp_stream_reassemble(stream, dir, tracker->data_callback, tracker->user_data);
    }
}

tcp_stream_t* tcp_stream_create(const packet_t *pkt) {
    if (!pkt || !pkt->ip_hdr || !pkt->tcp_hdr) return NULL;
    
    tcp_stream_t *stream = (tcp_stream_t*)calloc(1, sizeof(tcp_stream_t));
    if (!stream) {
        perror("calloc");
        return NULL;
    }
    
    stream->src_ip = pkt->ip_hdr->saddr;
    stream->dst_ip = pkt->ip_hdr->daddr;
    stream->src_port = pkt->tcp_hdr->source;
    stream->dst_port = pkt->tcp_hdr->dest;
    
    stream->state = STREAM_STATE_CLOSED;
    
    if (pkt->tcp_hdr->syn) {
        stream->isn_forward = ntohl(pkt->tcp_hdr->seq);
        stream->next_seq_forward = stream->isn_forward + 1;
        stream->state = STREAM_STATE_SYN_SENT;
        stream->seen_syn = 1;
    }
    
    gettimeofday(&stream->first_seen, NULL);
    stream->last_seen = stream->first_seen;
    
    return stream;
}

void tcp_stream_destroy(tcp_stream_t *stream) {
    if (!stream) return;
    
    // Free forward segments
    segment_t *seg = stream->segments_forward;
    while (seg) {
        segment_t *next = seg->next;
        if (seg->data) free(seg->data);
        free(seg);
        seg = next;
    }
    
    // Free reverse segments
    seg = stream->segments_reverse;
    while (seg) {
        segment_t *next = seg->next;
        if (seg->data) free(seg->data);
        free(seg);
        seg = next;
    }
    
    free(stream);
}

void tcp_stream_add_packet(tcp_stream_t *stream, const packet_t *pkt, stream_direction_t dir) {
    if (!stream || !pkt || !pkt->tcp_hdr) return;
    
    gettimeofday(&stream->last_seen, NULL);
    
    // Update state based on flags
    if (pkt->tcp_hdr->syn) {
        stream->seen_syn = 1;
        if (dir == STREAM_DIR_FORWARD) {
            stream->isn_forward = ntohl(pkt->tcp_hdr->seq);
            stream->next_seq_forward = stream->isn_forward + 1;
            stream->state = STREAM_STATE_SYN_SENT;
        } else {
            stream->isn_reverse = ntohl(pkt->tcp_hdr->seq);
            stream->next_seq_reverse = stream->isn_reverse + 1;
            if (pkt->tcp_hdr->ack) {
                stream->state = STREAM_STATE_SYN_RECEIVED;
            }
        }
    }
    
    if (pkt->tcp_hdr->ack && stream->state == STREAM_STATE_SYN_RECEIVED) {
        stream->state = STREAM_STATE_ESTABLISHED;
    }
    
    if (pkt->tcp_hdr->fin) {
        stream->seen_fin = 1;
        if (stream->state == STREAM_STATE_ESTABLISHED) {
            stream->state = STREAM_STATE_FIN_WAIT;
        }
    }
    
    if (pkt->tcp_hdr->rst) {
        stream->seen_rst = 1;
        stream->state = STREAM_STATE_CLOSED;
    }
    
    // Update counters
    if (dir == STREAM_DIR_FORWARD) {
        stream->packets_forward++;
        stream->bytes_forward += pkt->length;
    } else {
        stream->packets_reverse++;
        stream->bytes_reverse += pkt->length;
    }
    
    // Add payload segment if exists
    if (pkt->payload && pkt->payload_len > 0) {
        segment_t *seg = (segment_t*)malloc(sizeof(segment_t));
        if (!seg) return;
        
        seg->seq = ntohl(pkt->tcp_hdr->seq);
        seg->len = pkt->payload_len;
        seg->data = (uint8_t*)malloc(pkt->payload_len);
        if (!seg->data) {
            free(seg);
            return;
        }
        
        memcpy(seg->data, pkt->payload, pkt->payload_len);
        seg->timestamp = pkt->timestamp;
        seg->next = NULL;
        
        // Add to appropriate list
        segment_t **list = (dir == STREAM_DIR_FORWARD) ? 
                          &stream->segments_forward : &stream->segments_reverse;
        
        // Insert in order by sequence number
        if (!*list || seg->seq < (*list)->seq) {
            seg->next = *list;
            *list = seg;
        } else {
            segment_t *curr = *list;
            while (curr->next && curr->next->seq < seg->seq) {
                curr = curr->next;
            }
            seg->next = curr->next;
            curr->next = seg;
        }
    }
}

void tcp_stream_reassemble(tcp_stream_t *stream, stream_direction_t dir,
                          void (*callback)(tcp_stream_t*, stream_direction_t,
                                          const uint8_t*, size_t, void*),
                          void *user_data) {
    if (!stream || !callback) return;
    
    segment_t **list = (dir == STREAM_DIR_FORWARD) ? 
                      &stream->segments_forward : &stream->segments_reverse;
    uint32_t *next_seq = (dir == STREAM_DIR_FORWARD) ?
                        &stream->next_seq_forward : &stream->next_seq_reverse;
    
    // Process contiguous segments
    while (*list && (*list)->seq <= *next_seq) {
        segment_t *seg = *list;
        
        // Skip if we've already seen this data
        if (seg->seq + seg->len <= *next_seq) {
            *list = seg->next;
            if (seg->data) free(seg->data);
            free(seg);
            continue;
        }
        
        // Calculate how much new data we have
        uint32_t offset = 0;
        uint32_t len = seg->len;
        
        if (seg->seq < *next_seq) {
            offset = *next_seq - seg->seq;
            len -= offset;
        }
        
        if (len > 0) {
            // Call callback with reassembled data
            callback(stream, dir, seg->data + offset, len, user_data);
            *next_seq = seg->seq + seg->len;
        }
        
        // Remove segment
        *list = seg->next;
        if (seg->data) free(seg->data);
        free(seg);
    }
}

const char* stream_state_to_string(stream_state_t state) {
    switch (state) {
        case STREAM_STATE_CLOSED: return "CLOSED";
        case STREAM_STATE_SYN_SENT: return "SYN_SENT";
        case STREAM_STATE_SYN_RECEIVED: return "SYN_RECEIVED";
        case STREAM_STATE_ESTABLISHED: return "ESTABLISHED";
        case STREAM_STATE_FIN_WAIT: return "FIN_WAIT";
        case STREAM_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case STREAM_STATE_CLOSING: return "CLOSING";
        case STREAM_STATE_TIME_WAIT: return "TIME_WAIT";
        default: return "UNKNOWN";
    }
}

void stream_print_info(tcp_stream_t *stream, FILE *output) {
    if (!stream || !output) return;
    
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr addr;
    
    addr.s_addr = stream->src_ip;
    inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip));
    addr.s_addr = stream->dst_ip;
    inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));
    
    fprintf(output, "Stream: %s:%u -> %s:%u\n",
            src_ip, ntohs(stream->src_port),
            dst_ip, ntohs(stream->dst_port));
    fprintf(output, "  State: %s\n", stream_state_to_string(stream->state));
    fprintf(output, "  Forward: %lu packets, %lu bytes\n",
            stream->packets_forward, stream->bytes_forward);
    fprintf(output, "  Reverse: %lu packets, %lu bytes\n",
            stream->packets_reverse, stream->bytes_reverse);
    
    double duration = (stream->last_seen.tv_sec - stream->first_seen.tv_sec) +
                     (stream->last_seen.tv_usec - stream->first_seen.tv_usec) / 1000000.0;
    fprintf(output, "  Duration: %.3f seconds\n", duration);
}