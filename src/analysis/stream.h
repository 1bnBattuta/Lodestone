#ifndef STREAM_H
#define STREAM_H

#include <stdio.h>
#include "../utils/common.h"
#include "../utils/packet.h"
#include "../utils/hash.h"

// TCP stream state
typedef enum {
    STREAM_STATE_CLOSED,
    STREAM_STATE_SYN_SENT,
    STREAM_STATE_SYN_RECEIVED,
    STREAM_STATE_ESTABLISHED,
    STREAM_STATE_FIN_WAIT,
    STREAM_STATE_CLOSE_WAIT,
    STREAM_STATE_CLOSING,
    STREAM_STATE_TIME_WAIT
} stream_state_t;

// Stream direction
typedef enum {
    STREAM_DIR_FORWARD,
    STREAM_DIR_REVERSE
} stream_direction_t;

// Data segment
typedef struct segment {
    uint32_t seq;
    uint32_t len;
    uint8_t *data;
    struct timeval timestamp;
    struct segment *next;
} segment_t;

// TCP stream
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    
    stream_state_t state;
    
    // Sequence tracking
    uint32_t isn_forward;      // Initial sequence number (client->server)
    uint32_t isn_reverse;      // Initial sequence number (server->client)
    uint32_t next_seq_forward;
    uint32_t next_seq_reverse;
    
    // Data buffers
    segment_t *segments_forward;
    segment_t *segments_reverse;
    
    uint64_t bytes_forward;
    uint64_t bytes_reverse;
    uint64_t packets_forward;
    uint64_t packets_reverse;
    
    // Timestamps
    struct timeval first_seen;
    struct timeval last_seen;
    
    // Flags
    uint8_t seen_syn:1;
    uint8_t seen_fin:1;
    uint8_t seen_rst:1;
} tcp_stream_t;

typedef struct {
    hash_table_t *streams;
    uint64_t total_streams;
    uint64_t active_streams;
    
    // Callbacks for reassembled data
    void (*data_callback)(tcp_stream_t *stream, stream_direction_t dir, 
                         const uint8_t *data, size_t len, void *user_data);
    void *user_data;
} stream_tracker_t;

// Stream tracking functions
stream_tracker_t* stream_tracker_init(void);
void stream_tracker_cleanup(stream_tracker_t *tracker);
void stream_tracker_process_packet(stream_tracker_t *tracker, const packet_t *pkt);
tcp_stream_t* stream_tracker_get_stream(stream_tracker_t *tracker, const packet_t *pkt);
void stream_tracker_set_callback(stream_tracker_t *tracker,
                                 void (*callback)(tcp_stream_t*, stream_direction_t,
                                                 const uint8_t*, size_t, void*),
                                 void *user_data);

// Stream operations
tcp_stream_t* tcp_stream_create(const packet_t *pkt);
void tcp_stream_destroy(tcp_stream_t *stream);
void tcp_stream_add_packet(tcp_stream_t *stream, const packet_t *pkt, stream_direction_t dir);
void tcp_stream_reassemble(tcp_stream_t *stream, stream_direction_t dir,
                          void (*callback)(tcp_stream_t*, stream_direction_t,
                                          const uint8_t*, size_t, void*),
                          void *user_data);

// Helper functions
const char* stream_state_to_string(stream_state_t state);
void stream_print_info(tcp_stream_t *stream, FILE *output);

#endif