#include "buffer.h"

ring_buffer_t* ring_buffer_create(size_t capacity) {
    ring_buffer_t *rb = (ring_buffer_t*)malloc(sizeof(ring_buffer_t));
    if (!rb) return NULL;
    
    rb->packets = (packet_t**)calloc(capacity, sizeof(packet_t*));
    if (!rb->packets) {
        free(rb);
        return NULL;
    }
    
    rb->capacity = capacity;
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
    
    return rb;
}

void ring_buffer_destroy(ring_buffer_t *rb) {
    if (rb) {
        free(rb->packets);
        free(rb);
    }
}

int ring_buffer_push(ring_buffer_t *rb, packet_t *pkt) {
    if (ring_buffer_is_full(rb)) return ERROR;
    
    rb->packets[rb->head] = pkt;
    rb->head = (rb->head + 1) % rb->capacity;
    rb->count++;
    
    return SUCCESS;
}

packet_t* ring_buffer_pop(ring_buffer_t *rb) {
    if (ring_buffer_is_empty(rb)) return NULL;
    
    packet_t *pkt = rb->packets[rb->tail];
    rb->tail = (rb->tail + 1) % rb->capacity;
    rb->count--;
    
    return pkt;
}

int ring_buffer_is_empty(ring_buffer_t *rb) {
    return rb->count == 0;
}

int ring_buffer_is_full(ring_buffer_t *rb) {
    return rb->count == rb->capacity;
}