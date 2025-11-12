#include <stdio.h>
#ifndef BUFFER_H
#define BUFFER_H

#include "packet.h"

typedef struct {
    packet_t **packets;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
} ring_buffer_t;

ring_buffer_t* ring_buffer_create(size_t capacity);
void ring_buffer_destroy(ring_buffer_t *rb);
int ring_buffer_push(ring_buffer_t *rb, packet_t *pkt);
packet_t* ring_buffer_pop(ring_buffer_t *rb);
int ring_buffer_is_empty(ring_buffer_t *rb);
int ring_buffer_is_full(ring_buffer_t *rb);

#endif