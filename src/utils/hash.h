#ifndef HASH_H
#define HASH_H

#include "common.h"

typedef struct hash_node {
    void *key;
    size_t key_len;
    void *value;
    struct hash_node *next;
} hash_node_t;

typedef struct {
    hash_node_t **buckets;
    size_t size;
    size_t count;
} hash_table_t;

hash_table_t* hash_table_create(size_t size);
void hash_table_destroy(hash_table_t *ht);
int hash_table_insert(hash_table_t *ht, const void *key, size_t key_len, void *value);
void* hash_table_lookup(hash_table_t *ht, const void *key, size_t key_len);
void hash_table_remove(hash_table_t *ht, const void *key, size_t key_len);

#endif