#include "hash.h"
// DJB2 hash function
static uint32_t hash_function(const void *key, size_t len) {
    const uint8_t *data = (const uint8_t*)key;
    uint32_t hash = 5381;
    
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    
    return hash;
}

hash_table_t* hash_table_create(size_t size) {
    hash_table_t *ht = (hash_table_t*)malloc(sizeof(hash_table_t));
    if (!ht) return NULL;
    
    ht->buckets = (hash_node_t**)calloc(size, sizeof(hash_node_t*));
    if (!ht->buckets) {
        free(ht);
        return NULL;
    }
    
    ht->size = size;
    ht->count = 0;
    
    return ht;
}

void hash_table_destroy(hash_table_t *ht) {
    if (!ht) return;
    
    for (size_t i = 0; i < ht->size; i++) {
        hash_node_t *node = ht->buckets[i];
        while (node) {
            hash_node_t *next = node->next;
            free(node->key);
            free(node);
            node = next;
        }
    }
    
    free(ht->buckets);
    free(ht);
}

int hash_table_insert(hash_table_t *ht, const void *key, size_t key_len, void *value) {
    uint32_t index = hash_function(key, key_len) % ht->size;
    
    hash_node_t *node = (hash_node_t*)malloc(sizeof(hash_node_t));
    if (!node) return ERROR;
    
    node->key = malloc(key_len);
    if (!node->key) {
        free(node);
        return ERROR;
    }
    
    memcpy(node->key, key, key_len);
    node->key_len = key_len;
    node->value = value;
    node->next = ht->buckets[index];
    ht->buckets[index] = node;
    ht->count++;
    
    return SUCCESS;
}

void* hash_table_lookup(hash_table_t *ht, const void *key, size_t key_len) {
    uint32_t index = hash_function(key, key_len) % ht->size;
    hash_node_t *node = ht->buckets[index];
    
    while (node) {
        if (node->key_len == key_len && memcmp(node->key, key, key_len) == 0) {
            return node->value;
        }
        node = node->next;
    }
    
    return NULL;
}

void hash_table_remove(hash_table_t *ht, const void *key, size_t key_len) {
    uint32_t index = hash_function(key, key_len) % ht->size;
    hash_node_t *node = ht->buckets[index];
    hash_node_t *prev = NULL;
    
    while (node) {
        if (node->key_len == key_len && memcmp(node->key, key, key_len) == 0) {
            if (prev) {
                prev->next = node->next;
            } else {
                ht->buckets[index] = node->next;
            }
            free(node->key);
            free(node);
            ht->count--;
            return;
        }
        prev = node;
        node = node->next;
    }
}