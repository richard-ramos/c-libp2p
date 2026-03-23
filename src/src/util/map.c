/* src/util/map.c — simple hash map (string keys, void* values) */
#define _POSIX_C_SOURCE 200809L
#include "util/map.h"
#include <stdlib.h>
#include <string.h>

static size_t map_hash(const char *key, size_t bucket_count) {
    size_t h = 5381;
    for (const char *p = key; *p; p++)
        h = ((h << 5) + h) ^ (unsigned char)*p;
    return h % bucket_count;
}

bool lp2p_map_init(lp2p_map_t *map, size_t initial_buckets) {
    if (initial_buckets == 0)
        initial_buckets = 16;
    map->buckets = calloc(initial_buckets, sizeof(lp2p_map_entry_t *));
    if (!map->buckets) return false;
    map->bucket_count = initial_buckets;
    map->count = 0;
    return true;
}

void lp2p_map_free(lp2p_map_t *map) {
    if (!map->buckets) return;
    for (size_t i = 0; i < map->bucket_count; i++) {
        lp2p_map_entry_t *e = map->buckets[i];
        while (e) {
            lp2p_map_entry_t *next = e->next;
            free(e->key);
            free(e);
            e = next;
        }
    }
    free(map->buckets);
    map->buckets = NULL;
    map->count = 0;
}

bool lp2p_map_set(lp2p_map_t *map, const char *key, void *value) {
    size_t idx = map_hash(key, map->bucket_count);
    for (lp2p_map_entry_t *e = map->buckets[idx]; e; e = e->next) {
        if (strcmp(e->key, key) == 0) {
            e->value = value;
            return true;
        }
    }
    lp2p_map_entry_t *e = malloc(sizeof(*e));
    if (!e) return false;
    e->key = strdup(key);
    if (!e->key) { free(e); return false; }
    e->value = value;
    e->next  = map->buckets[idx];
    map->buckets[idx] = e;
    map->count++;
    return true;
}

void *lp2p_map_get(const lp2p_map_t *map, const char *key) {
    size_t idx = map_hash(key, map->bucket_count);
    for (lp2p_map_entry_t *e = map->buckets[idx]; e; e = e->next) {
        if (strcmp(e->key, key) == 0)
            return e->value;
    }
    return NULL;
}

bool lp2p_map_del(lp2p_map_t *map, const char *key) {
    size_t idx = map_hash(key, map->bucket_count);
    lp2p_map_entry_t **pp = &map->buckets[idx];
    while (*pp) {
        if (strcmp((*pp)->key, key) == 0) {
            lp2p_map_entry_t *e = *pp;
            *pp = e->next;
            free(e->key);
            free(e);
            map->count--;
            return true;
        }
        pp = &(*pp)->next;
    }
    return false;
}
