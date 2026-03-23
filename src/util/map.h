/* src/util/map.h — simple hash map (string keys, void* values) */
#ifndef LP2P_UTIL_MAP_H
#define LP2P_UTIL_MAP_H

#include <stddef.h>
#include <stdbool.h>

typedef struct lp2p_map_entry {
    char                   *key;
    void                   *value;
    struct lp2p_map_entry  *next;
} lp2p_map_entry_t;

typedef struct {
    lp2p_map_entry_t **buckets;
    size_t             bucket_count;
    size_t             count;
} lp2p_map_t;

bool  lp2p_map_init(lp2p_map_t *map, size_t initial_buckets);
void  lp2p_map_free(lp2p_map_t *map);
bool  lp2p_map_set(lp2p_map_t *map, const char *key, void *value);
void *lp2p_map_get(const lp2p_map_t *map, const char *key);
bool  lp2p_map_del(lp2p_map_t *map, const char *key);

#endif /* LP2P_UTIL_MAP_H */
