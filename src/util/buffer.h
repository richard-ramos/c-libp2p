/* src/util/buffer.h — growable byte buffer */
#ifndef LP2P_UTIL_BUFFER_H
#define LP2P_UTIL_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} lp2p_buffer_t;

void   lp2p_buffer_init(lp2p_buffer_t *buf);
void   lp2p_buffer_free(lp2p_buffer_t *buf);
bool   lp2p_buffer_reserve(lp2p_buffer_t *buf, size_t additional);
bool   lp2p_buffer_append(lp2p_buffer_t *buf, const uint8_t *data, size_t len);
bool   lp2p_buffer_append_byte(lp2p_buffer_t *buf, uint8_t byte);
void   lp2p_buffer_reset(lp2p_buffer_t *buf);

#endif /* LP2P_UTIL_BUFFER_H */
