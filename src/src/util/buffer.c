/* src/util/buffer.c — growable byte buffer */
#include "util/buffer.h"
#include <stdlib.h>
#include <string.h>

void lp2p_buffer_init(lp2p_buffer_t *buf) {
    buf->data = NULL;
    buf->len  = 0;
    buf->cap  = 0;
}

void lp2p_buffer_free(lp2p_buffer_t *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len  = 0;
    buf->cap  = 0;
}

bool lp2p_buffer_reserve(lp2p_buffer_t *buf, size_t additional) {
    size_t needed = buf->len + additional;
    if (needed <= buf->cap)
        return true;
    size_t new_cap = buf->cap ? buf->cap : 64;
    while (new_cap < needed)
        new_cap *= 2;
    uint8_t *p = realloc(buf->data, new_cap);
    if (!p) return false;
    buf->data = p;
    buf->cap  = new_cap;
    return true;
}

bool lp2p_buffer_append(lp2p_buffer_t *buf, const uint8_t *data, size_t len) {
    if (!lp2p_buffer_reserve(buf, len))
        return false;
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return true;
}

bool lp2p_buffer_append_byte(lp2p_buffer_t *buf, uint8_t byte) {
    return lp2p_buffer_append(buf, &byte, 1);
}

void lp2p_buffer_reset(lp2p_buffer_t *buf) {
    buf->len = 0;
}
