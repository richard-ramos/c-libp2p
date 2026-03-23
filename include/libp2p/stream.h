#ifndef LIBP2P_STREAM_H
#define LIBP2P_STREAM_H

#include "types.h"
#include "errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Callbacks ────────────────────────────────────────────────────────────── */
typedef void (*lp2p_stream_read_cb)(lp2p_stream_t *stream, lp2p_err_t err,
                                     const lp2p_buf_t *buf, void *userdata);
typedef void (*lp2p_stream_write_cb)(lp2p_stream_t *stream, lp2p_err_t err,
                                      void *userdata);
typedef void (*lp2p_open_stream_cb)(lp2p_stream_t *stream, lp2p_err_t err,
                                     void *userdata);

/* ── Read ─────────────────────────────────────────────────────────────────── */
lp2p_err_t lp2p_stream_read(lp2p_stream_t *stream, size_t max_bytes,
                              lp2p_stream_read_cb cb, void *userdata);
lp2p_err_t lp2p_stream_read_lp(lp2p_stream_t *stream, size_t max_frame_len,
                                 lp2p_stream_read_cb cb, void *userdata);

/* ── Write ────────────────────────────────────────────────────────────────── */
lp2p_err_t lp2p_stream_write(lp2p_stream_t *stream, const lp2p_buf_t *buf,
                               lp2p_stream_write_cb cb, void *userdata);
lp2p_err_t lp2p_stream_write_lp(lp2p_stream_t *stream, const lp2p_buf_t *buf,
                                  lp2p_stream_write_cb cb, void *userdata);

/* ── Lifecycle ────────────────────────────────────────────────────────────── */
lp2p_err_t  lp2p_stream_close(lp2p_stream_t *stream, lp2p_stream_write_cb cb,
                                void *userdata);
lp2p_err_t  lp2p_stream_reset(lp2p_stream_t *stream);

/* ── Introspection ────────────────────────────────────────────────────────── */
const char  *lp2p_stream_protocol(const lp2p_stream_t *stream);
void         lp2p_stream_set_userdata(lp2p_stream_t *stream, void *data);
void        *lp2p_stream_get_userdata(const lp2p_stream_t *stream);
lp2p_conn_t *lp2p_stream_connection(const lp2p_stream_t *stream);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_STREAM_H */
