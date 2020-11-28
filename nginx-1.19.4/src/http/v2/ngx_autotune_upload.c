/*
 * Copyright (C) 2020 Cloudflare, Inc.
 */

#include <ngx_http.h>
#include <ngx_http_v2_module.h>
#include <ngx_autotune_upload.h>

static void *ngx_prealloc(ngx_pool_t *pool, void *p, size_t size);
static void *ngx_realloc(void *oldp, size_t size, ngx_log_t *log);

static ngx_int_t ngx_resize_buf(ngx_pool_t *pool, ngx_buf_t *buf, size_t nsize);


static void *
ngx_prealloc(ngx_pool_t *pool, void *p, size_t size)
{
    ngx_pool_large_t *l;
    void *newp;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "prealloc: %p", l->alloc);

            newp = ngx_realloc(l->alloc, size, pool->log);
            if (newp) {
                l->alloc = newp;

                return newp;
            } else {
                return NULL;
           }
        }
    }

    /* not found */
    return NULL;
}


static void *
ngx_realloc(void *oldp, size_t size, ngx_log_t *log)
{
    void *newp;

    newp = realloc(oldp, size);
    if (newp == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "realloc(%uz) failed", size);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "realloc: %p:%uz", newp, size);

    return newp;
}


/* resize the buffer to the new size */
static ngx_int_t
ngx_resize_buf(ngx_pool_t *pool, ngx_buf_t *buf, size_t nsize)
{
    void *nbuf = ngx_prealloc(pool, buf->start, nsize);

    if (!nbuf) {
        return NGX_ERROR;
    }

    /* if buf->start is moved to a new location */
    if (nbuf != buf->start) {
        buf->pos = (u_char *)nbuf + (buf->pos - buf->start);
        buf->last = (u_char *)nbuf + (buf->last - buf->start);
    }

    /* resize buffer */
    buf->start = nbuf;
    buf->end = (u_char *)nbuf + nsize;

    return NGX_OK;
}


/* get current TCP RTT (ms) of the connection */
ngx_int_t
ngx_tcp_rtt_ms(int fd)
{
#if (NGX_HAVE_TCP_INFO)
    struct tcp_info  ti;
    socklen_t        len;

    len = sizeof(struct tcp_info);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == 0) {
        return ti.tcpi_rtt / 1000;
    }
#endif

    return NGX_ERROR;
}


/* return current timestamp (ms) */
ngx_msec_int_t
ngx_timestamp_ms()
{
    ngx_time_t *tp = ngx_timeofday();

    return tp->sec * 1000 + tp->msec;
}


/*
 * double the buffer size based on the current BDP.
 * returns the new window size if resized.
 * returns the current window size if not resized.
 * if resizing fails, returns 0.
 */
size_t
ngx_autotune_client_body_buffer(ngx_http_request_t *r,
    size_t window)
{
    ngx_buf_t                 *buf;
    ngx_http_v2_stream_t      *stream;
    ngx_msec_int_t             ts_now;
    ngx_http_v2_loc_conf_t    *h2lcf;
    size_t                     max_window;

    h2lcf = ngx_http_get_module_loc_conf(r, ngx_http_v2_module);
    max_window = h2lcf->max_client_body_buffer_size;

    /* no autotuning configured */
    if (!max_window) {
        return window;
    }

    /* if max_window is smaller than the current window, do nothing */
    if (window >= max_window) {
        return window;
    }

    stream = r->stream;
    buf = r->request_body->buf;

    /* if rtt is not available, do nothing */
    if (stream->rtt == NGX_ERROR) {
        return window;
    }

    ts_now = ngx_timestamp_ms();

    if (ts_now >= (stream->ts_checkpoint + stream->rtt)) {
        size_t cur_win = (buf->end - buf->start);
        size_t new_win = ngx_min(cur_win * 2 , max_window);

        /* if already on the max size, do nothing */
        if (cur_win >= max_window) {
            return window;
        }

        /* min rtt is 1ms to prevent BDP from becoming zero. */
        ngx_uint_t rtt = ngx_max(stream->rtt, 1);

        /*
         * elapsed time (ms) from last checkpoint. mininum value is 1 to
         * prevent from dividing by zero in BDP calculation
         */
        ngx_uint_t elapsed = ngx_max(ts_now - stream->ts_checkpoint, 1);

        /* calculate BDP (bytes) = rtt * bw */
        ngx_uint_t bdp = rtt * stream->bytes_body_read / elapsed;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, stream->connection->connection->log, 0,
                       "http2 autotune sid:%ui rtt:%z bdp:%z win:%z",
                       stream->node->id, stream->rtt, bdp, window);

        stream->bytes_body_read = 0;
        stream->ts_checkpoint = ts_now;

        /*
         * check if we need to bump the buffer size
         * based on the heuristic condition
         */
        if (bdp > (window / 4)) {
            if (ngx_resize_buf(r->pool, buf, new_win) != NGX_OK) {
                return 0;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP,
                           stream->connection->connection->log, 0,
                           "http2 autotune sid:%ui rtt:%z resized:%z->%z",
                           stream->node->id, stream->rtt, window,
                           window + (new_win - cur_win));

            return window + (new_win - cur_win);
        }
    }

    return window;
}
