/*
 * Copyright (C) 2020 Cloudflare, Inc.
 */

#ifndef _NGX_AUTOTUNE_UPLOAD_H_INCLUDED_
#define _NGX_AUTOTUNE_UPLOAD_H_INCLUDED_

#include <ngx_core.h>


/* the maximum size of the receiver window */
#define NGX_HTTP_V2_MAX_CLIENT_BODY_BUFFER_SIZE (64*1024*1024)


/* get current TCP RTT (ms) of the connection */
ngx_int_t ngx_tcp_rtt_ms(int fd);

/* return current timestamp (ms) */
ngx_msec_int_t ngx_timestamp_ms();

/* auto resize the buffer */
size_t ngx_autotune_client_body_buffer(ngx_http_request_t *r, size_t window);


#endif
