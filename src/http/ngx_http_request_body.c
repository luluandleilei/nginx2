
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);

static ngx_int_t ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in);


/*
For dealing with the body of a client request, nginx provides the ngx_http_read_client_request_body(r, post_handler) 
and ngx_http_discard_request_body(r) functions. The first function reads the request body and makes it available via
the request_body request field. The second function instructs nginx to discard (read and ignore) the request body. 
One of these functions must be called for every request. Normally, the content handler makes the call.

Reading or discarding the client request body from a subrequest is not allowed. It must always be done in the main 
request. When a subrequest is created, it inherits the parent's request_body object which can be used by the 
subrequest if the main request has previously read the request body.

The function ngx_http_read_client_request_body(r, post_handler) starts the process of reading the request body. 
When the body is completely read, the post_handler callback is called to continue processing the request. 
If the request body is missing or has already been read, the callback is called immediately. 
The function ngx_http_read_client_request_body(r, post_handler) allocates the request_body request field of type 
ngx_http_request_body_t. The field bufs of this object keeps the result as a buffer chain. The body can be saved 
in memory buffers or file buffers, if the capacity specified by the client_body_buffer_size directive is not 
enough to fit the entire body in memory.

接收包体
启动了接收包体这一动作，在这个动作完成后，就会回调HTTP模块定义的post_handler方法。
NGX_OK:
NGX_AGAIN:
NGX_HTTP_*:
*/
ngx_int_t
ngx_http_read_client_request_body(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler)
{
    size_t                     preread;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

	//将该请求对应的原始请求的引用计数加1。
	//这同时是在要求每一个HTTP模块在传入的post_handler方法被回调时， 
	//务必调用类似ngx_http_finalize_request的方法去结束请求， 
	//否则引用计数会始终无法清零，从而导致请求无法释放。
    r->main->count++;

	//r != r->main，表示子请求不处理请求体
	//r->request_body != NULL，表示正在/已经执行过读取请求体方法
	//r->discard_body != 0，表示正在执行丢弃请求体的方法
    if (r != r->main || r->request_body || r->discard_body) {
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

    if (ngx_http_test_expect(r) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

	//分配用于接收包体的request_body成员
    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->free = NULL;
     *     rb->busy = NULL;
     *     rb->chunked = NULL;
     */

    rb->rest = -1;
    rb->post_handler = post_handler;

    r->request_body = rb;

	//XXX: 什么意思？表示没有请求体吗？
	//不会出现r->headers_in.content_length_n == 0 表示什么？不表示没有包体么？
    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {	
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_request_body(r);
        goto done;
    }
#endif

	//接收请求头的流程中，是有可能接收到请求体的
	//因此，需要检查是否在读取请求头时预读了请求体，
	//这里的检查是通过判断保存请求头的缓存(r->header_in)中是否还有未处理的数据
    preread = r->header_in->last - r->header_in->pos;

    if (preread) {	//header_in缓冲区中已经接收到包体

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http client request body preread %uz", preread);

        out.buf = r->header_in;
        out.next = NULL;

        rc = ngx_http_request_body_filter(r, &out);

        if (rc != NGX_OK) {
            goto done;
        }

		//更新请求长度大小
        r->request_length += preread - (r->header_in->last - r->header_in->pos);

		//在content_length模式下，还没有接收到全部的包体，检查header_in缓冲区里的剩余空间是否可存放下全部包体
        if (!r->headers_in.chunked && rb->rest > 0 && rb->rest <= (off_t) (r->header_in->end - r->header_in->last)) {
            /* the whole request body may be placed in r->header_in */

			//XXX:若剩余空间比client_body_buffer_size还大，当请求体大于client_body_buffer_size时那么仍就不会被写到文件中？
            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;

            rb->buf = b;

            r->read_event_handler = ngx_http_read_client_request_body_handler;
            r->write_event_handler = ngx_http_request_empty_handler;

            rc = ngx_http_do_read_client_request_body(r);
            goto done;
        }

    } else {	//header_in缓冲区中已经接收到包体
        /* set rb->rest */

        if (ngx_http_request_body_filter(r, NULL) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }

    if (rb->rest == 0) {	 /* the whole request body was pre-read */
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

    if (rb->rest < 0) {	//XXX:什么时候会出现？
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

	/* rb->rest > 0 */

	//XXX:a.创建读buf
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2;

    /* TODO: honor r->request_body_in_single_buf */

    if (!r->headers_in.chunked && rb->rest < size) {
        size = (ssize_t) rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

	//XXX:a+1.设置读写回调函数
    r->read_event_handler = ngx_http_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

	//XXX:a+2.
    rc = ngx_http_do_read_client_request_body(r);

done:

    if (r->request_body_no_buffering && (rc == NGX_OK || rc == NGX_AGAIN)) {
        if (rc == NGX_OK) {
            r->request_body_no_buffering = 0;

        } else {
            /* rc == NGX_AGAIN */
            r->reading_body = 1;
        }

		//
        r->read_event_handler = ngx_http_block_reading;	
        post_handler(r);
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		//XXX:为什么不是像ngx_http_read_client_request_body_handler中调用ngx_http_finalize_request来结束请求？
        r->main->count--;	
    }

    return rc;
}


ngx_int_t
ngx_http_read_unbuffered_request_body(ngx_http_request_t *r)
{
    ngx_int_t  rc;

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_unbuffered_request_body(r);

        if (rc == NGX_OK) {
            r->reading_body = 0;
        }

        return rc;
    }
#endif

    if (r->connection->read->timedout) {	//XXX: 这个是什么定时器？？
        r->connection->timedout = 1;
        return NGX_HTTP_REQUEST_TIME_OUT;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc == NGX_OK) {
        r->reading_body = 0;
    }

    return rc;
}


static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

	//Timeout for reading client request body 
    if (r->connection->read->timedout) {
        r->connection->timedout = 1;	//XXX:为什么需要把connection结构体上的timeout标志位也置为1
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_do_read_client_request_body(r);

	//XXX:rc >= NGX_HTTP_SPECIAL_RESPONSE 发生错误，不会调用post_handler
	//XXX:通过调用ngx_http_finalize_request将原始请求的count计数减1。
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}


/*
如果r->request_body_no_buffering == 0，则在(1)或(2)时调用filter函数
如果r->request_body_no_buffering == 1，则在(1)或(2)或(3)时调用filter函数
(1)‘读取到的数据等于rb->rest大小’
(2)‘读缓冲区满’
(3)‘没有更多数据可读’

如果r->request_body_no_buffering == 1，则在
//仅当 读取到的数据等于rb->rest 或者 读到缓冲区满 或者 无法读取跟多数据 的时候才调用filter进行处理
NGX_OK:	XXX:请求体全部读完
NGX_AGAIN: XXX:需要再次读取
NGX_HTTP_*: XXX：发生错误
*/
static ngx_int_t
ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_chain_t                out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http read client request body");

    for ( ;; ) {
        for ( ;; ) { 	//XXX: 为什么需要两个for循环
            if (rb->buf->last == rb->buf->end) {		//没有位置存放新的数据

                if (rb->buf->pos != rb->buf->last) {	//缓冲区中有数据

                    /* pass buffer to request body filter chain */

                    out.buf = rb->buf;
                    out.next = NULL;

                    rc = ngx_http_request_body_filter(r, &out);

                    if (rc != NGX_OK) {
                        return rc;
                    }

                } else {	//缓冲区中没有数据(都被消费了)， XXX：什么时候会这样？？？ 当前n也等于rest，已经调用了ngx_http_request_body_filter，消费掉了数据

                    /* update chains */

                    rc = ngx_http_request_body_filter(r, NULL);

                    if (rc != NGX_OK) {
                        return rc;
                    }
                }

                if (rb->busy != NULL) {		//XXX:调用filter后rb->busy在r->request_body_no_buffering== 0时应该为NULL（被写入了文件）。？？
                    if (r->request_body_no_buffering) {
                        if (c->read->timer_set) {	//XXX:这里为什么要删除定时器？？？
                            ngx_del_timer(c->read);
                        }

                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NGX_AGAIN;
                    }

                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

				//重置buf缓冲区
                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

			/* 缓冲区还有空闲的空间，读取内核套接字缓冲区里的TCP字符流 */
			
            size = rb->buf->end - rb->buf->last;				//缓冲区剩余空间大小
            rest = rb->rest - (rb->buf->last - rb->buf->pos);	//请求体剩余未读取的数据大小

            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

			//XXX:读数据之前为什么不判断c->read->ready ？？
			//对于no_buffering==1的情况，在读缓冲区满且任可以读时也会添加读事件后直接返回NGX_AGAIN
			//对于边沿触发事件机制，再下一次有数据到来之前不会触发读事件，
            n = c->recv(c, rb->buf->last, size);	

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0, "client prematurely closed connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

			/* n > 0 */
			
            rb->buf->last += n;
            r->request_length += n;

            if (n == rest) {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            if (rb->rest == 0) {
                break;
            }

			/* rb->rest > 0 */
			
            if (rb->buf->last < rb->buf->end) {
                break;
            }

			/* rb->buf->last == rb->buf->end */
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http client request body rest %O", rb->rest);

		//检查是否接收到完整的包体
        if (rb->rest == 0) {
            break;
        }

		/* rb->rest != 0 */

		//没有接收到完整的包体，且当前流不可读，则说明需要把读事件添加到事件模块， 等待可读事件发生时
        if (!c->read->ready) {

            if (r->request_body_no_buffering && rb->buf->pos != rb->buf->last) {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
		
		//还没有接收到完整的包体，且当前TCP流还可以读
    }

	//接收到完整的包体

	//删除XXX定时器
	//如果一次性读完了请求体是不会添加定时器的
    if (c->read->timer_set) {	//XXX:这是什么定时器，什么时候c->read->timer_set会为0
        ngx_del_timer(c->read);
    }

    if (!r->request_body_no_buffering) {
        r->read_event_handler = ngx_http_block_reading;
        rb->post_handler(r);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_write_request_body(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_chain_t               *cl, *ln;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http write client request body, bufs %p", rb->bufs);

    if (rb->temp_file == NULL) {
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;

        if (rb->bufs == NULL) {
            /* empty body with r->request_body_in_file_only */

            if (ngx_create_temp_file(&tf->file, tf->path, tf->pool, tf->persistent, tf->clean, tf->access) != NGX_OK) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

	//XXX:可能在rb->bufs == NULL的时候调用ngx_http_write_request_body这个函数吗？
    if (rb->bufs == NULL) {
        return NGX_OK;
    }

    n = ngx_write_chain_to_temp_file(rb->temp_file, rb->bufs);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    rb->temp_file->offset += n;

    /* mark all buffers as written */

    for (cl = rb->bufs; cl; /* void */) {

        cl->buf->pos = cl->buf->last;

        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    rb->bufs = NULL;

    return NGX_OK;
}


/*
instructs nginx to discard (read and ignore) the request body. 
对于HTTP模块而言，放弃接收包体就是简单地不处理包体了，可是对于HTTP框架而言，并不是不接收包体就可以的。因为对于客户端而言，通常
会调用一些阻塞的发送方法来发送包体，如果HTTP框架一直不接收包体，会导致实现上不够健壮的客户端认为服务器超时无响应，因而简单地关
闭连接，可这时Nginx模块可能还在处理这个连接。因此，HTTP模块中的放弃接收包体，对HTTP框架而言就是接收包体，但是接收后不做保存，直接丢弃。

HTTP模块调用的ngx_http_discard_request_body方法用于第一次启动丢弃包体动作，而ngx_http_discarded_request_body_handler是作为请
求的read_event_handler方法的，在有新的可读事件时会调用它处理包体。ngx_http_read discarded_request_body方法则是根据上述两个方法
通用部分提取出的公共方法，用来读取包体且不做任何处理。

*/
ngx_int_t
ngx_http_discard_request_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_int_t     rc;
    ngx_event_t  *rev;

	//r != r->main -- 非原始请求
	//r->discard_body -- 正在执行放弃接收请求体过程
	//r->request_body -- 正在/已经读取了请求体 或 已经放弃接收chunked请求体
    if (r != r->main || r->discard_body || r->request_body) {
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        r->stream->skip_data = 1;
        return NGX_OK;
    }
#endif

    if (ngx_http_test_expect(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

	//删掉读事件上的定时器
	//因为这时本身就不需要请求体，所以也无所谓客户端发送的快还是慢了
	//XXX:太慢会不会用来作为ddos攻击？？？
    if (rev->timer_set) {	//XXX: rev->timer_set 什么时候为1？？？
        ngx_del_timer(rev);
    }

	//注意：这里与ngx_http_read_client_request_body的区别
	//当放弃接收请求体过程执行完成，r->headers_in.content_length_n将会为0
	//当重复调用ngx_http_discard_request_body，在content_length模式下在此处直接返回
	//在chunked模式下，因为r->request_body != NULL返回
    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return NGX_OK;
    }

    size = r->header_in->last - r->header_in->pos;

    if (size || r->headers_in.chunked) { /* set r->headers_in.content_length_n for r->headers_in.chunked */
        rc = ngx_http_discard_request_body_filter(r, r->header_in);

        if (rc != NGX_OK) {	//XXX:发生错误
            return rc;
        }

        if (r->headers_in.content_length_n == 0) {	//XXX:请求体读取完成
            return NGX_OK;	//XXX:这里为什么不r->lingering_close = 0; ???
        }
    }

    rc = ngx_http_read_discarded_request_body(r);

    if (rc == NGX_OK) {
        r->lingering_close = 0;
        return NGX_OK;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    /* rc == NGX_AGAIN */

    r->read_event_handler = ngx_http_discarded_request_body_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->count++;
    r->discard_body = 1;	//XXX:数据还没有读取完毕，置变量，read_event_handler会下次处理

    return NGX_OK;
}


void
ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_msec_t                 timer;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (r->lingering_time) {
        timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();

        if ((ngx_msec_int_t) timer <= 0) {
            r->discard_body = 0;
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

    } else {
        timer = 0;
    }

    rc = ngx_http_read_discarded_request_body(r);

    if (rc == NGX_OK) {
        r->discard_body = 0;
        r->lingering_close = 0;
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* rc == NGX_AGAIN */

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (timer) {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        timer *= 1000;

        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }

        ngx_add_timer(rev, timer);
    }
}

/*
NGX_AGAIN:
NGX_OK:		XXX:所有的请求体都被读取完成
NGX_HTTP_*:
*/
static ngx_int_t
ngx_http_read_discarded_request_body(ngx_http_request_t *r)
{
    size_t     size;
    ssize_t    n;
    ngx_int_t  rc;
    ngx_buf_t  b;
    u_char     buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http read discarded body");

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.temporary = 1;

    for ( ;; ) {
        if (r->headers_in.content_length_n == 0) {	//XXX:为什么感觉应该是放在for循环的最后来进行判断 ???
            r->read_event_handler = ngx_http_block_reading;
            return NGX_OK;
        }

        if (!r->connection->read->ready) {
            return NGX_AGAIN;
        }

        size = (size_t) ngx_min(r->headers_in.content_length_n, NGX_HTTP_DISCARD_BUFFER_SIZE);

        n = r->connection->recv(r->connection, buffer, size);

        if (n == NGX_ERROR) {
            r->connection->error = 1;
            return NGX_OK;	//为什么返回NGX_OK？连接读错误，视为数据已经读取完，故返回NGX_OK
        }

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == 0) {	//XXX:这种情况表示什么？？对端关闭了连接？
            return NGX_OK;	//为什么返回NGX_OK？对端关闭了连接，视为数据已经读取完，故返回NGX_OK
        }

		/* n > 0 */
		
        b.pos = buffer;
        b.last = buffer + n;

        rc = ngx_http_discard_request_body_filter(r, &b);

        if (rc != NGX_OK) {
            return rc;
        }
    }
}


/*
NGX_HTTP_INTERNAL_SERVER_ERROR:
NGX_HTTP_BAD_REQUEST:
NGX_OK:
*/
static ngx_int_t
ngx_http_discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t                    size;
    ngx_int_t                 rc;
    ngx_http_request_body_t  *rb;

    if (r->headers_in.chunked) {

        rb = r->request_body;

        if (rb == NULL) {

            rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
            if (rb == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
            if (rb->chunked == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->request_body = rb;
        }

        for ( ;; ) {

            rc = ngx_http_parse_chunked(r, b, rb->chunked);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                size = b->last - b->pos;

                if ((off_t) size > rb->chunked->size) {
                    b->pos += (size_t) rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    b->pos = b->last;
                }

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                r->headers_in.content_length_n = 0;
                break;
            }

            if (rc == NGX_AGAIN) {

                /* set amount of data we want to see next time */

                r->headers_in.content_length_n = rb->chunked->length;
                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }

    } else {
        size = b->last - b->pos;

        if ((off_t) size > r->headers_in.content_length_n) {
            b->pos += (size_t) r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;

        } else {
            b->pos = b->last;
            r->headers_in.content_length_n -= size;
        }
    }

    return NGX_OK;
}

/*
处理http1.1 expect的情况：
	检查客户端是否发送了Expect: 100-continue头，是的话则给客户端回复”HTTP/1.1 100 Continue”，

根据http 1.1协议，客户端可以发送一个Expect头来向服务器表明期望发送请求体，
服务器如果允许客户端发送请求体，则会回复”HTTP/1.1 100 Continue”，客户端收到时，才会开始发送请求体。
而服务端不希望接收请求体时，必须返回417(Expectation Failed)错误。
nginx并没这样做，它只是简单的让客户端把请求体发送过来，然后丢弃掉。
*/
static ngx_int_t
ngx_http_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11
#if (NGX_HTTP_V2)
        || r->stream != NULL
#endif
       )
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1 
		|| ngx_strncasecmp(expect->data, (u_char *) "100-continue", sizeof("100-continue") - 1) != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "send 100 Continue");

    n = r->connection->send(r->connection, (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF, sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    r->connection->error = 1;

    return NGX_ERROR;
}


/*
NGX_OK:
NGX_HTTP_*:
*/
static ngx_int_t
ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (r->headers_in.chunked) {
        return ngx_http_request_body_chunked_filter(r, in);

    } else {
        return ngx_http_request_body_length_filter(r, in);
    }
}


static ngx_int_t
ngx_http_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *tl, *out, **ll;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

    if (rb->rest == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http request body content length filter");

        rb->rest = r->headers_in.content_length_n;
    }

    out = NULL;
    ll = &out;

	//XXX: 为什么需要重新分配chain对象和buf对象 ？？
	//函数参数in对应的chain和buf肯能时临时变量？需要重新修一些字段？为了跟chunked_filter一致？
	//A filter handler receives a chain of buffers. The handler is supposed to process the buffers and pass
	//a possibly new chain to the next handler. It's worth noting that the chain links ngx_chain_t of the 
	//incoming chain belong to the caller, and must not be reused or changed. Right after the handler 
	//completes, the caller can use its output chain links to keep track of the buffers it has sent. To save
	//the buffer chain or to substitute some buffers before passing to the next filter, a handler needs to 
	//allocate its own chain links.
    for (cl = in; cl; cl = cl->next) {

        if (rb->rest == 0) {
            break;
        }

        tl = ngx_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->temporary = 1;
        b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
        b->start = cl->buf->pos;					//XXX:
        b->pos = cl->buf->pos;
        b->last = cl->buf->last;
        b->end = cl->buf->end;
        b->flush = r->request_body_no_buffering;	//XXX:

        size = cl->buf->last - cl->buf->pos; //缓冲区中数据大小

        if ((off_t) size < rb->rest) {
            cl->buf->pos = cl->buf->last;
            rb->rest -= size;

        } else {
            cl->buf->pos += (size_t) rb->rest;
            rb->rest = 0;
            b->last = cl->buf->pos;
            b->last_buf = 1;
        }

        *ll = tl;
        ll = &tl->next;
    }

    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out, (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


static ngx_int_t
ngx_http_request_body_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *out, *tl, **ll;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    if (rb->rest == -1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http request body chunked filter");

        rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
        if (rb->chunked == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_in.content_length_n = 0;	//XXX:用于记录已经读到的请求体的大小
        rb->rest = 3;
    }

    out = NULL;
    ll = &out;

	//处理每一个chain
    for (cl = in; cl; cl = cl->next) {

		//处理每一个buf
        for ( ;; ) {

            ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                           "http body chunked buf "
                           "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
                           cl->buf->temporary, cl->buf->in_file,
                           cl->buf->start, cl->buf->pos,
                           cl->buf->last - cl->buf->pos,
                           cl->buf->file_pos,
                           cl->buf->file_last - cl->buf->file_pos);

            rc = ngx_http_parse_chunked(r, cl->buf, rb->chunked);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

				//若当前请求体的总大小超过了client_max_body_size大小返回413
                if (clcf->client_max_body_size && clcf->client_max_body_size - r->headers_in.content_length_n < rb->chunked->size) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "client intended to send too large chunked " "body: %O+%O bytes", r->headers_in.content_length_n, rb->chunked->size);

                    r->lingering_close = 1;

                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->temporary = 1;
                b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
                b->start = cl->buf->pos;
                b->pos = cl->buf->pos;
                b->last = cl->buf->last;
                b->end = cl->buf->end;
                b->flush = r->request_body_no_buffering;

                *ll = tl;
                ll = &tl->next;

                size = cl->buf->last - cl->buf->pos;

                if ((off_t) size > rb->chunked->size) {
                    cl->buf->pos += (size_t) rb->chunked->size;
                    r->headers_in.content_length_n += rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    r->headers_in.content_length_n += size;
                    cl->buf->pos = cl->buf->last;
                }

                b->last = cl->buf->pos;

                continue;
            }

            if (rc == NGX_DONE) {	//XXX:在NGX_DONE之后会不会buf中还有多余的数据或者后面还有chain节点？（参看ngx_http_request_body_length_filter）

                /* a whole response has been parsed successfully */

                rb->rest = 0;

				//
                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->last_buf = 1;

                *ll = tl;
                ll = &tl->next;

                break;
            }

            if (rc == NGX_AGAIN) {

                /* set rb->rest, amount of data we want to see next time */

                rb->rest = rb->chunked->length;

                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out, (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


ngx_int_t
ngx_http_request_body_save_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

#if (NGX_DEBUG)

#if 0
    for (cl = rb->bufs; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }
#endif

    for (cl = in; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    /* TODO: coalesce neighbouring buffers */

    if (ngx_chain_add_copy(r->pool, &rb->bufs, in) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->request_body_no_buffering) {
        return NGX_OK;
    }

    if (rb->rest > 0) {

		//缓冲区已满，将缓冲区数据写入文件
		//XXX：这里rb->buf有可能为NULL吗？
		//当处理r->header_in中的请求体中的数据的时候rb->buf为NULL
        if (rb->buf && rb->buf->last == rb->buf->end && ngx_http_write_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_OK;
    }

    /* rb->rest == 0 */

	//XXX:在rb->temp_file不为NULL的情况下，为什么还要把剩余数据写到文件中??
    if (rb->temp_file || r->request_body_in_file_only) {	

        if (ngx_http_write_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rb->temp_file->file.offset != 0) {

            cl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;

            rb->bufs = cl;
        }
    }

    return NGX_OK;
}
