
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NGX_THREAD_POOL_H_INCLUDED_
#define _NGX_THREAD_POOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


struct ngx_thread_task_s {
    ngx_thread_task_t   *next;
    ngx_uint_t           id;	//任务ID，用于唯一标识一个线程池中的任务
    void                *ctx;	//执行任务的上下文(handler的第一个参数)
    void               (*handler)(void *data, ngx_log_t *log); //需要异步执行的任务
    ngx_event_t          event;	//(复用event对象)用于记录一些状态和task完成时的回调函数
};


typedef struct ngx_thread_pool_s  ngx_thread_pool_t;


ngx_thread_pool_t *ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name);
ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name);

ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *pool, size_t size);
ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task);


#endif /* _NGX_THREAD_POOL_H_INCLUDED_ */
