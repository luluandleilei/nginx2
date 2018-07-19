
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    u_char      *addr;	//共享内存起始地址
    size_t       size;	//共享内存大小
    ngx_str_t    name;	//共享内存名称,唯一标识该共享内存
    ngx_log_t   *log;
    ngx_uint_t   exists;   /* unsigned  exists:1;  */	//目前仅在windows下使用，表示共享内存是否分配过的标志位，为1表示已经存在
} ngx_shm_t;


ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHMEM_H_INCLUDED_ */
