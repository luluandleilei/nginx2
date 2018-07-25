
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_atomic_t   lock;	//通过对该变量进行原子操作来进行锁的获取与释放
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;	//支持信号量时才会有该成员变量，表示当前在信号量上等待的进程数目
#endif
} ngx_shmtx_sh_t;


//ngx_shmtx_t结构体定义使用了两个宏：NGX_HAVE_ATOMIC_OPS 与 NGX_HAVE_POSIX_SEM，分别用来代表操作系统是否支持原子变量操作与信号量。
//根据这两个宏的取值，可以有3种不同的互斥锁实现：
//	(1)不支持原子操作。(2)支持原子操作，但不支持信号量 (3) 支持原子操作，也支持信号量
//第1种情况最简单，会直接使用文件锁来实现互斥锁，这时该结构体只有 fd 、 name和 spin 三个字段，但 spin 字段是不起作用的。
//对于2和3两种情况 nginx 均会使用原子变量操作来实现一个自旋锁，其中 spin 表示自旋次数。它们两个的区别是：在支持信号量的情况下，
//如果自旋次数达到了上限而进程还未获取到锁，则进程会在信号量上阻塞等待，进入睡眠状态。不支持信号量的情况，如果自旋次数达到了上限
//而进程还未获取到锁，进程会通过调度器直接「让出」cpu，进程不会进入睡眠状态，这回减少内核态与用户态切换带来的开销，所以往往性能更好
//因此在nginx中使用锁时一般不使用信号量
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    ngx_atomic_t  *lock;
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t  *wait;		//表示当前等待在信号量上的进程数目
    ngx_uint_t     semaphore;	//表示是否使用信号量sem
    sem_t          sem;
#endif
#else							//不支持原子操作，使用文件锁来实现，效率稍低
    ngx_fd_t       fd;			
    u_char        *name;
#endif
    ngx_uint_t     spin;		//获取锁时尝试的自旋次数，使用原子操作实现锁时才有意义
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
