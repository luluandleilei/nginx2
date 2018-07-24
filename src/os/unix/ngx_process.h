
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_pid_t           pid;		//进程id  
    int                 status;		//进程的退出状态(主要在waitpid中进行处理).
    ngx_socket_t        channel[2];	//进程channel(也就是通过socketpair创建的两个句柄); channel[0] -- 对端进程 channel[1] -- 本端进程

    ngx_spawn_proc_pt   proc;	//进程的执行函数（也就是每次spawn，子进程所要执行的那个函数)
    void               *data;
    char               *name;

    unsigned            respawn:1;		//表示当进程挂掉，需要重新拉起来
    unsigned            just_spawn:1;	//表示该进程刚刚被重新拉起来
    unsigned            detached:1;		//表示该进程分离了
    unsigned            exiting:1;		//表示进程正在退出（给该子进程发送了XXX信号(消息)）
    unsigned            exited:1;		//表示进程已经退出（收到该子进程的SIGCHLD信号）
} ngx_process_t;


typedef struct {
    char         *path;	//程序路径
    char         *name;
    char *const  *argv;	//程序参数
    char *const  *envp; //程序环境变量
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024

#define NGX_PROCESS_NORESPAWN     -1	//子进程退出时,父进程不会再次创建(在创建cache loader process时使用)
#define NGX_PROCESS_JUST_SPAWN    -2
#define NGX_PROCESS_RESPAWN       -3	//子进程异常退出时,父进程重新生成子进程
#define NGX_PROCESS_JUST_RESPAWN  -4
#define NGX_PROCESS_DETACHED      -5		//热代码替换,父、子进程分离的标识位 


#define ngx_getpid   getpid
#define ngx_getppid  getppid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_pid_t      ngx_parent;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
