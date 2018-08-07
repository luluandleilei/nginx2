
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_RESOLVER_H_INCLUDED_
#define _NGX_RESOLVER_H_INCLUDED_


#define NGX_RESOLVE_A         1
#define NGX_RESOLVE_CNAME     5
#define NGX_RESOLVE_PTR       12
#define NGX_RESOLVE_MX        15
#define NGX_RESOLVE_TXT       16
#if (NGX_HAVE_INET6)
#define NGX_RESOLVE_AAAA      28
#endif
#define NGX_RESOLVE_SRV       33
#define NGX_RESOLVE_DNAME     39

//报文格式错误(Format error) - 服务器不能理解请求的报文
#define NGX_RESOLVE_FORMERR   1	
//服务器失败(Server failure) - 因为服务器的原因导致没办法处理这个请求。
#define NGX_RESOLVE_SERVFAIL  2
//名字错误(Name Error) - 只有对授权域名解析服务器有意义，指出解析的域名不存在。
#define NGX_RESOLVE_NXDOMAIN  3
//没有实现(Not Implemented) - 域名服务器不支持查询类型。
#define NGX_RESOLVE_NOTIMP    4
//拒绝(Refused) - 服务器由于设置的策略拒绝给出应答。
//比如，服务器不希望对某些请求者给出应答，或者服务器不希望进行某些操作（比如区域传送zone transfer）
#define NGX_RESOLVE_REFUSED   5
#define NGX_RESOLVE_TIMEDOUT  NGX_ETIMEDOUT


#define NGX_NO_RESOLVER       (void *) -1

#define NGX_RESOLVER_MAX_RECURSION    50


typedef struct ngx_resolver_s  ngx_resolver_t;


//描述了一个用于进行域名解析的的连接
typedef struct {
    ngx_connection_t         *udp;
    ngx_connection_t         *tcp;
    struct sockaddr          *sockaddr;	//DNS服务器套接字地址结构
    socklen_t                 socklen;	//
    ngx_str_t                 server;	//DNS服务器ip:port字符串表示
    ngx_log_t                 log;		//
    ngx_buf_t                *read_buf;	//tcp对象使用
    ngx_buf_t                *write_buf;//tcp对象使用
    ngx_resolver_t           *resolver;	//该连接所属于的resolver对象
} ngx_resolver_connection_t;


typedef struct ngx_resolver_ctx_s  ngx_resolver_ctx_t;

typedef void (*ngx_resolver_handler_pt)(ngx_resolver_ctx_t *ctx);


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    ngx_str_t                 name;
    u_short                   priority;
    u_short                   weight;
} ngx_resolver_addr_t;


typedef struct {
    ngx_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;
} ngx_resolver_srv_t;


typedef struct {
    ngx_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;

    ngx_resolver_ctx_t       *ctx;
    ngx_int_t                 state;

    ngx_uint_t                naddrs;
    ngx_addr_t               *addrs;
} ngx_resolver_srv_name_t;


typedef struct {
    ngx_rbtree_node_t         node;
    ngx_queue_t               queue;

    /* PTR: resolved name, A: name to resolve */
    u_char                   *name;

#if (NGX_HAVE_INET6)
    /* PTR: IPv6 address to resolve (IPv4 address is in rbtree node key) */
    struct in6_addr           addr6;
#endif

    u_short                   nlen;		//name的长度
    u_short                   qlen;		//dns的ipv4|ipv6的name查询报文(长度是一样的，仅仅某些字段的值不一样)

    u_char                   *query;	//dns的ipv4的name查询报文(malloc分配)
#if (NGX_HAVE_INET6)
    u_char                   *query6;	//dns的ipv6的name查询报文
#endif

    union {
        in_addr_t             addr;		//存放回答中有且仅有的一个地址结果
        in_addr_t            *addrs;	//存放回答中的多个地址结果
        u_char               *cname;	//存放回答中的cname结果(没有ipv4,ipv6地址)
        ngx_resolver_srv_t   *srvs;		//XXX:service查询结果
    } u;

    u_char                    code;
    u_short                   naddrs;	//A查询响应的回答中addrs的个数
    u_short                   nsrvs;	//srvs的个数
    u_short                   cnlen;	//cname的长度

#if (NGX_HAVE_INET6)
    union {
        struct in6_addr       addr6;	//存放回答中有且仅有的一个地址结果
        struct in6_addr      *addrs6;	//存放回答中的多个地址结果
    } u6;

    u_short                   naddrs6;	//AAAA查询响应的回答addrs6的个数
#endif

    time_t                    expire;	//重新发送请求的时间
    time_t                    valid;	//地址解析结果的有效时间
    uint32_t                  ttl;		//回答中最小的ttl

    unsigned                  tcp:1;	//表示使用tcp进行域名的Ipv4地址查询
#if (NGX_HAVE_INET6)
    unsigned                  tcp6:1;	//表示使用tcp进行域名的ipv6地址查询
#endif

    ngx_uint_t                last_connection;	//使用ngx_resolver_t->connections的连接对象的索引

    ngx_resolver_ctx_t       *waiting;	//等待此node的ctx
} ngx_resolver_node_t;


struct ngx_resolver_s {
    /* has to be pointer because of "incomplete type" */
	//重传定时器事件，与resend_timeout配合使用
    ngx_event_t              *event;	 
    void                     *dummy;
    ngx_log_t                *log;

    /* event ident must be after 3 pointers as in ngx_connection_t */
    ngx_int_t                 ident;

    /* simple round robin DNS peers balancer */
	//array of ngx_resolver_connection_t
    ngx_array_t               connections;	
    ngx_uint_t                last_connection;

	//XXX:name查询的缓存？？？
    ngx_rbtree_t              name_rbtree;	
    ngx_rbtree_node_t         name_sentinel;

	//XXX:srv查询的缓存？？？
    ngx_rbtree_t              srv_rbtree;
    ngx_rbtree_node_t         srv_sentinel;

	//XXX:addr查询的缓存
    ngx_rbtree_t              addr_rbtree;
    ngx_rbtree_node_t         addr_sentinel;

    ngx_queue_t               name_resend_queue;
    ngx_queue_t               srv_resend_queue;
    ngx_queue_t               addr_resend_queue;

    ngx_queue_t               name_expire_queue;
    ngx_queue_t               srv_expire_queue;
    ngx_queue_t               addr_expire_queue;

#if (NGX_HAVE_INET6)
	//XXX:enable looking up of IPv6 addressess
    ngx_uint_t                ipv6;  
	//XXX:addr6查询的缓存
    ngx_rbtree_t              addr6_rbtree;
    ngx_rbtree_node_t         addr6_sentinel;
    ngx_queue_t               addr6_resend_queue;
    ngx_queue_t               addr6_expire_queue;
#endif

	//重传间隔
	//每个请求在发出请求后，若在resend_timeout时间内未收到请求，
	//且还有上层关心该请求则将会切换后端dns sersver进行重传
    time_t                    resend_timeout;	
    time_t                    tcp_timeout;	//tcp连接在tcp_timeout时间内至少要有数据发送，不然认为超时
    //XXX:过期间隔
    //(节点在解析成功之后，）在连续的expire时间间隔内node未被访问，将会被删除掉
    time_t                    expire;	
	//XXX:time of cacheing answers
    time_t                    valid;	

    ngx_uint_t                log_level;
};


//进行域名解析时的上下文
struct ngx_resolver_ctx_s {
    ngx_resolver_ctx_t       *next;		//[internal]关注同一个node的ctx链表形式组织
    ngx_resolver_t           *resolver;	//[internal]
    ngx_resolver_node_t      *node;		//[internal]

    /* event ident must be after 3 pointers as in ngx_connection_t */
    ngx_int_t                 ident;

    ngx_int_t                 state;	//[out]域名解析结果状态 NGX_OK, NGX_AGAIN, NGX_RESOLVE_TIMEDOUT, NGX_RESOLVE_NXDOMAIN
    ngx_str_t                 name;		//[in]需要解析的域名name
    ngx_str_t                 service;	//[in]需要XXX的service？？？

    time_t                    valid;	//[out?]//解析的结果的有效时间
    ngx_uint_t                naddrs;	//[out]存储name解析的结果的数组元素个数
    ngx_resolver_addr_t      *addrs;	//[out]存储name解析的结果的数组
    ngx_resolver_addr_t       addr;		//[internal]存储name解析的有且仅有的一个ipv4结果
    struct sockaddr_in        sin;		//[internal]存储name解析的有且仅有的一个ipv4结果(addr.sockaddr)引用的地址

    ngx_uint_t                count;
    ngx_uint_t                nsrvs;
    ngx_resolver_srv_name_t  *srvs;

    ngx_resolver_handler_pt   handler;	//[in]域名解析完成后的回调函数
    void                     *data;		//[in]handler回调函数使用的数据
    ngx_msec_t                timeout;	//[in]ctx等待node域名解析的超时时间

    unsigned                  quick:1;	//[internal]
    unsigned                  async:1;
    unsigned                  cancelable:1;	//[internal]超时事件的cancelable标识
    ngx_uint_t                recursion;	//[internal]
    ngx_event_t              *event;		//[internal]timeout指定的超时事件
};


ngx_resolver_t *ngx_resolver_create(ngx_conf_t *cf, ngx_str_t *names, ngx_uint_t n);
ngx_resolver_ctx_t *ngx_resolve_start(ngx_resolver_t *r, ngx_resolver_ctx_t *temp);
ngx_int_t ngx_resolve_name(ngx_resolver_ctx_t *ctx);
void ngx_resolve_name_done(ngx_resolver_ctx_t *ctx);
ngx_int_t ngx_resolve_addr(ngx_resolver_ctx_t *ctx);
void ngx_resolve_addr_done(ngx_resolver_ctx_t *ctx);
char *ngx_resolver_strerror(ngx_int_t err);


#endif /* _NGX_RESOLVER_H_INCLUDED_ */
