
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;					////套接字

    struct sockaddr    *sockaddr;			//本地绑定的套接字地址结构
    socklen_t           socklen;    		/* size of sockaddr */
    size_t              addr_text_max_len;	//地址的字符串表示的可能的最大长度
    ngx_str_t           addr_text;			//本地绑定的地址的字符串表示

    int                 type;

    int                 backlog;
    int                 rcvbuf;
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;	//ngx_http_init_connection, ngx_stream_init_connection

	/* array of ngx_http_in_addr_t, for example */
	//XXX：每个ngx_http_in_addr_t记录了对应的ip，默认server,及。。。
    void               *servers;  

    ngx_log_t           log;
    ngx_log_t          *logp;

	//Per-connection memory allocations of default server
    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
	//Timeout for reading client request header of default server
    ngx_msec_t          post_accept_timeout;

	//记录该listen对象继承的listen对象，用于删除侦听套接字的先前事件(继承的listen对象)，仅在单进程模式下有效
    ngx_listening_t    *previous;	
    ngx_connection_t   *connection;	//XXX:监听套接字对应的connection对象

    ngx_rbtree_t        rbtree;		//XXX: UDP?
    ngx_rbtree_node_t   sentinel;

    ngx_uint_t          worker;		//该listen对象所属于的worker进程的编号

    unsigned            open:1;		//XXX:表示cycle的listen对象套接字主动打开的，而不是从old_cycle继承的，在初始化新的cycle失败时需要调用close释放掉，继承listen对象不能close掉，将会回滚还原时使用
    unsigned            remain:1;	//XXX:保留该对象？记录old_cycle的listen对象是否被新的cycle复用，复用则标记保留，在关闭old_cycle的listen对象时不关闭掉
    unsigned            ignore:1;	//XXX：为1表示跳过设置当前ngx_listening_t结构体中的套接字，为0时正常初始化套接字

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;		//XXX：we should change backlog via listen
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;	//XXX:将网络地址转换为字符串形式的地址?
    unsigned            wildcard:1;	//XXX： 表示通配地址？

#if (NGX_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;

    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02


//XXX:表示一个监听套接字或者已连接套接字及其状态，
//(被动连接)表示客户端主动发起的，Nginx服务器被动接受的TCP连接
//不可以随意创建， 必须从连接池中获取该对象
//The connection type ngx_connection_t is a wrapper around a socket descriptor.
struct ngx_connection_s {
	//Arbitrary connection context. Normally, it is a pointer to a higher-level object built on top
	//of the connection, such as an HTTP request or a Stream session.
    void               *data;	 //连接未使用时，data成员用于充当连接池中空闲连接链表中的next指针。 //当连接被使用时，data的意义由使用它的nginx模块而定，如在HTTP框架中，data指向ngx_http_request_t请求
    ngx_event_t        *read;	//Read events for the connection.	//连接对应的读事件
    ngx_event_t        *write;	//write events for the connection.	//连接对应的写事件

    ngx_socket_t        fd;		//Socket descriptor//连接对象对应的套接字 //连接对应的套接字句柄

	 //下面4个成员以方法指针的形式出现， 说明每个连接都可以采用不同的接收方法， 每个事件消费模块都可以灵活地决定其行为。
    //不同的事件驱动机制需要使用的接收、发送方法多半是不一样的。
    //recv, send, recv_chain, send_chain — I/O operations for the connection.
    ngx_recv_pt         recv;	//直接接受网络字符流的方法，根据系统环境的不同指向不同的函数
    ngx_send_pt         send;	//直接发送网络字符流的方法，根据系统环境的不同指向不同的函数
    ngx_recv_chain_pt   recv_chain;	//以ngx_chain_t链表为参数来接收网络字节流的方法
    ngx_send_chain_pt   send_chain;	//以ngx_chain_t链表为参数来发送网络字节流的方法

    ngx_listening_t    *listening;	//连接对应的ngx_listening_t监听对象，此连接由listening监听端口的事件建立

    off_t               sent;	//连接上已经发送出去的字节数

    ngx_log_t          *log;	//Connection log.	//可以记录日志的ngx_log_t对象

    ngx_pool_t         *pool;	//Connection pool.	//内存池。 一般在accept一个新连接时会创建一个内存池，而在这个连接结束时会销毁内存池。 //这个内存池的大小将由上面的listening监听对象中的pool_size成员决定 //注意， 这里所说的连接是指成功建立的TCP连接， 所有的ngx_connection_t结构体都是预分配的。

    int                 type;	//套接字类型SOCK_STREAM|SOCK_DATAGRAM

	//sockaddr, socklen, addr_text — Remote socket address in binary and text forms.
    struct sockaddr    *sockaddr;	//连接客户端的sockaddr结构体		
    socklen_t           socklen;	//sockaddr结构体的长度		
    ngx_str_t           addr_text;	//连接客户端字符串形式的ip地址

	//proxy_protocol_addr, proxy_protocol_port - PROXY protocol client address and port, 
	//if the PROXY protocol is enabled for the connection.
    ngx_str_t           proxy_protocol_addr;
    in_port_t           proxy_protocol_port;

#if (NGX_SSL || NGX_COMPAT)
	//An nginx connection can transparently encapsulate the SSL layer. 
	//In this case the connection's ssl field holds a pointer to an ngx_ssl_connection_t structure, 
	//keeping all SSL-related data for the connection, including SSL_CTX and SSL. 
	//The recv, send, recv_chain, and send_chain handlers are set to SSL-enabled functions as well.
    ngx_ssl_connection_t  *ssl;	//SSL context for the connection.
#endif

    ngx_udp_connection_t  *udp;

	//local_sockaddr, local_socklen — Local socket address in binary form. Initially, these fields are empty. 
	//Use the ngx_connection_local_sockaddr() function to get the local socket address.
    struct sockaddr    *local_sockaddr;	//本机的监听端口对应的sockaddr结构体，也就是listening监听对象中的sockaddr成员
    socklen_t           local_socklen;

	//用于接收、缓存客户端发来的字节流，每个事件消费模块可自由决定从连接池中分配多大的空间给该字段。 
	//例如，在HTTP模块中，它的大小决定于client_header_buffer_size配置项
    ngx_buf_t          *buffer;		

	//用来将当前连接以双向链表元素的形式添加到ngx_cycle_t核心结构体的reuseable_connections_queue双向链表中，表示可以重用的连接
    ngx_queue_t         queue;	

	//连接使用次数。ngx_connection_t结构体每次建立一条来自客户端的连接，
	//或者用于主动向后端服务器发起连接时(ngx_peer_connection_s也使用它)，number都会加 1
    ngx_atomic_uint_t   number;	

    ngx_uint_t          requests;	//处理的请求次数

	//缓存中的业务类型。 任何事件消费模块都可以自定义需要的标志位。这个buffered字段有8位， 最多可以同时表示8个不同的业务。 
	//第三方模块在自定义buffered标志位时注意不要与可能使用的模块定义的标志位冲突。 
	//目前openssl模块定义了一个标志位：#define NGX_SSL_BUFFERED 0x01 
	//HTTP官方模块定义了以下标志位：#define NGX_HTTP_LOWLEVEL_BUFFERED 0xf0 #define NGX_HTTP_WRITE_BUFFERED 0x10 #define NGX_HTTP_GZIP_BUFFERED 0x20 
	//#define NGX_HTTP_SSI_BUFFERED 0x01 #define NGX_HTTP_SUB_BUFFERED 0x02 #define NGX_HTTP_COPY_BUFFERED 0x04 #define NGX_HTTP_IMAGE_BUFFERED 0x08 
	//同时，对于HTTP模块而言，buffered的低4位要慎用，在实际发送响应的ngx_http_write_filter_module过滤模块中，低4位标志位为1则意味着Nginx会一直认为有 
	//HTTP模块还需要处理这个请求， 必须等待HTTP模块将低4位全置为0才会正常结束请求。 检查低4位的宏如下：#define NGX_LOWLEVEL_BUFFERED 0x0f
    unsigned            buffered:8;	

    unsigned            log_error:3;	/* ngx_connection_log_error_e *///本连接记录日志时的级别, 由ngx_connection_log_error_e枚举表示 

    unsigned            timedout:1;		//标志位，为 1时表示连接已超时
    unsigned            error:1;		//表示连接处理(读或写)过程中出现错误
    //(1)标志位，为 1时表示连接已经销毁。这里的连接指的是TCP连接，而不是ngx_connection_t结构体。 
    //当destroyed为 1时，结构体仍然存在，但其对应的套接字、内存池等已经不可用
    //(2)表示连接上承载的request已近销毁(subrequest or main request???)
    unsigned            destroyed:1;	

    unsigned            idle:1;		//标志位，为 1时表示连接处于空闲状态，如keepalive请求中两次请求之间的状态
    //Flag indicating the connection is in a state that makes it eligible for reuse.
    unsigned            reusable:1;	//标志位，为 1时表示连接可重用，它与上面的queue字段是对应使用的
    //Flag indicating that the connection is being reused and needs to be closed.
    unsigned            close:1;	 //标志位，为 1时表示连接关闭
    unsigned            shared:1;	

    unsigned            sendfile:1;		//标志位，为 1时表示正将文件中的数据发往连接的另一端
    //标志位，为 1时表示只有在连接套接字对应的发送缓冲区必须满足最低设置的大小阈值时，事件驱动模块才会分发该事件。 
    //与ngx_handle_write_event函数中的lowat参数是对应的。是否设置该连接的发送低水位标志，若设置过将不再重复设置
    unsigned            sndlowat:1;		
    unsigned            tcp_nodelay:2;	/* ngx_connection_tcp_nodelay_e */	 //标志位，表示如何使用TCP的nodelay特性。 它的取值范围是ngx_connection_tcp_nodelay_e枚举类型
    unsigned            tcp_nopush:2;	/* ngx_connection_tcp_nopush_e */ //标志位，表示如何使用TCP的nopush特性。 它的取值范围是ngx_connection_tcp_nopush_e枚举类型

    unsigned            need_last_buf:1;

#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr, socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_conf_t *cf, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s, ngx_uint_t port);
ngx_int_t ngx_tcp_nodelay(ngx_connection_t *c);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
