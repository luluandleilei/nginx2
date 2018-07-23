
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#elif (NGX_COMPAT)
typedef struct ngx_thread_pool_s  ngx_thread_pool_t;
#endif


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_THREADS            2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


#define NGX_HTTP_SERVER_TOKENS_OFF      0
#define NGX_HTTP_SERVER_TOKENS_ON       1
#define NGX_HTTP_SERVER_TOKENS_BUILD    2


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


typedef struct {
    ngx_sockaddr_t             sockaddr;
    socklen_t                  socklen;

    unsigned                   set:1;					//设置了套接字相关的选项
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;				//XXX: wildcard address ??
    unsigned                   ssl:1;
    unsigned                   http2:1;	
#if (NGX_HAVE_INET6)
	//this parameter (0.7.42) determines (via the IPV6_V6ONLY socket option) whether an IPv6 socket listening on a wildcard address [::] will accept only IPv6 connections or both IPv6 and IPv4 connections. 
	//This parameter is turned on by default. It can only be set once on start.
	//Prior to version 1.3.4, if this parameter was omitted then the operating system’s settings were in effect for the socket.
    unsigned                   ipv6only:1;
#endif
	//instructs to use a deferred accept() (the TCP_DEFER_ACCEPT socket option) on Linux.
    unsigned                   deferred_accept:1;
	//this parameter (1.9.1) instructs to create an individual listening socket for each worker process (using the SO_REUSEPORT socket option on Linux 3.9+ and DragonFly BSD, or SO_REUSEPORT_LB on FreeBSD 12+), allowing a kernel to distribute incoming connections between worker processes. 
	//This currently works only on Linux 3.9+, DragonFly BSD, and FreeBSD 12+ (1.15.1).
	//Inappropriate use of this option may have its security implications.	//XXX: ??
    unsigned                   reuseport:1;
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

	//sets the backlog parameter in the listen() call that limits the maximum length for the queue of pending connections. 
	//By default, backlog is set to -1 on FreeBSD, DragonFly BSD, and macOS, and to 511 on other platforms.
    int                        backlog;		
	//sets the receive buffer size (the SO_RCVBUF option) for the listening socket.
	int                        rcvbuf;	
	//the send buffer size (the SO_SNDBUF option) for the listening socket.
    int                        sndbuf;		
#if (NGX_HAVE_SETFIB)
	//this parameter (0.8.44) sets the associated routing table, FIB (the SO_SETFIB option) for the listening socket. 
	//This currently works only on FreeBSD.	//XXX ??
    int                        setfib;		
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
	//enables “TCP Fast Open” for the listening socket and limits the maximum length for the queue of connections that have not yet completed the three-way handshake.
	//Do not enable this feature unless the server can handle receiving the same SYN packet with data more than once.//XXX ??
    int                        fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
	//sets the name of accept filter (the SO_ACCEPTFILTER option) for the listening socket that filters incoming connections before passing them to accept(). 
	//This works only on FreeBSD and NetBSD 5.0+. Possible values are dataready and httpready.
    char                      *accept_filter;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];	//sockaddr的字符串表示形式
} ngx_http_listen_opt_t;


typedef enum {
    NGX_HTTP_POST_READ_PHASE = 0,

    NGX_HTTP_SERVER_REWRITE_PHASE,

    NGX_HTTP_FIND_CONFIG_PHASE,
    NGX_HTTP_REWRITE_PHASE,
    NGX_HTTP_POST_REWRITE_PHASE,

    NGX_HTTP_PREACCESS_PHASE,

    NGX_HTTP_ACCESS_PHASE,
    NGX_HTTP_POST_ACCESS_PHASE,

    NGX_HTTP_PRECONTENT_PHASE,

    NGX_HTTP_CONTENT_PHASE,

    NGX_HTTP_LOG_PHASE
} ngx_http_phases;

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

struct ngx_http_phase_handler_s {
    ngx_http_phase_handler_pt  checker;
    ngx_http_handler_pt        handler;
    ngx_uint_t                 next;
};


typedef struct {
    ngx_http_phase_handler_t  *handlers;
    ngx_uint_t                 server_rewrite_index;
    ngx_uint_t                 location_rewrite_index;
} ngx_http_phase_engine_t;


typedef struct {
    ngx_array_t                handlers;
} ngx_http_phase_t;


typedef struct {
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */ 	//

    ngx_http_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;	//XXX: 将ngx_http_headers_in构造的散列表

    ngx_hash_t                 variables_hash;	//存储被散列的变量的散列表

    ngx_array_t                variables;         /* ngx_http_variable_t */		//XXX:记录实际被引用的变量 //存储索引过的变量的数组
    ngx_array_t                prefix_variables;  /* ngx_http_variable_t */		//存储前缀匹配的变量的数组
    ngx_uint_t                 ncaptures;		  //XXX: max number of capturing subpatterns of server_name

    ngx_uint_t                 server_names_hash_max_size;		//the maximum size of the server names hash tables
    ngx_uint_t                 server_names_hash_bucket_size;	//the bucket size for the server names hash tables

    ngx_uint_t                 variables_hash_max_size;		//the maximum size of the variables hash table. 
    ngx_uint_t                 variables_hash_bucket_size;	//the bucket size for the variables hash table

    ngx_hash_keys_arrays_t    *variables_keys;	//缓存各个模块定义的变量(由于nginx的hash需要一次提供所有hash节点来构建hash表)

    ngx_array_t               *ports;	//array of ngx_http_conf_port_t //保存http{}配置块下监听的所有ngx_http_conf_port_t地址

    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t;


typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    ngx_http_conf_ctx_t        *ctx;	//指向当前server块所属的ngx_http_conf_ctx_t结构体

    u_char                     *file_name;	//
    ngx_uint_t                  line;

    ngx_str_t                   server_name;	//当前server块的虚拟主机名，如果存在的话，则会与HTTP请求中的Host头部做匹配，匹配上后由当前ngx_http_core_srv_conf_t处理请求

    size_t                      connection_pool_size;	//Allows accurate tuning of per-connection memory allocations.
    size_t                      request_pool_size;		//Allows accurate tuning of per-request memory allocations. 
    size_t                      client_header_buffer_size;		//Sets buffer size for reading client request header. 

    ngx_bufs_t                  large_client_header_buffers;	//Sets the maximum number and size of buffers used for reading large client request header.

    ngx_msec_t                  client_header_timeout;	//Defines a timeout for reading client request header. 

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;	//Enables or disables the use of underscores in client request header fields.

    unsigned                    listen:1;	//表示当前server配置块下有listen配置项
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
} ngx_http_server_name_t;


typedef struct {
    ngx_hash_combined_t        names;

    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
} ngx_http_virtual_names_t;


struct ngx_http_addr_conf_s {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;	 //ip地址（网络字节序）
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;	//XXX: addrs中元素个数
} ngx_http_port_t;


typedef struct {
    ngx_int_t                  family;	  //socket协议族
    in_port_t                  port;	  //监听端口
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t;


typedef struct {
    ngx_http_listen_opt_t      opt;		//监听套接字的各种属性

    ngx_hash_t                 hash;	//完全匹配server_name的散列表
    ngx_hash_wildcard_t       *wc_head;	//通配符前置的server_name的散列表
    ngx_hash_wildcard_t       *wc_tail;	//通配符后置的server_name的散列表

#if (NGX_PCRE)
    ngx_uint_t                 nregex;	//正则匹配的server_name的数组中元素个数
    ngx_http_server_name_t    *regex;	//正则匹配的server_name的数组
#endif
    
    ngx_http_core_srv_conf_t  *default_server;	/* the default server configuration for this address:port */
    ngx_array_t                servers;  		/* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;
    ngx_str_t                  args;
} ngx_http_err_page_t;


struct ngx_http_core_loc_conf_s {
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;			//XXX:the named location

    unsigned      exact_match:1;	//XXX:the exact location
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
    unsigned      gzip_disable_degradation:2;
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;		//指向所属location块内ngx_http_conf_ctx_t结构体中的loc_conf指针数组，它保存着当前location块内所有HTTP模块create_loc_conf方法产生的结构体指针

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */	//Sets buffer size for reading client request body.
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */
    size_t        subrequest_output_buffer_size;
                                           /* subrequest_output_buffer_size */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */	//Sets the maximum number of requests that can be served through one keep-alive connection
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer; /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
    ngx_flag_t    aio;                     /* aio */
    ngx_flag_t    aio_write;               /* aio_write */
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    absolute_redirect;       /* absolute_redirect */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_uint_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    ngx_flag_t    etag;                    /* etag */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_pool_t         *thread_pool;
    ngx_http_complex_value_t  *thread_pool_value;
#endif

#if (NGX_HAVE_OPENAT)
    ngx_uint_t    disable_symlinks;        /* disable_symlinks */
    ngx_http_complex_value_t  *disable_symlinks_from;
#endif

    ngx_array_t  *error_pages;             /* error_page */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */ //a directory for storing temporary files holding client request bodies

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;		//Sets the maximum size of the types hash tables.
    ngx_uint_t    types_hash_bucket_size;	//Sets the bucket size for the types hash tables.

    ngx_queue_t  *locations;	//将同一个server块内多个表达location块的ngx_http_core_loc_conf_t结构体以双向链表方式组织起来，该location指针指向ngx_http_location_queue_t结构体	//属于当前块的所有location块通过ngx_http_location_queue_t结构体构成的双向链表

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    ngx_queue_t                      queue;		//XXX:ngx_http_location_queue_t类型双向链表头节点(父location）或 ngx_http_location_queue_t类型双向链表的子节点(子location)
    ngx_http_core_loc_conf_t        *exact;		//如果子location中的字符串可以精确匹配(包括正则表达式)，exect将指向对应的ngx_http_core_loc_conf_t结构体(子location)，否则值为NULL
    ngx_http_core_loc_conf_t        *inclusive;	//如果子location中的字符串无法精确匹配(包括自定义的通配符)，inclusive将指向对应的ngx_http_core_loc_conf_t结构体(子location)，否则值为NULL
    ngx_str_t                       *name;		//XXX: pointer to location name(子location)//指向location(子location)的名称
    u_char                          *file_name;	//XXX：子location的命令对应的配置文件(子location)
    ngx_uint_t                       line;		//XXX: 子location的命令对应的配置文件的行号(子location)
    ngx_queue_t                      list;		//
} ngx_http_location_queue_t;


struct ngx_http_location_tree_node_s {
    ngx_http_location_tree_node_t   *left;
    ngx_http_location_tree_node_t   *right;
    ngx_http_location_tree_node_t   *tree;

    ngx_http_core_loc_conf_t        *exact;
    ngx_http_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_set_etag(ngx_http_request_t *r);
void ngx_http_weak_etag(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **sr,
    ngx_http_post_subrequest_t *psr, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt) (ngx_http_request_t *r, ngx_chain_t *chain);
typedef ngx_int_t (*ngx_http_request_body_filter_pt) (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r,
    ngx_chain_t *chain);


ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);

ngx_int_t ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
    ngx_array_t *headers, ngx_str_t *value, ngx_array_t *proxies,
    int recursive);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

#define ngx_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
