
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)
#define NGX_INET6_ADDRSTRLEN                                                 \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define NGX_UNIX_ADDRSTRLEN                                                  \
    (sizeof("unix:") - 1 +                                                   \
     sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#if (NGX_HAVE_UNIX_DOMAIN)
#define NGX_SOCKADDR_STRLEN   NGX_UNIX_ADDRSTRLEN
#elif (NGX_HAVE_INET6)
#define NGX_SOCKADDR_STRLEN   (NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
#else
#define NGX_SOCKADDR_STRLEN   (NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1)
#endif

/* compatibility */
#define NGX_SOCKADDRLEN       sizeof(ngx_sockaddr_t)


typedef union {
    struct sockaddr           sockaddr;		//通用的socket地址结构
    struct sockaddr_in        sockaddr_in;	//IPv4的socket地址结构
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       sockaddr_in6;	//IPv6的socket地址结构
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un        sockaddr_un;	//unix域的socket地址结构
#endif
} ngx_sockaddr_t;


typedef struct {
    in_addr_t                 addr;
    in_addr_t                 mask;
} ngx_in_cidr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr           addr;
    struct in6_addr           mask;
} ngx_in6_cidr_t;

#endif


typedef struct {
    ngx_uint_t                family;
    union {
        ngx_in_cidr_t         in;
#if (NGX_HAVE_INET6)
        ngx_in6_cidr_t        in6;
#endif
    } u;
} ngx_cidr_t;


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    ngx_str_t                 name;		//"ip:port"字符串表示
} ngx_addr_t;


typedef struct {
    ngx_str_t                 url;			//[in]需要被解析的url
    ngx_str_t                 host;			//[out]
    ngx_str_t                 port_text;
    ngx_str_t                 uri;			//[out]uri

    in_port_t                 port;			//[out]
    in_port_t                 default_port;	//[in]默认端口
    int                       family;		//[out]协议族

    unsigned                  listen:1;		//[in]XXX:用于对listen配置的解析
    unsigned                  uri_part:1;	//[in]XXX:包含uri部分
    unsigned                  no_resolve:1;	//[in]不对域名进行解析

    unsigned                  no_port:1;	//[out]
    unsigned                  wildcard:1;	//[out]未指定ip地址，INADDR_ANY

    socklen_t                 socklen;
    ngx_sockaddr_t            sockaddr;

    ngx_addr_t               *addrs;		//[out]
    ngx_uint_t                naddrs;		//[out]

    char                     *err;			//解析
} ngx_url_t;


in_addr_t ngx_inet_addr(u_char *text, size_t len);
#if (NGX_HAVE_INET6)
ngx_int_t ngx_inet6_addr(u_char *p, size_t len, u_char *addr);
size_t ngx_inet6_ntop(u_char *p, u_char *text, size_t len);
#endif
size_t ngx_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text, size_t len, ngx_uint_t port);
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);
ngx_int_t ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr);
ngx_int_t ngx_cidr_match(struct sockaddr *sa, ngx_array_t *cidrs);
ngx_int_t ngx_parse_addr(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text,
    size_t len);
ngx_int_t ngx_parse_addr_port(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text, size_t len);
ngx_int_t ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1, struct sockaddr *sa2, socklen_t slen2, ngx_uint_t cmp_port);
in_port_t ngx_inet_get_port(struct sockaddr *sa);
void ngx_inet_set_port(struct sockaddr *sa, in_port_t port);


#endif /* _NGX_INET_H_INCLUDED_ */
