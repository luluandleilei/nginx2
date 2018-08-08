
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STRING_H_INCLUDED_
#define _NGX_STRING_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
通过长度来表示字符串长度，减少计算字符串长度的次数
可以重复引用一段字符串内存，data可以指向任意内存，长度表示结束， 而不用去copy一份自己的字符串 (因为如果要以’\0’结束，而不能更改原字符串，所以势必要copy一段字符串)
正是基于此特性，在nginx中，必须谨慎的去修改一个字符串。在修改字符串时需要认真的去考虑：是否可以修改该字符串；字符串修改后，是否会对其它的引用造成影响。
*/
typedef struct {
    size_t      len;
    u_char     *data;	//指向字符串数据的第一个字符，字符串的结束用长度来表示，而不是由’\0’来表示结束。
} ngx_str_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
} ngx_keyval_t;


typedef struct {
    unsigned    len:28;			//The length of the value //变量值必须是一段连续内存中的字符串，值的长度就是len成员

    unsigned    valid:1;		//The value is valid //为1时表示当前这个变量值已经解析过，且数据是可用的
    unsigned    no_cacheable:1;	//Do not cache result	//为1时表示变量不可悲缓存，它与ngx_http_variable_t结构体flags成员里的NGX_HTTP_VAR_NOCACHEABLE标志位是相关的， 即设置这个标志位后no_cacheable就会为1
	//The variable was not found and thus the data and len fields are irrelevant;
	//this can happen, for example, with variables like $arg_foo when a corresponding argument was not passed in a request
	unsigned    not_found:1;	 //为1表示当前这个变量值已经解析过了，但没有解析到相应的值
    unsigned    escape:1;		//Used internally by the logging module to mark values that require escaping on output. //仅由ngx_http_log_module模块使用， 用于日志格式的字符转义， 其他模块通常忽略这个字段

    u_char     *data;			//The value itself //指向变量值所在内存的起始地址， 与len成员配合使用
} ngx_variable_value_t;


#define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }	//将一个以’\0’结尾的常量字符串str构造一个nginx的字符串
#define ngx_null_string     { 0, NULL }							//构造一个nginx的空字符串，一般用于初始化
#define ngx_str_set(str, text)                                               \	//设置字符串str为常量字符串text
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL	//设置字符串str为空串


#define ngx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define ngx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

void ngx_strlow(u_char *dst, u_char *src, size_t n);	//将src的前n个字符转换成小写存放在dst字符串当中，调用者需要保证dst指向的空间大于等于n，且指向的空间必须可写。


#define ngx_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)	//区分大小写的字符串比较，只比较前n个字符。


/* msvc and icc7 compile strcmp() to inline loop */
#define ngx_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)	//区分大小写的不带长度的字符串比较。


#define ngx_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
#define ngx_strlen(s)       strlen((const char *) s)

size_t ngx_strnlen(u_char *p, size_t n);

#define ngx_strchr(s1, c)   strchr((const char *) s1, (int) c)

static ngx_inline u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {

        if (*p == c) {
            return p;
        }

        p++;
    }

    return NULL;
}


/*
 * msvc and icc7 compile memset() to the inline "rep stos"
 * while ZeroMemory() and bzero() are the calls.
 * icc7 may also inline several mov's of a zeroed register for small blocks.
 */
#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)
#define ngx_memset(buf, c, n)     (void) memset(buf, c, n)


#if (NGX_MEMCPY_LIMIT)

void *ngx_memcpy(void *dst, const void *src, size_t n);
#define ngx_cpymem(dst, src, n)   (((u_char *) ngx_memcpy(dst, src, n)) + (n))

#else

/*
 * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
 * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
 * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
 */
#define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#endif


#if ( __INTEL_COMPILER >= 800 )

/*
 * the simple inline cycle copies the variable length strings up to 16
 * bytes faster than icc8 autodetecting _intel_fast_memcpy()
 */

static ngx_inline u_char *
ngx_copy(u_char *dst, u_char *src, size_t len)
{
    if (len < 17) {

        while (len) {
            *dst++ = *src++;
            len--;
        }

        return dst;

    } else {
        return ngx_cpymem(dst, src, len);
    }
}

#else

#define ngx_copy                  ngx_cpymem

#endif


#define ngx_memmove(dst, src, n)   (void) memmove(dst, src, n)
#define ngx_movemem(dst, src, n)   (((u_char *) memmove(dst, src, n)) + (n))


/* msvc and icc7 compile memcmp() to the inline loop */
#define ngx_memcmp(s1, s2, n)  memcmp((const char *) s1, (const char *) s2, n)


u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n);
u_char *ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *src);
u_char * ngx_cdecl ngx_sprintf(u_char *buf, const char *fmt, ...);					//用于字符串格式化，
u_char * ngx_cdecl ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...);	//用于字符串格式化，参数max指明buf的空间大小
u_char * ngx_cdecl ngx_slprintf(u_char *buf, u_char *last, const char *fmt,			//用于字符串格式化，参数last指明buf的空间大小
    ...);
u_char *ngx_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
#define ngx_vsnprintf(buf, max, fmt, args)                                   \
    ngx_vslprintf(buf, buf + (max), fmt, args)

ngx_int_t ngx_strcasecmp(u_char *s1, u_char *s2);					//区分大小写的不带长度的字符串比较
ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n);		//不区分大小写的带长度的字符串比较，只比较前n个字符。

u_char *ngx_strnstr(u_char *s1, char *s2, size_t n);

u_char *ngx_strstrn(u_char *s1, char *s2, size_t n);
u_char *ngx_strcasestrn(u_char *s1, char *s2, size_t n);
u_char *ngx_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);

ngx_int_t ngx_rstrncmp(u_char *s1, u_char *s2, size_t n);
ngx_int_t ngx_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
ngx_int_t ngx_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
ngx_int_t ngx_dns_strcmp(u_char *s1, u_char *s2);
ngx_int_t ngx_filename_cmp(u_char *s1, u_char *s2, size_t n);

ngx_int_t ngx_atoi(u_char *line, size_t n);
ngx_int_t ngx_atofp(u_char *line, size_t n, size_t point);
ssize_t ngx_atosz(u_char *line, size_t n);
off_t ngx_atoof(u_char *line, size_t n);
time_t ngx_atotm(u_char *line, size_t n);
ngx_int_t ngx_hextoi(u_char *line, size_t n);

u_char *ngx_hex_dump(u_char *dst, u_char *src, size_t len);


#define ngx_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define ngx_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src);	
void ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src);
ngx_int_t ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src);			
ngx_int_t ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src);

uint32_t ngx_utf8_decode(u_char **p, size_t n);
size_t ngx_utf8_length(u_char *p, size_t n);
u_char *ngx_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len);


#define NGX_ESCAPE_URI            0
#define NGX_ESCAPE_ARGS           1
#define NGX_ESCAPE_URI_COMPONENT  2
#define NGX_ESCAPE_HTML           3
#define NGX_ESCAPE_REFRESH        4
#define NGX_ESCAPE_MEMCACHED      5
#define NGX_ESCAPE_MAIL_AUTH      6

#define NGX_UNESCAPE_URI       1	//遇到’?’后就结束,遇到的需要转码的字符，都会转码
#define NGX_UNESCAPE_REDIRECT  2	//遇到’?’后就结束,只对非可见字符进行转码

uintptr_t ngx_escape_uri(u_char *dst, u_char *src, size_t size,							
    ngx_uint_t type);
void ngx_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type);
uintptr_t ngx_escape_html(u_char *dst, u_char *src, size_t size);
uintptr_t ngx_escape_json(u_char *dst, u_char *src, size_t size);


typedef struct {
    ngx_rbtree_node_t         node;
    ngx_str_t                 str;
} ngx_str_node_t;


void ngx_str_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
ngx_str_node_t *ngx_str_rbtree_lookup(ngx_rbtree_t *rbtree, ngx_str_t *name,
    uint32_t hash);


void ngx_sort(void *base, size_t n, size_t size,
    ngx_int_t (*cmp)(const void *, const void *));
#define ngx_qsort             qsort


#define ngx_value_helper(n)   #n
#define ngx_value(n)          ngx_value_helper(n)


#endif /* _NGX_STRING_H_INCLUDED_ */
