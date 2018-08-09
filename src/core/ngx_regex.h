
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_REGEX_H_INCLUDED_
#define _NGX_REGEX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <pcre.h>


#define NGX_REGEX_NO_MATCHED  PCRE_ERROR_NOMATCH   /* -1 */

#define NGX_REGEX_CASELESS    PCRE_CASELESS


typedef struct {
    pcre        *code;	//Compiled regular expression
    pcre_extra  *extra;	//Result of pcre[16|32]_study() or NULL
} ngx_regex_t;


typedef struct {
    ngx_str_t     pattern;			//[in] A zero-terminated string containing the regular expression to be compiled
    ngx_pool_t   *pool;				//[in]
    ngx_int_t     options;			//[in]

    ngx_regex_t  *regex;			//[out]
    int           captures;			//[out]	Number of capturing subpatterns  the count of named captures
    int           named_captures;	//[out] Number of named subpatterns  the count of all captures
    int           name_size;		//[out] Size of name table entry
    u_char       *names;			//[out] Pointer to name table
    ngx_str_t     err;				//[out]	存放编译正则表达式发生错误时的错误信息
} ngx_regex_compile_t;


typedef struct {
    ngx_regex_t  *regex;
    u_char       *name;	//A zero-terminated string containing the regular expression to be compiled
} ngx_regex_elt_t;


void ngx_regex_init(void);
ngx_int_t ngx_regex_compile(ngx_regex_compile_t *rc);

#define ngx_regex_exec(re, s, captures, size)                                \
    pcre_exec(re->code, re->extra, (const char *) (s)->data, (s)->len, 0, 0, \
              captures, size)
#define ngx_regex_exec_n      "pcre_exec()"

ngx_int_t ngx_regex_exec_array(ngx_array_t *a, ngx_str_t *s, ngx_log_t *log);


#endif /* _NGX_REGEX_H_INCLUDED_ */
