
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_VARIABLES_H_INCLUDED_
#define _NGX_HTTP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_variable_value_t  ngx_http_variable_value_t;

#define ngx_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_http_variable_s  ngx_http_variable_t;

typedef void (*ngx_http_set_variable_pt) (ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_http_get_variable_pt) (ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


//Enables redefinition of the variable: there is no conflict if another module defines a variable with the same name. 
//This allows the 'set' directive to override variables.
#define NGX_HTTP_VAR_CHANGEABLE   1		
//Disables caching, which is useful for variables such as $time_local. 
#define NGX_HTTP_VAR_NOCACHEABLE  2		//表示这个变量每次都要去取值，而不是直接返回上次cache的值(配合对应的接口)
//Indicates that this variable is only accessible by index, not by name. 
//This is a small optimization for use when it is known that the variable is not needed in modules like SSI or Perl.
#define NGX_HTTP_VAR_INDEXED      4		//表示这个变量是用索引读取的. //表示这个变量可以用索引进行读取
#define NGX_HTTP_VAR_NOHASH       8		//表示这个变量不需要被hash.
#define NGX_HTTP_VAR_WEAK         16
//The name of the variable is a prefix. 
//In this case, a handler must implement additional logic to obtain the value of a specific variable. 
//For example, all “arg_” variables are processed by the same handler, 
//which performs lookup in request arguments and returns the value of a specific argument.
#define NGX_HTTP_VAR_PREFIX       32	


struct ngx_http_variable_s {
    ngx_str_t                     name;   /* must be first to build the hash */	//对应的变量名字
    ngx_http_set_variable_pt      set_handler;	//The get handler is responsible for evaluating a variable in the context of a specific request,设置变量值的函数
    ngx_http_get_variable_pt      get_handler;	//The set handler allows setting the property referenced by the variable. 读取变量值的函数
    uintptr_t                     data;			//data is passed to variable handlers //传递给set_handler和get_handler的参数
    ngx_uint_t                    flags;		//变量的属性NGX_HTTP_VAR_*
    ngx_uint_t                    index;		//index holds assigned variable index used to reference the variable. //XXX：该变量在 ngx_http_core_main_conf_t.variables 数组中的索引，从而可以迅速定位到对应的变量。
};

#define ngx_http_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }


ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags);
ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_http_variable_value_t *ngx_http_get_indexed_variable(ngx_http_request_t *r, ngx_uint_t index);
ngx_http_variable_value_t *ngx_http_get_flushed_variable(ngx_http_request_t *r, ngx_uint_t index);

ngx_http_variable_value_t *ngx_http_get_variable(ngx_http_request_t *r, ngx_str_t *name, ngx_uint_t key);

ngx_int_t ngx_http_variable_unknown_header(ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part, size_t prefix);


#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_http_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;		//
    ngx_uint_t                    ncaptures;	//Number of capturing subpatterns
    ngx_http_regex_variable_t    *variables;	//变量数组
    ngx_uint_t                    nvariables;	//变量数组元素个数
    ngx_str_t                     name;			//正则表达式字符串 //A zero-terminated string containing the regular expression to be compiled
} ngx_http_regex_t;


typedef struct {
    ngx_http_regex_t             *regex;
    void                         *value;
} ngx_http_map_regex_t;


ngx_http_regex_t *ngx_http_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc);
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_http_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_http_map_t;


void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map, ngx_str_t *match);


ngx_int_t ngx_http_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_http_variables_init_vars(ngx_conf_t *cf);


extern ngx_http_variable_value_t  ngx_http_variable_null_value;
extern ngx_http_variable_value_t  ngx_http_variable_true_value;


#endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
