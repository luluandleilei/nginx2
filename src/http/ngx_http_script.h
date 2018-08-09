
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_SCRIPT_H_INCLUDED_
#define _NGX_HTTP_SCRIPT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    u_char                     *ip;		//指向待执行的脚本命令
    u_char                     *pos;	//pos之前的数据就是解析成功的，后面的数据将追加到pos后面
    ngx_http_variable_value_t  *sp;		//变量值构成的栈， 默认大小为10个变量值

    ngx_str_t                   buf; 	//存放结果，也就是buffer，pos指向其中。
    ngx_str_t                   line;	//记录请求行URI      e->line = r->uri;

    /* the start of the rewritten arguments */
    u_char                     *args;

    unsigned                    flushed:1;
    unsigned                    skip:1;
    unsigned                    quote:1;
    unsigned                    is_args:1;
    unsigned                    log:1;

    ngx_int_t                   status;		//脚本引擎执行状态
    ngx_http_request_t         *request;	//指向当前脚本引擎所属的HTTP请求
} ngx_http_script_engine_t;


typedef struct {
    ngx_conf_t                 *cf;			//[in]
    ngx_str_t                  *source;		//[in]

    ngx_array_t               **flushes;	//记录需要nocache的变量
    ngx_array_t               **lengths;	//[out]记录执行对应指令后结果长度会改变多少
    ngx_array_t               **values;		//[out]

    ngx_uint_t                  variables;	//[in]可能的变量个数，用于预估内部空间分配的大小，[out]返回实际的变量个数
    ngx_uint_t                  ncaptures;	//[out]	
    ngx_uint_t                  captures_mask;	//[out] XXX:记录正则匹配的索引
    ngx_uint_t                  size;

    void                       *main;		//[out]

    unsigned                    compile_args:1;		//XXX:表示编译参数，当不编译参数时将当做普通字符对待
    unsigned                    complete_lengths:1;
    unsigned                    complete_values:1;
    unsigned                    zero:1;				//[in]末尾添加'\0'
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;

    unsigned                    dup_capture:1;		//[out]XXX:
    unsigned                    args:1;				//[out]XXX:表示含有参数
} ngx_http_script_compile_t;


typedef struct {
    ngx_str_t                   value;
    ngx_uint_t                 *flushes;
    void                       *lengths;	//cv.lengths contains information about the presence of variables in the expression. The NULL value means that the expression contained static text only, and so can be stored in a simple string rather than as a complex value.
    void                       *values;
} ngx_http_complex_value_t;


typedef struct {
    ngx_conf_t                 *cf;				//[in]Configuration pointer
    ngx_str_t                  *value;			//[in]String to be parsed
    ngx_http_complex_value_t   *complex_value;	//[out]Compiled value

	//[in]Flag that enables zero-terminating value. 
	//It is useful when results are to be passed to libraries that require zero-terminated strings.
    unsigned                    zero:1;			
	//[in]Prefixes the result with the configuration prefix (the directory where nginx is currently looking for configuration). 
	//Prefixes are handy when dealing with filenames.
	unsigned                    conf_prefix:1;	
	//[in]Prefixes the result with the root prefix (the normal nginx installation prefix). 
	//Prefixes are handy when dealing with filenames.
	unsigned                    root_prefix:1;	
} ngx_http_compile_complex_value_t;


typedef void (*ngx_http_script_code_pt) (ngx_http_script_engine_t *e);
typedef size_t (*ngx_http_script_len_code_pt) (ngx_http_script_engine_t *e);


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   len;
} ngx_http_script_copy_code_t;


typedef struct {
    ngx_http_script_code_pt     code;	//ngx_http_script_var_code
    uintptr_t                   index;	//变量的索引
} ngx_http_script_var_code_t;


typedef struct {
    ngx_http_script_code_pt     code;		//ngx_http_script_var_set_handler_code
    ngx_http_set_variable_pt    handler;
    uintptr_t                   data;
} ngx_http_script_var_handler_code_t;


typedef struct {
    ngx_http_script_code_pt     code;	//ngx_http_script_copy_capture_code 
    uintptr_t                   n;
} ngx_http_script_copy_capture_code_t;


#if (NGX_PCRE)

typedef struct {
    ngx_http_script_code_pt     code;
    ngx_http_regex_t           *regex;
    ngx_array_t                *lengths;
    uintptr_t                   size;
    uintptr_t                   status;
    uintptr_t                   next;

    unsigned                    test:1;
    unsigned                    negative_test:1;
    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;

    unsigned                    redirect:1;
    unsigned                    break_cycle:1;

    ngx_str_t                   name;
} ngx_http_script_regex_code_t;


typedef struct {
    ngx_http_script_code_pt     code;

    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;

    unsigned                    redirect:1;
} ngx_http_script_regex_end_code_t;

#endif


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   conf_prefix;
} ngx_http_script_full_name_code_t;


typedef struct {
    ngx_http_script_code_pt     code;	//ngx_http_script_return_code
    uintptr_t                   status;
    ngx_http_complex_value_t    text;
} ngx_http_script_return_code_t;


typedef enum {
    ngx_http_script_file_plain = 0,
    ngx_http_script_file_not_plain,
    ngx_http_script_file_dir,
    ngx_http_script_file_not_dir,
    ngx_http_script_file_exists,
    ngx_http_script_file_not_exists,
    ngx_http_script_file_exec,
    ngx_http_script_file_not_exec
} ngx_http_script_file_op_e;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   op;
} ngx_http_script_file_code_t;


typedef struct {
    ngx_http_script_code_pt     code;		//ngx_http_script_if_code
    uintptr_t                   next;		//if判断条件为假时，指令指针相对跳转的偏移量
    void                      **loc_conf;	//if判断条件为真时，更新当前request的loc为此loc_conf
} ngx_http_script_if_code_t;


typedef struct {
    ngx_http_script_code_pt     code;		//ngx_http_script_complex_value_code
    ngx_array_t                *lengths;
} ngx_http_script_complex_value_code_t;


typedef struct {
    ngx_http_script_code_pt     code;		//ngx_http_script_value_code
    uintptr_t                   value;
    uintptr_t                   text_len;
    uintptr_t                   text_data;
} ngx_http_script_value_code_t;


void ngx_http_script_flush_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *val);
ngx_int_t ngx_http_complex_value(ngx_http_request_t *r, ngx_http_complex_value_t *val, ngx_str_t *value);
ngx_int_t ngx_http_compile_complex_value(ngx_http_compile_complex_value_t *ccv);
char *ngx_http_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_int_t ngx_http_test_predicates(ngx_http_request_t *r,
    ngx_array_t *predicates);
char *ngx_http_set_predicate_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

ngx_uint_t ngx_http_script_variables_count(ngx_str_t *value);
ngx_int_t ngx_http_script_compile(ngx_http_script_compile_t *sc);
u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void ngx_http_script_flush_no_cacheable_variables(ngx_http_request_t *r,
    ngx_array_t *indices);

void *ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes,
    size_t size);
void *ngx_http_script_add_code(ngx_array_t *codes, size_t size, void *code);

size_t ngx_http_script_copy_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_var_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_var_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_mark_args_code(ngx_http_script_engine_t *e);
void ngx_http_script_start_args_code(ngx_http_script_engine_t *e);
#if (NGX_PCRE)
void ngx_http_script_regex_start_code(ngx_http_script_engine_t *e);
void ngx_http_script_regex_end_code(ngx_http_script_engine_t *e);
#endif
void ngx_http_script_return_code(ngx_http_script_engine_t *e);
void ngx_http_script_break_code(ngx_http_script_engine_t *e);
void ngx_http_script_if_code(ngx_http_script_engine_t *e);
void ngx_http_script_equal_code(ngx_http_script_engine_t *e);
void ngx_http_script_not_equal_code(ngx_http_script_engine_t *e);
void ngx_http_script_file_code(ngx_http_script_engine_t *e);
void ngx_http_script_complex_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_set_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_set_handler_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_nop_code(ngx_http_script_engine_t *e);


#endif /* _NGX_HTTP_SCRIPT_H_INCLUDED_ */
