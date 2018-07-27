
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10
#define NGX_HTTP_MAX_SUBREQUESTS           50

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001
#define NGX_HTTP_VERSION_20                2000

#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_TRACE                     0x8000

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_VERSION     12
#define NGX_HTTP_PARSE_INVALID_09_METHOD   13

#define NGX_HTTP_PARSE_INVALID_HEADER      14


/* unused                                  1 */
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
#define NGX_HTTP_SUBREQUEST_WAITED         4	//表示如果该子请求提前完成(按后续遍历的顺序)，是否设置将它的状态设为done，当设置该参数时，提前完成就会设置done，不设时，会让该子请求等待它之前的子请求处理完毕才会将状态设置为done
#define NGX_HTTP_SUBREQUEST_CLONE          8
#define NGX_HTTP_SUBREQUEST_BACKGROUND     16

#define NGX_HTTP_LOG_UNSAFE                1


#define NGX_HTTP_CONTINUE                  100
#define NGX_HTTP_SWITCHING_PROTOCOLS       101
#define NGX_HTTP_PROCESSING                102

#define NGX_HTTP_OK                        200
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_ACCEPTED                  202
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_TEMPORARY_REDIRECT        307
#define NGX_HTTP_PERMANENT_REDIRECT        308

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416
#define NGX_HTTP_MISDIRECTED_REQUEST       421
#define NGX_HTTP_TOO_MANY_REQUESTS         429


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NGX_HTTP_CLOSE                     444

#define NGX_HTTP_NGINX_CODES               494

#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NGX_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_VERSION_NOT_SUPPORTED     505
#define NGX_HTTP_INSUFFICIENT_STORAGE      507


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NGX_HTTP_WRITE_BUFFERED            0x10
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
    ngx_http_header_handler_pt        handler;
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header_out_t;


typedef struct {
    ngx_list_t                        headers;

    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *if_match;
    ngx_table_elt_t                  *if_none_match;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *te;
    ngx_table_elt_t                  *expect;
    ngx_table_elt_t                  *upgrade;

#if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;

#if (NGX_HTTP_X_FORWARDED_FOR)
    ngx_array_t                       x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *depth;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *overwrite;
    ngx_table_elt_t                  *date;
#endif

    ngx_str_t                         user;
    ngx_str_t                         passwd;

    ngx_array_t                       cookies;

    ngx_str_t                         server;
    off_t                             content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;
    unsigned                          chunked:1;
    unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;


typedef struct {
    ngx_list_t                        headers;		//array of ngx_table_elt_t
    ngx_list_t                        trailers;

    ngx_uint_t                        status;
    ngx_str_t                         status_line;

    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_str_t                        *override_charset;

    size_t                            content_type_len;
    ngx_str_t                         content_type;
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;	//content_type_lowcase对应的散列值

    ngx_array_t                       cache_control;
    ngx_array_t                       link;

    off_t                             content_length_n;
    off_t                             content_offset;
    time_t                            date_time;
    time_t                            last_modified_time;
} ngx_http_headers_out_t;


typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

typedef struct {
    ngx_temp_file_t                  *temp_file;
    ngx_chain_t                      *bufs;
    ngx_buf_t                        *buf;
    off_t                             rest;
    off_t                             received;
    ngx_chain_t                      *free;
    ngx_chain_t                      *busy;
    ngx_http_chunked_t               *chunked;
    ngx_http_client_body_handler_pt   post_handler;
} ngx_http_request_body_t;


typedef struct ngx_http_addr_conf_s  ngx_http_addr_conf_t;

typedef struct {
    ngx_http_addr_conf_t             *addr_conf;
    ngx_http_conf_ctx_t              *conf_ctx;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        *ssl_servername;
#if (NGX_PCRE)
    ngx_http_regex_t                 *ssl_servername_regex;
#endif
#endif

    ngx_chain_t                      *busy;
    ngx_int_t                         nbusy;

    ngx_chain_t                      *free;

    unsigned                          ssl:1;
    unsigned                          proxy_protocol:1;
} ngx_http_connection_t;


typedef void (*ngx_http_cleanup_pt)(void *data);

typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;

struct ngx_http_cleanup_s {
    ngx_http_cleanup_pt               handler;
    void                             *data;
    ngx_http_cleanup_t               *next;
};


typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r, void *data, ngx_int_t rc);

typedef struct {
    ngx_http_post_subrequest_pt       handler;
    void                             *data;
} ngx_http_post_subrequest_t;


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

struct ngx_http_postponed_request_s {
    ngx_http_request_t               *request;	//保存了subrequest
    ngx_chain_t                      *out;		//保存了所需要发送的chain
    ngx_http_postponed_request_t     *next;		//保存了下一个postpone_request. 
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

struct ngx_http_posted_request_s {
    ngx_http_request_t               *request;
    ngx_http_posted_request_t        *next;
};


typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);


struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

	//Pointer to a ngx_connection_t client connection object. 
	//Several requests can reference the same connection object at the same time - one main request and its subrequests. 
	//After a request is deleted, a new request can be created on the same connection.

	//Note that for HTTP connections ngx_connection_t's data field points back to the request. 
	//Such requests are called active, as opposed to the other requests tied to the connection. 
	//An active request is used to handle client connection events and is allowed to output its response to the client. 
	//Normally, each request becomes active at some point so that it can send its output.
    ngx_connection_t                 *connection;

	//Array of HTTP module contexts. 
	//Each module of type NGX_HTTP_MODULE can store any value (normally, a pointer to a structure) in the request. 
	//The value is stored in the ctx array at the module's ctx_index position. 
	//The following macros provide a convenient way to get and set request contexts:
	//		ngx_http_get_module_ctx(r, module) — Returns the module's context
	//		ngx_http_set_ctx(r, c, module) — Sets c as the module's context
    void                            **ctx;
	//main_conf, srv_conf, loc_conf — Arrays of current request configurations. 
	//Configurations are stored at the module's ctx_index positions.
    void                            **main_conf;
    void                            **srv_conf;
    void                            **loc_conf;

	//read_event_handler, write_event_handler - Read and write event handlers for the request. 
	//Normally, both the read and write event handlers for an HTTP connection are set to ngx_http_request_handler(). 
	//This function calls the read_event_handler and write_event_handler handlers for the currently active request.
    ngx_http_event_handler_pt         read_event_handler;
    ngx_http_event_handler_pt         write_event_handler;

#if (NGX_HTTP_CACHE)
	//Request cache object for caching the upstream response.
    ngx_http_cache_t                 *cache;
#endif

	//Request upstream object for proxying.
    ngx_http_upstream_t              *upstream;
    ngx_array_t                      *upstream_states;
                                         /* of ngx_http_upstream_state_t */

	//Request pool. 
	//The request object itself is allocated in this pool, which is destroyed when the request is deleted. 
	//For allocations that need to be available throughout the client connection's lifetime, use ngx_connection_t's pool instead.
    ngx_pool_t                       *pool;
	//Buffer into which the client HTTP request header is read.
    ngx_buf_t                        *header_in;

	//headers_in, headers_out — Input and output HTTP headers objects. 
	//Both objects contain the headers field of type ngx_list_t for keeping the raw list of headers. 
	//In addition to that, specific headers are available for getting and setting as separate fields, 
	//for example content_length_n, status etc.
    ngx_http_headers_in_t             headers_in;
    ngx_http_headers_out_t            headers_out;

	//Client request body object.
    ngx_http_request_body_t          *request_body;

    time_t                            lingering_time;
	//start_sec, start_msec — Time point when the request was created, used for tracking request duration.
    time_t                            start_sec;
    ngx_msec_t                        start_msec;

	//Numeric representation of the client HTTP request method. 
	//Numeric values for methods are defined in src/http/ngx_http_request.h with the macros NGX_HTTP_GET, NGX_HTTP_HEAD, NGX_HTTP_POST, etc.
    ngx_uint_t                        method;
	//Client HTTP protocol version in numeric form (NGX_HTTP_VERSION_10, NGX_HTTP_VERSION_11, etc.).
    ngx_uint_t                        http_version;		

	//Request line in the original client request.
    ngx_str_t                         request_line;		
	//uri, args, exten — URI, arguments and file extension for the current request. 
	//The URI value here might differ from the original URI sent by the client due to normalization. 
	//Throughout request processing, these values can change as internal redirects are performed.
    ngx_str_t                         uri;
    ngx_str_t                         args;
    ngx_str_t                         exten;
	//URI in the original client request
    ngx_str_t                         unparsed_uri;	

	//text representation of the client HTTP request method.
    ngx_str_t                         method_name;
	//Client HTTP protocol version in its original text form (“HTTP/1.0”, “HTTP/1.1” etc).
    ngx_str_t                         http_protocol;	
    ngx_str_t                         schema;

    ngx_chain_t                      *out;
	//Pointer to a main request object. 
	//This object is created to process a client HTTP request, as opposed to subrequests, 
	//which are created to perform a specific subtask within the main request.
    ngx_http_request_t               *main;		
	//Pointer to the parent request of a subrequest.
    ngx_http_request_t               *parent;		
    //List of output buffers and subrequests, in the order in which they are sent and created. 
    //The list is used by the postpone filter to provide consistent request output when parts of it are created by subrequests.
    ngx_http_postponed_request_t     *postponed;	
	//Pointer to a handler with the context to be called when a subrequest gets finalized. Unused for main requests.
	ngx_http_post_subrequest_t       *post_subrequest;	
	//List of requests to be started or resumed, which is done by calling the request's write_event_handler. 
	//Normally, this handler holds the request main function, which at first runs request phases and then produces the output.
	ngx_http_posted_request_t        *posted_requests;	

	//Index of current request phase.
    ngx_int_t                         phase_handler;	
    ngx_http_handler_pt               content_handler;
    ngx_uint_t                        access_code;

    ngx_http_variable_value_t        *variables;	//XXX:缓存所有被索引的变量的值

#if (NGX_PCRE)
	//ncaptures, captures, captures_data — Regex captures produced by the last regex match of the request. 
	//A regex match can occur at a number of places during request processing: map lookup, server lookup 
	//by SNI or HTTP Host, rewrite, proxy_redirect, etc. Captures produced by a lookup are stored in the 
	//above mentioned fields. The field ncaptures holds the number of captures, captures holds captures 
	//boundaries and captures_data holds the string against which the regex was matched and which is used 
	//to extract captures. After each new regex match, request captures are reset to hold new values.
    ngx_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

    size_t                            limit_rate;
    size_t                            limit_rate_after;

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;

    off_t                             request_length;

    ngx_uint_t                        err_status;

    ngx_http_connection_t            *http_connection;
    ngx_http_v2_stream_t             *stream;

    ngx_http_log_handler_pt           log_handler;

    ngx_http_cleanup_t               *cleanup;

	//Request reference counter. 
	//The field only makes sense for the main request. 
	//Increasing the counter is done by simple r->main->count++. 
	//To decrease the counter, call ngx_http_finalize_request(r, rc). 
	//Creating of a subrequest and running the request body read process both increment the counter.
    unsigned                          count:16;		
	//Current subrequest nesting level. 
	//Each subrequest inherits its parent's nesting level, decreased by one. 
	//An error is generated if the value reaches zero. 
	//The value for the main request is defined by the NGX_HTTP_MAX_SUBREQUESTS constant.
    unsigned                          subrequests:8;	
	//Counter of blocks held on the request. 
	//While this value is non-zero, the request cannot be terminated. 
	//Currently, this value is increased by pending AIO operations (POSIX AIO and thread operations) and active cache lock.
    unsigned                          blocked:8;		

    unsigned                          aio:1;	//表示当前是否在进行aio操作

    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with " " */
    unsigned                          space_in_uri:1;

    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;
    unsigned                          uri_changed:1;
	//Number of URI changes remaining for the request. 
	//The total number of times a request can change its URI is limited by the NGX_HTTP_MAX_URI_CHANGES constant. 
	//With each change the value is decremented until it reaches zero, at which time an error is generated. 
	//Rewrites and internal redirects to normal or named locations are considered URI changes.
    unsigned                          uri_changes:4;		

    unsigned                          request_body_in_single_buf:1;
    unsigned                          request_body_in_file_only:1;
    unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;
    unsigned                          request_body_no_buffering:1;

	//Output is not sent to the client, but rather stored in memory. 
	//The flag only affects subrequests which are processed by one of the proxying modules. 
	//After a subrequest is finalized its output is available in a r->upstream->buffer of type ngx_buf_t.
    unsigned                          subrequest_in_memory:1;	
    unsigned                          waited:1;

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;
    unsigned                          gzip_ok:1;
    unsigned                          gzip_vary:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * ngx_http_limit_conn_module and ngx_http_limit_req_module
     * we use the single bits in the request structure
     */
    unsigned                          limit_conn_set:1;
    unsigned                          limit_req_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;
    unsigned                          chunked:1;
	//Flag indicating that the output does not require a body. For example, this flag is used by HTTP HEAD requests.
    unsigned                          header_only:1;		
    unsigned                          expect_trailers:1;
	//Flag indicating whether client connection keepalive is supported. 
	//The value is inferred from the HTTP version and the value of the “Connection” header.
    unsigned                          keepalive:1;			
    unsigned                          lingering_close:1;
    unsigned                          discard_body:1;
    unsigned                          reading_body:1;
    unsigned                          internal:1;			//Flag indicating that the current request is internal. To enter the internal state, a request must pass through an internal redirect or be a subrequest. Internal requests are allowed to enter internal locations.
    unsigned                          error_page:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;
    unsigned                          header_sent:1;		//Flag indicating that the output header has already been sent by the request.
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;

    unsigned                          buffered:4;	//Bitmask showing which modules have buffered the output produced by the request. A number of filters can buffer output; for example, sub_filter can buffer data because of a partial string match, copy filter can buffer data because of the lack of free output buffers etc. As long as this value is non-zero, the request is not finalized pending the flush.

	//main_filter_need_in_memory, filter_need_in_memory — Flags requesting that the output produced in memory buffers rather than files. 
	//This is a signal to the copy filter to read data from file buffers even if sendfile is enabled. 
	//The difference between the two flags is the location of the filter modules that set them. 
	//Filters called before the postpone filter in the filter chain set filter_need_in_memory, 
	//requesting that only the current request output come in memory buffers. 
	//Filters called later in the filter chain set main_filter_need_in_memory, 
	//requesting that both the main request and all subrequests read files in memory while sending output.
    unsigned                          main_filter_need_in_memory:1;	
    unsigned                          filter_need_in_memory:1;		
	//Flag requesting that the request output be produced in temporary buffers, but not in readonly memory buffers or file buffers. This is used by filters which may change output directly in the buffers where it's sent.
	unsigned                          filter_need_temporary:1;		
    unsigned                          preserve_body:1;
	//Flag indicating that a partial response can be sent to the client, as requested by the HTTP Range header.
    unsigned                          allow_ranges:1;				
	//Flag indicating that a partial response can be sent while a subrequest is being processed.
	unsigned                          subrequest_ranges:1;			
	//Flag indicating that only a single continuous range of output data can be sent to the client. 
	//This flag is usually set when sending a stream of data, 
	//for example from a proxied server, and the entire response is not available in one buffer.
	unsigned                          single_range:1;				
    unsigned                          disable_not_modified:1;
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
    unsigned                          stat_processing:1;

    unsigned                          background:1;
    unsigned                          health_check:1;

    /* used to parse HTTP headers */

    ngx_uint_t                        state;

    ngx_uint_t                        header_hash;
    ngx_uint_t                        lowcase_index;
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char                           *header_name_start;
    u_char                           *header_name_end;
    u_char                           *header_start;
    u_char                           *header_end;

    /*
     * a memory that can be reused after parsing a request line
     * via ngx_http_ephemeral_t
     */

    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;

	//http_major, http_minor  — Client HTTP protocol version in numeric form split into major and minor parts.
    unsigned                          http_minor:16;	
    unsigned                          http_major:16;	
};


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
} ngx_http_ephemeral_t;


#define ngx_http_ephemeral(r)  (void *) (&r->uri_start)


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#define ngx_http_set_log_request(log, r)                                      \
    ((ngx_http_log_ctx_t *) log->data)->current_request = r


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
