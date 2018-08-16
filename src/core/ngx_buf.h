
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;


//该结构实际上是一种抽象的数据结构，它代表某种具体的数据。这个数据可能是指向内存中的某个缓冲区，也可能
//指向一个文件的某一部分，也可能是一些纯元数据（元数据的作用在于指示这个链表的读取者对读取的数据进行不同的处理）。
/*
For input/output operations, nginx provides the buffer type ngx_buf_t. 
Normally, it's used to hold data to be written to a destination or read from a source. 
A buffer can reference data in memory or in a file and it's technically possible for a buffer to reference both at the same time. 
Memory for the buffer is allocated separately and is not related to the buffer structure ngx_buf_t.
*/
struct ngx_buf_s {
	//pos, last — The boundaries of the memory buffer; normally a subrange of start .. end.
    u_char          *pos;		//当buf所指向的数据在内存里的时候，pos指向的是这段数据开始的位置。
    u_char          *last;		//当buf所指向的数据在内存里的时候，last指向的是这段数据结束的位置。
	//file_pos, file_last — The boundaries of a file buffer, expressed as offsets from the beginning of the file.
	off_t            file_pos;	//当buf所指向的数据是在文件里的时候，file_pos指向的是这段数据的开始位置在文件中的偏移量。
    off_t            file_last;	//当buf所指向的数据是在文件里的时候，file_last指向的是这段数据的结束位置在文件中的偏移量

	//The boundaries of the memory block allocated for the buffer.
    u_char          *start;   	//start of buffer;当buf所指向的数据在内存里的时候，这一整块内存包含的内容可能被包含在多个buf中(比如在某段数据中间插入了其他的数据，这一块数据就需要被拆分开)。那么这些buf中的start和end都指向这一块内存的开始地址和结束地址。而pos和last指向本buf所实际包含的数据的开始和结尾。
    u_char          *end;       //end of buffer;解释参见start。
    //Unique value used to distinguish buffers; created by different nginx modules, usually for the purpose of buffer reuse.
    ngx_buf_tag_t    tag;		//实际上是一个void*类型的指针，使用者可以关联任意的对象上去，只要对使用者有意义
	//File object.
	ngx_file_t      *file;		//当buf所包含的内容在文件中时，file字段指向对应的文件对象
	//Reference to another ("shadow") buffer related to the current buffer, 
	//usually in the sense that the buffer uses data from the shadow. 
	//When the buffer is consumed, the shadow buffer is normally also marked as consumed.
	ngx_buf_t       *shadow;	//当这个buf完整copy了另外一个buf的所有字段的时候，那么这两个buf指向的实际上是同一块内存，或者是同一个文件的同一部分，此时这两个buf的shadow字段都是指向对方的。那么对于这样的两个buf，在释放的时候，就需要使用者特别小心，具体是由哪里释放，要提前考虑好，如果造成资源的多次释放，可能会造成程序崩溃！


    /* the buf's content could be changed */
	//Flag indicating that the buffer references writable memory.
    unsigned         temporary:1;	//为1时表示该buf所包含的内容是在一个用户创建的内存块中，并且可以被在filter处理的过程中进行变更，而不会造成问题

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    //Flag indicating that the buffer references read-only memory.
    unsigned         memory:1;	//为1时表示该buf所包含的内容是在内存中，但是这些内容却不能被进行处理的filter进行变更。

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;	//为1时表示该buf所包含的内容是在内存中, 是通过mmap使用内存映射从文件中映射到内存中的，这些内容却不能被进行处理的filter进行变更

	//Flag indicating that the buffer can be reused and needs to be consumed as soon as possible.
    unsigned         recycled:1;	//可以回收的。也就是这个buf是可以被释放的。这个字段通常是配合shadow字段一起使用的，对于使用ngx_create_temp_buf 函数创建的buf，并且是另外一个buf的shadow，那么可以使用这个字段来标示这个buf是可以被释放的
	//Flag indicating that the buffer references data in a file.
	unsigned         in_file:1;		//为1时表示该buf所包含的内容是在文件中
	//Flag indicating that all data prior to the buffer need to be flushed.
    unsigned         flush:1;		//遇到有flush字段被设置为1的的buf的chain，则该chain的数据即便不是最后结束的数据（last_buf被设置，标志所有要输出的内容都完了），也会进行输出，不会受postpone_output配置的限制，但是会受到发送速率等其他条件的限制。
	//Flag indicating that the buffer carries no data or special signal like flush or last_buf. 
	//By default nginx considers such buffers an error condition, but this flag tells nginx to skip the error check
	unsigned         sync:1;
	//Flag indicating that the buffer is the last in output.
    unsigned         last_buf:1;		//数据被以多个chain传递给了过滤器，此字段为1表明这是最后一个buf
	//Flag indicating that there are no more data buffers in a request or subrequest.
	unsigned         last_in_chain:1;	//在当前的chain里面，此buf是最后一个。特别要注意的是last_in_chain的buf不一定是last_buf，但是last_buf的buf一定是last_in_chain的。这是因为数据会被以多个chain传递给某个filter模块

	//Flag indicating that the buffer is the last one that references a particular shadow buffer.
    unsigned         last_shadow:1;		//在创建一个buf的shadow的时候，通常将新创建的一个buf的last_shadow置为1。
	//Flag indicating that the buffer is in a temporary file.
	unsigned         temp_file:1;		//由于受到内存使用的限制，有时候一些buf的内容需要被写到磁盘上的临时文件中去，那么这时，就设置此标志 

    /* STUB */ int   num;	//统计用，表示使用次数 
};


/*
For input and output operations buffers are linked in chains. 
A chain is a sequence of chain links of type ngx_chain_t
*/
struct ngx_chain_s {
    ngx_buf_t    *buf;	//指向实际的数据
    ngx_chain_t  *next;	//指向这个链表的下个节点
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task, ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


//判断这个buf里面的内容是否在内存里
#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)	
//判断这个buf里面的内容是否仅仅在内存里，并且没有在文件里
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)	

//判断这个buf是否是一个特殊的buf，只含有特殊的标志并且没有包含真正的数据
#define ngx_buf_special(b)                                                   \	
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

//返回这个buf所含数据的大小，不管这个数据是在文件里还是在内存里。
#define ngx_buf_size(b)                                                      \	
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
//释放一个ngx_chain_t类型的对象
#define ngx_free_chain(pool, cl)                                             \	
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
