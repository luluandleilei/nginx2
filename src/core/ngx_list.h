
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

//ngx_list_t的节点不像我们常见的list的节点，只能存放一个元素，ngx_list_t的节点实际上是一个固定大小的数组。
//在初始化的时候，我们需要设定元素需要占用的空间大小，每个节点数组的容量大小。在添加元素到这个list里面的时候，
//会在最尾部的节点里的数组上添加元素，如果这个节点的数组存满了，就再增加一个新的节点到这个list里面去。
struct ngx_list_part_s {		//链表节点结构(每个节点都是一个元素的数组)
    void             *elts;		//节点中存放具体元素的内存的开始地址 //指向数组的起始地址
    ngx_uint_t        nelts;	//节点中已有元素个数。这个值是不能大于链表头节点ngx_list_t类型中的nalloc字段的 //数组中当前包含(使用)的元素个数
    ngx_list_part_t  *next;		//指向下一个节点
};


typedef struct {				//链表结构
    ngx_list_part_t  *last;		//指向该链表的最后一个节点
    ngx_list_part_t   part;		//该链表的第一个节点(至少有一个节点)
    size_t            size;		//该链表中存放的具体元素所需内存大小
    ngx_uint_t        nalloc;	//该链表中每一个节点能存放特定元素的容量（每一个节点拥有的最多的特定元素的个数)
    ngx_pool_t       *pool;		//该链表使用的分配内存的pool
} ngx_list_t;


ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

//该函数是用于ngx_list_t类型的对象已经存在，但是其第一个节点存放元素的内存空间还未分配的情况下，
//可以调用此函数来给这个list的首节点来分配存放元素的内存空间。
static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
