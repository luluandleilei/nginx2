
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


//hash里面查找key对应的value。
//key是对真正的key（也就是name）计算出的hash值。
//len是name的长度
//如果查找成功，则返回指向value的指针，否则返回NULL
void *
ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len)
{
    ngx_uint_t       i;
    ngx_hash_elt_t  *elt;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "hf:\"%*s\"", len, name);
#endif

    elt = hash->buckets[key % hash->size];

    if (elt == NULL) {
        return NULL;
    }

    while (elt->value) {
        if (len != (size_t) elt->len) {
            goto next;
        }

        for (i = 0; i < len; i++) {
            if (name[i] != elt->name[i]) {
                goto next;
            }
        }

        return elt->value;

    next:

        elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len, sizeof(void *));
        continue;
    }

    return NULL;
}


//ngx_hash_wildcard_t的查询是通过函数ngx_hash_find_wc_head或者ngx_hash_find_wc_tail来做的。
//ngx_hash_find_wc_head是查询包含通配符在前的key的hash表的
//hwc -- hash表对象的指针。
//name -- 需要查询的域名，例如: www.abc.com
//len -- name的长度
//该函数返回匹配的通配符对应value。如果没有查到，返回NULL
void *
ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    ngx_uint_t   i, n, key;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wch:\"%*s\"", len, name);
#endif

    n = len;

    while (n) {
        if (name[n - 1] == '.') {
            break;
        }

        n--;
    }

	/*计算hash值。注意:构造带通配符的hash表时用于计算hash值的函数需要与此处计算的方法匹配*/
    key = 0;

    for (i = n; i < len; i++) {
        key = ngx_hash(key, name[i]);
    }

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
#endif

    value = ngx_hash_find(&hwc->hash, key, &name[n], len - n);

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "value:\"%p\"", value);
#endif

    if (value) {

        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer for both "example.com"
         *          and "*.example.com";
         *     01 - value is data pointer for "*.example.com" only;
         *     10 - value is pointer to wildcard hash allowing
         *          both "example.com" and "*.example.com";
         *     11 - value is pointer to wildcard hash allowing
         *          "*.example.com" only.
         */

        if ((uintptr_t) value & 2) {

            if (n == 0) {

                /* "example.com" */

                if ((uintptr_t) value & 1) {
                    return NULL;
                }

                hwc = (ngx_hash_wildcard_t *)
                                          ((uintptr_t) value & (uintptr_t) ~3);
                return hwc->value;
            }

            hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);

            value = ngx_hash_find_wc_head(hwc, name, n - 1);

            if (value) {
                return value;
            }

            return hwc->value;
        }

        if ((uintptr_t) value & 1) {

            if (n == 0) {

                /* "example.com" */

                return NULL;
            }

            return (void *) ((uintptr_t) value & (uintptr_t) ~3);
        }

        return value;
    }

    return hwc->value;
}


//ngx_hash_wildcard_t的查询是通过函数ngx_hash_find_wc_head或者ngx_hash_find_wc_tail来做的。
//ngx_hash_find_wc_tail是查询包含通配符在前的key的hash表的
//hwc -- hash表对象的指针。
//name -- 需要查询的域名，例如: www.abc.com
//len -- name的长度
//该函数返回匹配的通配符对应value。如果没有查到，返回NULL
void *
ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    ngx_uint_t   i, key;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wct:\"%*s\"", len, name);
#endif

    key = 0;

    for (i = 0; i < len; i++) {
        if (name[i] == '.') {
            break;
        }

        key = ngx_hash(key, name[i]);
    }

    if (i == len) {
        return NULL;
    }

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
#endif

    value = ngx_hash_find(&hwc->hash, key, name, i);

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "value:\"%p\"", value);
#endif

    if (value) {

        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer;
         *     11 - value is pointer to wildcard hash allowing "example.*".
         */

        if ((uintptr_t) value & 2) {

            i++;

            hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);

            value = ngx_hash_find_wc_tail(hwc, &name[i], len - i);

            if (value) {
                return value;
            }

            return hwc->value;
        }

        return value;
    }

    return hwc->value;
}


//在此组合hash表中，依次查询其三个子hash表，看是否匹配，一旦找到，立即返回查找结果，
//也就是说如果有多个可能匹配，则只返回第一个匹配的结果
//hash:	此组合hash表对象。
//key:	根据name计算出的hash值。
//name:	key的具体内容。
//len:	name的长度。
//返回查询的结果，未查到则返回NULL
void *
ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key, u_char *name, size_t len)
{
    void  *value;

    if (hash->hash.buckets) {
        value = ngx_hash_find(&hash->hash, key, name, len);

        if (value) {
            return value;
        }
    }

    if (len == 0) {
        return NULL;
    }

    if (hash->wc_head && hash->wc_head->hash.buckets) {
        value = ngx_hash_find_wc_head(hash->wc_head, name, len);

        if (value) {
            return value;
        }
    }

    if (hash->wc_tail && hash->wc_tail->hash.buckets) {
        value = ngx_hash_find_wc_tail(hash->wc_tail, name, len);

        if (value) {
            return value;
        }
    }

    return NULL;
}


#define NGX_HASH_ELT_SIZE(name)                                               \
    (sizeof(void *) + ngx_align((name)->key.len + 2, sizeof(void *)))

//ngx_hash_t的初始化
//hinit是初始化的一些参数的一个集合。
//names是初始化一个ngx_hash_t所需要的所有key的一个数组
//nelts就是key的个数
//成功返回NGX_OK，失败返回NGX_ERROR
ngx_int_t
ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts)
{
    u_char          *elts;
    size_t           len;
    u_short         *test;
    ngx_uint_t       i, n, key, size, start, bucket_size;
    ngx_hash_elt_t  *elt, **buckets;

	/*参数合法性检查*/

    if (hinit->max_size == 0) {
        ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0, "could not build %s, you should " "increase %s_max_size: %i", hinit->name, hinit->name, hinit->max_size);
        return NGX_ERROR;
    }

    for (n = 0; n < nelts; n++) {
        if (hinit->bucket_size < NGX_HASH_ELT_SIZE(&names[n]) + sizeof(void *)) { //NGX_HASH_ELT_SIZE(&names[n]) + sizeof(void *)为桶中仅仅存储一个元素所需要的空间
            ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0, "could not build %s, you should " "increase %s_bucket_size: %i", hinit->name, hinit->name, hinit->bucket_size);
            return NGX_ERROR;
        }
    }

    test = ngx_alloc(hinit->max_size * sizeof(u_short), hinit->pool->log);	//test用于统计不同桶个数的情况下每个桶所需存储空间
    if (test == NULL) {
        return NGX_ERROR;
    }

    bucket_size = hinit->bucket_size - sizeof(void *);	//计算一个桶实际可用于存储元素的空间(除去末尾表示结束的空指针空间)

	/*计算可能的最少桶个数*/
	
    start = nelts / (bucket_size / (2 * sizeof(void *))); //最少桶个数(start) = 总元素个数/桶中可以存放的元素的最大个数; 桶中可以存放的元素的最大个数 = 桶大小/元素的最小大小
    start = start ? start : 1;

    if (hinit->max_size > 10000 && nelts && hinit->max_size / nelts < 100) {	//XXX：什么意思？
        start = hinit->max_size - 1000;
    }

	/*查找最佳的(桶个数尽可能的少)桶个数size*/
    for (size = start; size <= hinit->max_size; size++) {

        ngx_memzero(test, size * sizeof(u_short));

        for (n = 0; n < nelts; n++) {
            if (names[n].key.data == NULL) {
                continue;
            }

            key = names[n].key_hash % size;
            test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %ui %ui \"%V\"",
                          size, key, test[key], &names[n].key);
#endif

            if (test[key] > (u_short) bucket_size) {
                goto next;
            }
        }

        goto found;

    next:

        continue;
    }

    size = hinit->max_size;

    ngx_log_error(NGX_LOG_WARN, hinit->pool->log, 0,
                  "could not build optimal %s, you should increase "
                  "either %s_max_size: %i or %s_bucket_size: %i; "
                  "ignoring %s_bucket_size",
                  hinit->name, hinit->name, hinit->max_size,
                  hinit->name, hinit->bucket_size, hinit->name);

found:

	/*重新计算在桶个数为size时所需总的桶大小*/

    for (i = 0; i < size; i++) {
        test[i] = sizeof(void *);
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        key = names[n].key_hash % size;
        test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
    }

    len = 0;	//记录所有桶的总大小

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {  //桶中没有元素，忽略该桶大小
            continue;
        }

        test[i] = (u_short) (ngx_align(test[i], ngx_cacheline_size));	//将每一个桶大小按ngx_cacheline_size进行对齐

        len += test[i];
    }

	/*分配桶个数，如必要分配哈希表*/
    if (hinit->hash == NULL) {
		//XXX:为什么是sizeof(ngx_hash_wildcard_t)而不是sizeof(ngx_hash_t) ???
        hinit->hash = ngx_pcalloc(hinit->pool, sizeof(ngx_hash_wildcard_t) + size * sizeof(ngx_hash_elt_t *));
        if (hinit->hash == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }

        buckets = (ngx_hash_elt_t **) ((u_char *) hinit->hash + sizeof(ngx_hash_wildcard_t));

    } else {
        buckets = ngx_pcalloc(hinit->pool, size * sizeof(ngx_hash_elt_t *));
        if (buckets == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }
    }

	/*分配总的桶大小*/
	
    elts = ngx_palloc(hinit->pool, len + ngx_cacheline_size);	//加一个ngx_cacheline_size大小，用于将总桶大小空间按ngx_cacheline_size对齐
    if (elts == NULL) {
        ngx_free(test);
        return NGX_ERROR;
    }

    elts = ngx_align_ptr(elts, ngx_cacheline_size);

	/*关联每个桶和齐对应的桶空间*/
    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }

        buckets[i] = (ngx_hash_elt_t *) elts;
        elts += test[i];
    }

	/*将所有元素存储到对应的桶中*/

    for (i = 0; i < size; i++) {
        test[i] = 0; 	//test用于记录每个桶中存储下一个元素的位置的偏移量
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        key = names[n].key_hash % size;
        elt = (ngx_hash_elt_t *) ((u_char *) buckets[key] + test[key]);

        elt->value = names[n].value;
        elt->len = (u_short) names[n].key.len;

        ngx_strlow(elt->name, names[n].key.data, names[n].key.len);			//XXX:将所有key转换成了小写存储 ？？？

        test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));	//桶中元素按sizeof(void*)进行对齐
    }

	//非空桶中，最后一个元素为NULL
    for (i = 0; i < size; i++) {
        if (buckets[i] == NULL) {
            continue;
        }

        elt = (ngx_hash_elt_t *) ((u_char *) buckets[i] + test[i]);

        elt->value = NULL;
    }

    ngx_free(test);

    hinit->hash->buckets = buckets;
    hinit->hash->size = size;

#if 0

    for (i = 0; i < size; i++) {
        ngx_str_t   val;
        ngx_uint_t  key;

        elt = buckets[i];

        if (elt == NULL) {
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0, "%ui: NULL", i);
            continue;
        }

        while (elt->value) {
            val.len = elt->len;
            val.data = &elt->name[0];

            key = hinit->key(val.data, val.len);

            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0, "%ui: %p \"%V\" %ui", i, elt, &val, key);

            elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len, sizeof(void *));
        }
    }

#endif

    return NGX_OK;
}


//ngx_hash_wildcard_t类型变量的构建是通过函数ngx_hash_wildcard_init完成的。
//注意调用前需要对要插入的所有元素排序
//hinit -- 构造一个通配符hash表的一些参数的一个集合
//name -- 构造此hash表的所有的通配符key的数组。特别要注意的是这里的key已经都是被预处理过的。
//		例如：“*.abc.com”或者“.abc.com”被预处理完成以后，变成了“com.abc.”。而“mail.xxx.*”则被预处理为“mail.xxx.”。
//		为什么会被处理这样？这里不得不简单地描述一下通配符hash表的实现原理。当构造此类型的hash表的时候，实际上是构
//		造了一个hash表的一个“链表”，是通过hash表中的key“链接”起来的。比如：对于“*.abc.com”将会构造出2个hash表，第一
//		个hash表中有一个key为com的表项，该表项的value包含有指向第二个hash表的指针，而第二个hash表中有一个表项abc，
//		该表项的value包含有指向*.abc.com对应的value的指针。那么查询的时候，比如查询www.abc.com的时候，先查com，通过
//		查com可以找到第二级的hash表，在第二级hash表中，再查找abc，依次类推，直到在某一级的hash表中查到的表项对应的
//		value对应一个真正的值而非一个指向下一级hash表的指针的时候，查询过程结束。这里有一点需要特别注意的，就是names
//		数组中元素的value值低两位bit必须为0（有特殊用途）。如果不满足这个条件，这个hash表查询不出正确结果。
//nelts -- names数组元素的个数。
//该函数执行成功返回NGX_OK，否则NGX_ERROR。
ngx_int_t
ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts)
{
    size_t                len, dot_len;
    ngx_uint_t            i, n, dot;
    ngx_array_t           curr_names, next_names;
    ngx_hash_key_t       *name, *next_name;
    ngx_hash_init_t       h;
    ngx_hash_wildcard_t  *wdc;

    if (ngx_array_init(&curr_names, hinit->temp_pool, nelts, sizeof(ngx_hash_key_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&next_names, hinit->temp_pool, nelts, sizeof(ngx_hash_key_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    for (n = 0; n < nelts; n = i) {	//注意这里是：n = i

#if 0
        ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0, "wc0: \"%V\"", &names[n].key);
#endif

        dot = 0;

        for (len = 0; len < names[n].key.len; len++) {
            if (names[n].key.data[len] == '.') {
                dot = 1;
                break;
            }
        }

        name = ngx_array_push(&curr_names);
        if (name == NULL) {
            return NGX_ERROR;
        }

        name->key.len = len;
        name->key.data = names[n].key.data;
        name->key_hash = hinit->key(name->key.data, name->key.len);	//此处计算hash值时是不考虑前面的'.'的，后面通过value字段的最后一位是否为1来表示是否前面有'.'
        name->value = names[n].value;

#if 0
        ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0, "wc1: \"%V\" %ui", &name->key, dot);
#endif

        dot_len = len + 1;

        if (dot) {
            len++;
        }

        next_names.nelts = 0;

        if (names[n].key.len != len) {
            next_name = ngx_array_push(&next_names);
            if (next_name == NULL) {
                return NGX_ERROR;
            }

            next_name->key.len = names[n].key.len - len;
            next_name->key.data = names[n].key.data + len;
            next_name->key_hash = 0;
            next_name->value = names[n].value;

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0, "wc2: \"%V\"", &next_name->key);
#endif
        }

        for (i = n + 1; i < nelts; i++) { //查看是否有相同前缀的其他元素
            if (ngx_strncmp(names[n].key.data, names[i].key.data, len) != 0) {
                break;	//调用ngx_hash_wildcard_init前已经对元素进行了排序，一旦不匹配，后续节点必然不匹配
            }

            if (!dot
                && names[i].key.len > len
                && names[i].key.data[len] != '.')	//具有相同前缀情况处理,例如：".test.com", ".testa.com"
            {
                break;	//调用ngx_hash_wildcard_init前已经对元素进行了排序，一旦不匹配，后续节点必然不匹配
            }

            next_name = ngx_array_push(&next_names);
            if (next_name == NULL) {
                return NGX_ERROR;
            }

            next_name->key.len = names[i].key.len - dot_len;
            next_name->key.data = names[i].key.data + dot_len;
            next_name->key_hash = 0;
            next_name->value = names[i].value;

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "wc3: \"%V\"", &next_name->key);
#endif
        }

        if (next_names.nelts) {

            h = *hinit;
            h.hash = NULL;

            if (ngx_hash_wildcard_init(&h, (ngx_hash_key_t *) next_names.elts, next_names.nelts) != NGX_OK) {
                return NGX_ERROR;
            }

            wdc = (ngx_hash_wildcard_t *) h.hash;

            if (names[n].key.len == len) {	//具有前缀子串关系的处理，例如："*.aaa.test.com", "*.test.com"
                wdc->value = names[n].value;
            }

            name->value = (void *) ((uintptr_t) wdc | (dot ? 3 : 2));	//value的第2位表示该value是一个data pointer还是一个wildcard hash

        } else if (dot) {
            name->value = (void *) ((uintptr_t) name->value | 1);
        }
    }

    if (ngx_hash_init(hinit, (ngx_hash_key_t *) curr_names.elts, curr_names.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_uint_t
ngx_hash_key(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, data[i]);
    }

    return key;
}


ngx_uint_t
ngx_hash_key_lc(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, ngx_tolower(data[i]));
    }

    return key;
}


ngx_uint_t
ngx_hash_strlow(u_char *dst, u_char *src, size_t n)
{
    ngx_uint_t  key;

    key = 0;

    while (n--) {
        *dst = ngx_tolower(*src);
        key = ngx_hash(key, *dst);
        dst++;
        src++;
    }

    return key;
}


//初始化这个结构，主要是对这个结构中的ngx_array_t类型的字段进行初始化，成功返回NGX_OK。
//在调用该函数之前需要定义一个这个类型的变量，并对字段pool和temp_pool赋值
//ha:	该结构的对象指针。
//type:	该字段有2个值可选择，即NGX_HASH_SMALL和NGX_HASH_LARGE。用来指明将要建立的hash表的类型，
//		如果是NGX_HASH_SMALL，则有比较小的桶的个数和数组元素大小。NGX_HASH_LARGE则相反。
ngx_int_t
ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type)
{
    ngx_uint_t  asize;

    if (type == NGX_HASH_SMALL) {
        asize = 4;
        ha->hsize = 107;

    } else {
        asize = NGX_HASH_LARGE_ASIZE;
        ha->hsize = NGX_HASH_LARGE_HSIZE;
    }

    if (ngx_array_init(&ha->keys, ha->temp_pool, asize, sizeof(ngx_hash_key_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&ha->dns_wc_head, ha->temp_pool, asize, sizeof(ngx_hash_key_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&ha->dns_wc_tail, ha->temp_pool, asize, sizeof(ngx_hash_key_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    ha->keys_hash = ngx_pcalloc(ha->temp_pool, sizeof(ngx_array_t) * ha->hsize);
    if (ha->keys_hash == NULL) {
        return NGX_ERROR;
    }

    ha->dns_wc_head_hash = ngx_pcalloc(ha->temp_pool, sizeof(ngx_array_t) * ha->hsize);
    if (ha->dns_wc_head_hash == NULL) {
        return NGX_ERROR;
    }

    ha->dns_wc_tail_hash = ngx_pcalloc(ha->temp_pool, sizeof(ngx_array_t) * ha->hsize);
    if (ha->dns_wc_tail_hash == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


//一般是循环调用这个函数，把一组键值对加入到这个结构体中。
//该函数会自动实现普通key，带前向通配符的key和带后向通配符的key的分类和检查，并将这个些值存放到对应的字段中去，
//然后就可以通过检查这个结构体中的keys、dns_wc_head、dns_wc_tail三个数组是否为空，来决定是否构建普通hash表，
//前向通配符hash表和后向通配符hash表了（在构建这三个类型的hash表的时候，可以分别使用keys、dns_wc_head、dns_wc_tail三个数组）。
//构建出这三个hash表以后，可以组合在一个ngx_hash_combined_t对象中，使用ngx_hash_find_combined进行查找。
//或者是仍然保持三个独立的变量对应这三个hash表，自己决定何时以及在哪个hash表中进行查询。
//ha:		该结构的对象指针。
//key:		参数名自解释了。
//value:	参数名自解释了。
//flags:	有两个标志位可以设置，NGX_HASH_WILDCARD_KEY和NGX_HASH_READONLY_KEY。同时要设置的使用逻辑与操作符就可以了。
//			NGX_HASH_READONLY_KEY被设置的时候，在计算hash值的时候，key的值不会被转成小写字符，否则会。
//			NGX_HASH_WILDCARD_KEY被设置的时候，说明key里面可能含有通配符，会进行相应的处理。
//			如果两个标志位都不设置，传0。
//返回NGX_OK是加入成功。返回NGX_BUSY意味着key值重复。
//NGX_DECLINED：不支持的key的格式
//NGX_ERROR:	内部错误
ngx_int_t
ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key, void *value, ngx_uint_t flags)
{
    size_t           len;
    u_char          *p;
    ngx_str_t       *name;
    ngx_uint_t       i, k, n, skip, last;
    ngx_array_t     *keys, *hwc;
    ngx_hash_key_t  *hk;

    last = key->len;

    if (flags & NGX_HASH_WILDCARD_KEY) {

        /*
         * supported wildcards:
         *     "*.example.com", ".example.com", and "www.example.*"
         */

        n = 0;	//统计key中包含的星号的个数

        for (i = 0; i < key->len; i++) {

            if (key->data[i] == '*') {
                if (++n > 1) {	//包含多个星号，不支持该格式
                    return NGX_DECLINED;
                }
            }

            if (key->data[i] == '.' && key->data[i + 1] == '.') {	//包含连续的两个点，不支持该格式 //XXX:key->data[i+1]越界，有问题吗？？？
                return NGX_DECLINED;
            }

            if (key->data[i] == '\0') {	//包含字符'\0'，不支持该格式
                return NGX_DECLINED;
            }
        }

        if (key->len > 1 && key->data[0] == '.') {	//".example.com"
            skip = 1;
            goto wildcard;
        }

        if (key->len > 2) {

            if (key->data[0] == '*' && key->data[1] == '.') {	//"*.example.com"
                skip = 2;
                goto wildcard;
            }

            if (key->data[i - 2] == '.' && key->data[i - 1] == '*') {	//"www.example.*"
                skip = 0;
                last -= 2;
                goto wildcard;
            }
        }

        if (n) {	//包含星号，但不支持该格式
            return NGX_DECLINED;
        }
    }

    /* exact hash */

    k = 0;

    for (i = 0; i < last; i++) {
        if (!(flags & NGX_HASH_READONLY_KEY)) {	//若没有NGX_HASH_READONLY_KEY标志，表示key是可以改写的，会将key转换为小写，再计算hash值
            key->data[i] = ngx_tolower(key->data[i]);
        }
        k = ngx_hash(k, key->data[i]);
    }

    k %= ha->hsize;

    /* check conflicts in exact hash */

    name = ha->keys_hash[k].elts;

    if (name) {
        for (i = 0; i < ha->keys_hash[k].nelts; i++) {
            if (last != name[i].len) {
                continue;
            }

            if (ngx_strncmp(key->data, name[i].data, last) == 0) {
                return NGX_BUSY;
            }
        }

    } else {
        if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    name = ngx_array_push(&ha->keys_hash[k]);
    if (name == NULL) {
        return NGX_ERROR;
    }

    *name = *key;

    hk = ngx_array_push(&ha->keys);
    if (hk == NULL) {
        return NGX_ERROR;
    }

    hk->key = *key;
    hk->key_hash = ngx_hash_key(key->data, last);
    hk->value = value;

    return NGX_OK;


wildcard:

    /* wildcard hash */

    k = ngx_hash_strlow(&key->data[skip], &key->data[skip], last - skip);

    k %= ha->hsize;

    if (skip == 1) {

        /* check conflicts in exact hash for ".example.com" */

        name = ha->keys_hash[k].elts;

        if (name) {
            len = last - skip;

            for (i = 0; i < ha->keys_hash[k].nelts; i++) {
                if (len != name[i].len) {
                    continue;
                }

				//XXX:为什么前向通配符的".example.com"形式不能与精确的相同?
				//.example.com 等价于*.example.com 和 example.com
                if (ngx_strncmp(&key->data[1], name[i].data, len) == 0) {	
                    return NGX_BUSY;
                }
            }

        } else {
            if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        name = ngx_array_push(&ha->keys_hash[k]);
        if (name == NULL) {
            return NGX_ERROR;
        }

        name->len = last - 1;
        name->data = ngx_pnalloc(ha->temp_pool, name->len);	//XXX:为什么这里要分配内存？不能让name->data = key->data + 1; ??
        if (name->data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(name->data, &key->data[1], name->len);
    }


    if (skip) {

        /*
         * convert "*.example.com" to "com.example.\0"
         *      and ".example.com" to "com.example\0"
         */

        p = ngx_pnalloc(ha->temp_pool, last);
        if (p == NULL) {
            return NGX_ERROR;
        }

        len = 0;
        n = 0;

        for (i = last - 1; i; i--) {
            if (key->data[i] == '.') {
                ngx_memcpy(&p[n], &key->data[i + 1], len);
                n += len;
                p[n++] = '.';
                len = 0;
                continue;
            }

            len++;
        }

        if (len) {
            ngx_memcpy(&p[n], &key->data[1], len);
            n += len;
        }

        p[n] = '\0';

        hwc = &ha->dns_wc_head;
        keys = &ha->dns_wc_head_hash[k];

    } else {

        /* convert "www.example.*" to "www.example\0" */

        last++;

        p = ngx_pnalloc(ha->temp_pool, last);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_cpystrn(p, key->data, last);

        hwc = &ha->dns_wc_tail;
        keys = &ha->dns_wc_tail_hash[k];
    }


    /* check conflicts in wildcard hash */

    name = keys->elts;

    if (name) {
        len = last - skip;

        for (i = 0; i < keys->nelts; i++) {
            if (len != name[i].len) {
                continue;
            }

            if (ngx_strncmp(key->data + skip, name[i].data, len) == 0) {
                return NGX_BUSY;
            }
        }

    } else {
        if (ngx_array_init(keys, ha->temp_pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    name = ngx_array_push(keys);
    if (name == NULL) {
        return NGX_ERROR;
    }

    name->len = last - skip;
    name->data = ngx_pnalloc(ha->temp_pool, name->len);	//XXX:为什么这里要分配内存？不能让name->data = key->data + skip; ??
    if (name->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(name->data, key->data + skip, name->len);


    /* add to wildcard hash */

    hk = ngx_array_push(hwc);
    if (hk == NULL) {
        return NGX_ERROR;
    }

    hk->key.len = last - 1;	//注意：这里是hk->key.len没有包括后面的'\0'，但 hk->key.data可以直接作为普通字符串使用，因为后面有'\0'
    hk->key.data = p;		//注意：这里hk->key.data是从ha->temp_pool中分配的
    hk->key_hash = 0;
    hk->value = value;

    return NGX_OK;
}
