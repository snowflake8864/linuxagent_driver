/*
 *hash_table.h: 2019-08-25 created by qudreams
 *简单hash表，没有自动扩展功能，是固定bucket大小的hash表
 *此处我们将hash table简称为htable
 *Note!!!:
 *此处的hash表，在init之后是线程安全的，初始化函数是非线程安全的
 */

#ifndef KOSEC_HASH_TABLE_H
#define KOSEC_HASH_TABLE_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>

/*
 * CentOS 5 内核版本号2.6.18 atomic.h定义在asm-generic/atomic.h中
 * CentOS 6.0 内核版本号2.6.32-71 只有asm/atomic.h
 *所以为了兼容我们全部采用asm/atomic.h
 */
#include <asm/atomic.h>

#include "hookframe/core/kvd_core.h"
#include "hookframe/core/kvd_blm.h"


struct vsec_htable_s;
//0-->相等，< 0-->key1小于key2, > 0-->key1大于key2
typedef int (*vsec_htable_cmp_fn_t)(void* key1,size_t len1,
				void* key2,size_t len2);

typedef void (*vsec_htable_free_fn_t)(struct vsec_htable_s* self,
				void* key,size_t len,void* data);

typedef uint32_t (*vsec_htable_hash_fn_t)(void* key,size_t len);

typedef struct vsec_htable_s {
    const char* name;
    void* htctx;
    vsec_htable_cmp_fn_t cmp_fn;
    vsec_htable_hash_fn_t hash_fn;
    vsec_htable_free_fn_t free_fn;
    struct kmem_cache* cachep;
    int nbucket;
    struct hlist_head* ht_heads;
    kvd_blm_hval_t* ht_blms;
    rwlock_t* locks;
    atomic_t size;
}vsec_htable_t;

//默认的hash_fn,cmp_fn,free_fn使用前请务必确认能满足自己的需求
static inline uint32_t vsec_htable_def_hash(void* key,size_t len)
{
    uint32_t hval = 0;

    hval = kvd_murmur_hash2(key,len);
    return hval;
}

static inline int vsec_htable_def_cmp(void* key1,size_t len1,
                                void* key2,size_t len2)
{
    int rc = 0;

    rc = (len1 - len2);
    if(rc) { return rc; }

    return memcmp(key1,key2,len1);
}

static inline void vsec_htable_def_free(vsec_htable_t* ht,
                        void* key,size_t key_len,
                        void* data)
{
    kfree(data);
}

int vsec_htable_init(vsec_htable_t* htable,
                const char* name,
                void* htctx,
                int nbucket,
                vsec_htable_cmp_fn_t cmp_fn,
                vsec_htable_hash_fn_t hash_fn,
                vsec_htable_free_fn_t free_fn);

//此处uninit不负责清理hash表中的元素
//在uninit之前，如果需要清理元素，可以调用vsec_htable_cleanup
void vsec_htable_uninit(vsec_htable_t* htable);

//清理hash表元素，
//返回值0或大于0的值-->均表示成功,此时是清理的元素个数
//小于0是错误,返回值就是错误码
int vsec_htable_cleanup(vsec_htable_t* htable);

//Note:调用此函数时要保证key与data不是临时变量，
//我们在此处不会复制key与data
//对应的key如果存在则替换，不存在则新增
int vsec_htable_upgrade(vsec_htable_t* htable,
        void* key,size_t key_len,void* data);

/*Note:调用此函数时要保证key与data不是临时变量，
 *我们在此处不会复制key与data
 *对应的key如果存在，将先调用cb返回旧值，然后用新值替换;
 *不存在则新增;
 *nmax用于进行限制元素的最大个数，我们在此处进行检验
 *nmax为0时，表示不做限制
 *!!!!!
 *此处不要在回调中释放data元素的值，可以修改data元素的值；但一定不要涉及key
 *一定不要在cb中修改key的值，否则一定会引起严重问题
 *这个函数除非有特殊需要，否则建议使用vsec_htable_upgrade
 */
int vsec_htable_upgrade2(vsec_htable_t* htable,size_t nmax,
        void* key,size_t key_len,void* data,
        void* ctx,void (*cb)(void* old_data,void* ctx));
/* 无ctx,只从old更新数据到data: old存在则更新后替换,不存在直接添加
 * key包含在data数据中 */
int vsec_htable_upgrade3(vsec_htable_t *ht,
        void *key, size_t key_len, void *data,
        void (*cb)(void *old, void *data));

//返回值: 0-->成功，失败-->小于0的值
int vsec_htable_del(vsec_htable_t* htable,
        void* key,size_t key_len);

int vsec_htable_exist(vsec_htable_t* htable,
    void* key,size_t key_len);

//此处我们通过cb将hash-data给返回，而不是将key一同返回
//是因为我们认为get操作不会做任何修改及释放操作，
//此处一定不要释放或者修改data，否则极有可能会崩溃
int vsec_htable_get(vsec_htable_t* htable,
        void* key,size_t key_len,void* ctx,
        void (*cb)(void* data,void* ctx));

//修改hash表的元素值,不是修改key
//此处我们通过cb将hash-data给返回，而不是将key一同返回
//是因为我们认为modify操作不会对key做任何修改，
//此处可以修改data,但一定不要释放data或者修改key，
//否则极有可能会崩溃
int vsec_htable_modify_data(vsec_htable_t* htable,
        void* key,size_t key_len,void* ctx,
        void (*cb)(void* data,void* ctx));

//遍历修改hash表的元素值,不是修改key
//此处我们通过cb将hash-data给返回，而不是将key一同返回
//是因为我们认为modify操作不会对key做任何修改，
//此处可以修改data,但一定不要释放data或者修改key，
//否则极有可能会崩溃,cb返回非0值停止循环
void vsec_htable_walk_modify_data(vsec_htable_t* htable,
        void* ctx,int (*cb)(void* data,void* ctx));

//此处的pop操作，我们同时通过cb返回key,data
//key,data可能被修改或者释放都不会有问题
int vsec_htable_pop(vsec_htable_t* htable,
        void* key,size_t key_len,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx));

//本函数只允许以只读方式遍历
int vsec_htable_walk(vsec_htable_t* htable,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx));

//本函数只允许以只读方式遍历: cb函数返回非0值内部会停止遍历
int vsec_htable_walk2(vsec_htable_t* htable,void* ctx,
        int (*cb)(void* key,size_t key_len,void* data,void* ctx));

//本函数只允许以只读方式遍历,按照链表头进行单步遍历链表头，遍历请求由audit_sysfs.c读取端发起
int vsec_htable_walk_step(vsec_htable_t* htable,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx),
		unsigned int *cur_pos);

//本函数用于判定hash table的表是否为空
int vsec_htable_empty(vsec_htable_t* htable);

//本函数用于获取hash table的表元素个数
//这个值是不准确的，因为不是采用的全局锁，
//而是采用原子操作，不具备全局一致性
size_t vsec_htable_size(vsec_htable_t* htable);

//清理满足条件的hash表元素，
//返回值0或大于0的值-->均表示成功,此时是清理的元素个数
//小于0是错误,返回值就是错误码
//filter-->返回非0值表示满足条件，0-->表示不满足条件;为空时会删除所有元素
int vsec_htable_clean_items(vsec_htable_t* htable,void* ctx,
        int (*filter)(void* key,size_t key_len,void* data,void* ctx));

//弹出满足条件的hash表元素，
//返回值0或大于0的值-->均表示成功,此时是清理的元素个数
//小于0是错误,返回值就是错误码
//filter-->返回非0值表示满足条件，0-->表示不满足条件;为空时会删除所有元素
//cb-->用于返回满足条件的元素
int vsec_htable_pop_items(vsec_htable_t* htable,void* ctx,
        int (*filter)(void* key,size_t key_len,void* data,void* ctx),
        void (*cb)(void* key,size_t key_len,void* data,void* ctx));

#endif
