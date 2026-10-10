/*
 *rb_htable.h: 2019-09-24 created by qudreams
 *基于red-black tree的开链hash表
 *主要用于处理路径匹配及子路径查找
 *这个hash表比使用hlist实现的vsec_htable_t更费内存
 *并且实现更复杂，大多数情况下使用vsec_htable_t更好
 */

#ifndef KOSEC_RB_HTABLE_H
#define KOSEC_RB_HTABLE_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/err.h>

struct vsec_rb_htable;

//0-->相等，< 0-->key1小于key2, > 0-->key1大于key2
typedef int (*vsec_rb_ht_cmp_fn_t)(void* key1,size_t len1,
								void* key2,size_t len2);

typedef void (*vsec_rb_ht_free_fn_t)(struct vsec_rb_htable* self,
						void* key,size_t len,void* data);

typedef uint32_t (*vsec_rb_ht_hash_fn_t)(void* key,size_t len);

//red-black hash-table entry
struct rb_ht_entry {
	struct rb_node node;
	void* key;
	size_t key_len;
    void* data;
};

//使用red-black tree的开链hash-table
//并且一旦初始化成功后不支持自动扩充,是一个固定bucket长度的hash
//因为自动扩充意味着需要对所有元素进行rehash，可能会导致严重的性能问题
//所以在初始化时尽可能指定的nbucket大一些
struct vsec_rb_htable {
	const char* name;
	void* ht_ctx;
    u_long debug; //调试开关
	vsec_rb_ht_cmp_fn_t cmp_fn;
    vsec_rb_ht_hash_fn_t hash_fn;
    vsec_rb_ht_free_fn_t free_fn;
    struct kmem_cache* cachep;
    int nbucket;
	rwlock_t* locks;
	struct rb_root* ht_roots;
};

int vsec_rb_htable_init(struct vsec_rb_htable* ht,
				const char* name,
				void* ctx,int nbucket,
				vsec_rb_ht_cmp_fn_t cmp_fn,
				vsec_rb_ht_hash_fn_t hash_fn,
				vsec_rb_ht_free_fn_t free_fn);
void vsec_rb_htable_uninit(struct vsec_rb_htable* ht);

//开启或关闭debug,这个主要用于在特殊情形下单独开启针对rb htable的调试
//目前在sub_path的实现中有使用
void vsec_rb_htable_debug(struct vsec_rb_htable* ht,int bon);

//Note:调用此函数时要保证key与data不是临时变量，
//我们在此处不会复制key与data，此处data可以为空，但key绝对不能为空
//成功返回0,失败返回小于0的错误码
int vsec_rb_htable_insert(struct vsec_rb_htable* ht,
				void* key,size_t key_len,void* data);

//判断给定的key在ht中是否存在，存在返回非0值，不存在返回0
int vsec_rb_htable_exist(struct vsec_rb_htable* ht,
                void* key,size_t len);

//成功返回0,失败时返回小于0的错误码
int vsec_rb_htable_delete(struct vsec_rb_htable* ht,
                void* key,size_t len);

//此处我们通过cb将hash-data给返回，而不是将key一同返回
//是因为我们认为get操作不会做任何修改及释放操作，
//此处一定不要释放或者修改data，否则极有可能会崩溃
int vsec_rb_htable_get(struct vsec_rb_htable* ht,
			void* key,size_t key_len,void* ctx,
			void (*cb)(void* data,void* ctx));

//此处的pop操作，我们同时通过cb返回key,data
//key,data可能被修改或者释放都不会有问题
int vsec_rb_htable_pop(struct vsec_rb_htable* ht,
        void* key,size_t key_len,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx));

//清理hash表元素，
//返回值0或大于0的值-->均表示成功,此时是清理的元素个数
//小于0是错误,返回值就是错误码
int vsec_rb_htable_cleanup(struct vsec_rb_htable* ht);

int vsec_rb_htable_empty(struct vsec_rb_htable* ht);

//本函数只允许以只读方式遍历
int vsec_rb_htable_walk(struct vsec_rb_htable* ht,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx));

//清理满足条件的hash表元素，
//返回值0或大于0的值-->均表示成功,此时是清理的元素个数
//小于0是错误,返回值就是错误码
//filter-->返回非0值表示满足条件，0-->表示不满足条件
int vsec_rb_htable_clean_items(struct vsec_rb_htable* ht,void* ctx,
        int (*filter)(void* key,size_t key_len,void* data,void* ctx));

/* 更新已有节点key(没有则插入),data为需保存的数据,其中包含key值 */
int vsec_rb_htable_upgrade(struct vsec_rb_htable *ht, void *key, size_t key_len,
        void *data, void (*cb)(void *old, void *data));
#endif
