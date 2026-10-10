#ifndef __H_TABLE_H
#define __H_TABLE_H

#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/timer.h>
#include <linux/list.h>
/* Vector hash entry (for caches). */
struct h_cache
{
    struct list_head  list;
    struct timer_list timer;
    struct h_bucket  *bucket;
    struct h_table   *table;
    struct list_head  idle_list;
    u8  timeo;
    /* Time for the latest `h_entry_put()` operation. */
    unsigned long     last_put;
    unsigned long     timestamp;
    int refs;
};

/* Scalar hash entry (mostly used for rule tables). */
struct h_scalar
{
    struct list_head  list;
    struct rcu_head   rcu;
    struct timer_list timer;
    struct h_bucket  *bucket;
    struct h_table   *table;
};

struct h_bucket
{
    struct list_head chain;
    spinlock_t       lock;
};

enum __h_table_type
{
    H_TABLE_TYPE_CACHE,
    H_TABLE_TYPE_SCALAR,
};

struct h_table
{
    int table_type;
    union
    {
        struct h_operations *ops;
        struct h_scalar_operations *s_ops;
    };
    struct h_bucket *base;
    bool      static_base;
    size_t    size;
    size_t    max_len;
    size_t    len;
    long      timeo;
    rwlock_t  rwlock;
    char     *proc_name;
    struct proc_dir_entry *proc_parent;

    struct list_head  idle_queue;
    spinlock_t        idle_lock;
    //struct timer_list timer;
    struct task_struct *timeo_kthread;
};

/* Hash table operation collections. */
struct h_operations
{
    u32   (*hash)(void *key);
    int   (*comp_key)(struct h_cache *he, void *key);
    void  (*release)(struct h_cache *he);
    char *(*build_line)(struct h_cache *he, gfp_t flags);
    int   (*operate_cmd)(struct h_table *ht, const char *cmd);
};

/* Scalar hash table operation collections. */
struct h_scalar_operations
{
    u32   (*hash)(void *key);
    int   (*comp_key)(struct h_scalar *he, void *key);
    void  (*release)(struct h_scalar *he);
    char *(*build_line)(struct h_scalar *he, gfp_t flags);
    int   (*operate_cmd)(struct h_table *ht, const char *cmd);
};


/* Exported operations. */

static inline int h_table_len(struct h_table *ht)
{
    return ht->len;
}

int h_table_iterate_safe(struct h_table *ht, void (*operate)(struct h_cache *),
        int max_duration, int min_per_sec );

int h_table_clear(struct h_table *ht);

struct h_cache *__h_cache_try_get(struct h_table *ht, void *key, u32 timeo,
        struct h_cache *(*create)(struct h_table *, void *),
        void (*modify)(struct h_cache *, void *) );

static inline struct h_cache *h_entry_try_get(struct h_table *ht, void *key, u32 timeo,
        struct h_cache *(*create)(struct h_table *, void *),
        void (*modify)(struct h_cache *, void *) )
{
    return __h_cache_try_get(ht, key, timeo, create, modify);
}
int h_cache_try_lookup(struct h_table *ht, void *key, void *result,  struct h_cache **ret_he,
		void (*action)(struct h_cache *, void *, void *) );

void h_entry_put(struct h_cache *he);
void h_entry_put_free(struct h_cache *he);

int __h_table_create(struct h_table *ht, enum __h_table_type table_type,
        struct h_bucket *base, size_t size, size_t max_len, long timeo,
        struct h_operations *ops, gfp_t flags,
        const char *proc_name, struct proc_dir_entry *proc_parent );

static inline int h_table_create(struct h_table *ht,
        struct h_bucket *base, size_t size, size_t max_len, long timeo,
        struct h_operations *ops, gfp_t flags,
        const char *proc_name, struct proc_dir_entry *proc_parent )
{
    return __h_table_create(ht, H_TABLE_TYPE_CACHE, base, size, max_len, timeo,
        ops, flags, proc_name, proc_parent);
}

int h_table_release(struct h_table *ht);


/* The following methods are usally for scalar and non-timer uses. */

int h_scalar_try_get(struct h_table *ht, void *key,
        struct h_scalar *(*create)(struct h_table *, void *),
        void (*modify)(struct h_scalar *, void *) );

int h_scalar_try_lookup(struct h_table *ht, void *key, void *result,
        void (*action)(struct h_scalar *, void *, void *) );

int h_scalar_try_free_key(struct h_table *ht, void *key);

int h_scalar_table_iterate_safe(struct h_table *ht, void (*operate)(struct h_scalar *));
int h_scalar_table_iterate_safe2(struct h_table *ht, void *p, void (*operate)(struct h_scalar *, void *));

void h_scalar_table_clear(struct h_table *ht);

void h_scalar_table_release(struct h_table *ht);
static inline int h_scalar_table_create(struct h_table *ht, struct h_bucket *base,
        size_t size, size_t max_len, struct h_scalar_operations *s_ops, gfp_t flags,
        const char *proc_name, struct proc_dir_entry *proc_parent )
{
    return __h_table_create(ht, H_TABLE_TYPE_SCALAR, base, size, max_len, 0,
        (struct h_operations *)s_ops, flags, proc_name, proc_parent);
}

#endif /* __H_TABLE_H */


