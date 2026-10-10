#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>  //kmalloc,kfree
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jhash.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include "utils/utils.h"
#include "defense/defense_inner.h"
#include "gnHead.h"
#include "h_cache.h"
/* --------- /proc interface part --------- */
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
#define GET_HCACHE_DATA(inode) pde_data(inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define GET_HCACHE_DATA(inode) PDE_DATA(inode)
#else
#define GET_HCACHE_DATA(inode) PDE(inode)->data
#endif
#endif


//#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static const struct proc_ops h_proc_fops;
#else
static const struct file_operations h_proc_fops;
#endif

static inline size_t h_table_len_inc(struct h_table *ht)
{
	size_t len;
	
	write_lock_bh(&ht->rwlock);
	len = ++ht->len;
	write_unlock_bh(&ht->rwlock);
	return len;
}

static inline size_t h_table_len_dec(struct h_table *ht)
{
	size_t len;
	
	write_lock_bh(&ht->rwlock);
	len = --ht->len;
	write_unlock_bh(&ht->rwlock);
	return len;
}

static inline size_t __h_table_len_dec(struct h_table *ht)
{
	size_t len;
	
	len = --ht->len;
	return len;
}

int h_table_iterate_safe(struct h_table *ht, void (*operate)(struct h_cache *),
		int max_duration, int min_per_sec )
{
	int i, count = 0;
	struct h_bucket *b;
	struct h_cache *he, *he_next;
	int max_per_sec = 0;
	long start_jiffies = jiffies;

	if(max_duration > 0)
	{
		max_per_sec = ht->len / max_duration;
		if(max_per_sec < min_per_sec)
			max_per_sec = min_per_sec;
	}
	
	for(i = 0; i < ht->size; i++)
	{
		b = &ht->base[i];
		spin_lock_bh(&b->lock);
		list_for_each_entry_safe(he, he_next, &b->chain, list)
		{
			if(operate)
				operate(he);
			count++;
		}
		spin_unlock_bh(&b->lock);
		
		/* Check the iteration rate. */
		if(max_duration > 0)
		{
			while(count * HZ > max_per_sec * (jiffies - start_jiffies))
			{
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(HZ / 10);
				set_current_state(TASK_RUNNING);
				if(kthread_should_stop())
				{
					set_current_state(TASK_RUNNING);
					goto out;
				}
			}
		}
	}/* for(i = 0; i < ht->size; i++) */

out:
	return count;
}

int h_cache_try_lookup(struct h_table *ht, void *key, void *result, struct h_cache **ret_he,
		void (*action)(struct h_cache *, void *, void *) )
{
	struct h_bucket *b = &ht->base[ht->ops->hash(key) & (ht->size - 1)];
	struct h_cache *he;
	
	spin_lock_bh(&b->lock);
	list_for_each_entry(he, &b->chain, list)
	{
		if(ht->ops->comp_key(he, key) == 0)
		{
			/* Invoke the callback to do modifications or return values. */
			if(action)
				action(he, key, result);
            *ret_he = he;
            he->timestamp = jiffies;
			spin_unlock_bh(&b->lock);
			return 0;
		}
	}
	spin_unlock_bh(&b->lock);
	
	/* Not found, return error code. */
	return -1;
}
#if 1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static void cache_timer_func(struct timer_list *data)
#else
static void cache_timer_func(unsigned long data)
#endif
{
    struct timer_list * timer = (struct timer_list *)data;
    struct h_cache *he = container_of(timer, struct h_cache, timer);
    struct h_table *ht = he->table;
	struct h_bucket *b = he->bucket;


    if(time_after_eq(jiffies, he->timestamp + he->timeo * HZ)) {
    //LOG_INFO("==timer [%p]--[%p]===timeout jiffies[%lu], timeout[%lu]\n", &he->timer, timer, jiffies, he->timestamp + he->timeo * HZ);
	    spin_lock_bh(&b->lock);
        list_del((struct list_head *)(&he->list));
	    spin_unlock_bh(&b->lock);
        //del_timer_sync(timer);
        ht->ops->release(he);
        h_table_len_dec(ht);
        return;
    }

    //he->expires = jiffies + he->timeo * HZ_1S;
    if (likely(is_close_net_business() == 0)) {
        mod_timer(timer, jiffies + 20 * HZ);
    }
}
#endif

struct h_cache *__h_cache_try_get(struct h_table *ht, void *key, u32 timeo,
		struct h_cache *(*create)(struct h_table *, void *),
		void (*modify)(struct h_cache *, void *) )
{
	struct h_bucket *b = &ht->base[ht->ops->hash(key) & (ht->size - 1)];
	struct h_cache *he;
	spin_lock_bh(&b->lock);
	list_for_each_entry(he, &b->chain, list)
	{
		if(ht->ops->comp_key(he, key) == 0)
		{
			/* Pop-up from idle queue when reference leaves 0. */
			if(++he->refs == 1)
			{
				//del_timer(&he->timer);
				spin_lock_bh(&ht->idle_lock);
				if(!list_entry_orphan(&he->idle_list))
					list_del(&he->idle_list);
				spin_unlock_bh(&ht->idle_lock);
			}
			/* Invoke the call back to do modifications. */
			if(modify)
				modify(he, key);
			spin_unlock_bh(&b->lock);
			return he;
		}
	}
	
	/* Not found, try to create a new entry. */
	if(unlikely(create == NULL))
	{
		spin_unlock_bh(&b->lock);
		return NULL;
	}
	
	/* If the table is full, try to recycle idle entries. */
	if(unlikely(h_table_len(ht) >= ht->max_len))
	{
		if(printk_ratelimit())
			//printk(KERN_WARNING "-- ht->len: %d, ht->max_len: %d\n", (int)ht->len, (int)ht->max_len);
			LOG_INFO("-- ht->len: %d, ht->max_len: %d\n", (int)ht->len, (int)ht->max_len);
		spin_unlock_bh(&b->lock);
		return NULL;
	}
	
	if(unlikely((he = create(ht, key)) == NULL))
	{
		spin_unlock_bh(&b->lock);
		return NULL;
	}
	/* Initialize the base class. */
	he->bucket = b;
	he->table = ht;
    if (timeo != 0) {
        he->timeo = timeo;
    } else if (ht->timeo != 0) {
        he->timeo = ht->timeo;
    } else {
        he->timeo = 0;
    }
	init_list_entry(&he->list);
	//init_timer(&he->timer);
	init_list_entry(&he->idle_list);
	he->last_put = 0;
	he->refs = 1;
	list_add(&he->list, &b->chain);
	spin_unlock_bh(&b->lock);
    he->timestamp = jiffies;
    if (he->timeo > 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        timer_setup(&he->timer, cache_timer_func, 0);
#else
        setup_timer(&he->timer, cache_timer_func,  (unsigned long)&he->timer);
#endif

        mod_timer(&he->timer, jiffies + 30 * HZ);
    }

	h_table_len_inc(ht);
	return he;
}

void h_entry_put(struct h_cache *he)
{
	struct h_table *ht = he->table;
	struct h_bucket *b = he->bucket;
	
	spin_lock_bh(&b->lock);
	if(--he->refs == 0)
	{
		/* Push unused entry to TAIL of the idle queue. */
		spin_lock_bh(&ht->idle_lock);
		if(list_entry_orphan(&he->idle_list))
		{
			/* Timer will check this to determine when it should be removed. */
			he->last_put = jiffies;
			list_add_tail(&he->idle_list, &ht->idle_queue);
		}
		else
		{
			printk(KERN_WARNING "%s(): [%s] entry(0x%08lx) is already in idle queue!\n",
				__FUNCTION__, ht->proc_name, (unsigned long)he);
		}
		spin_unlock_bh(&ht->idle_lock);
	}
	spin_unlock_bh(&b->lock);
}

/*
 * FIXME: Bug occurs, dangerous for calling!!!
 */
void h_entry_put_free(struct h_cache *he)
{
	struct h_table *ht = he->table;
	struct h_bucket *b = he->bucket;
	
	spin_lock_bh(&b->lock);
	//if(he->refs == 1)   /* !!!Tried fixing like this for test!!! */
	if(--he->refs == 0)
	{
		/* =============== Codes for test =============== */
		if(!list_entry_orphan(&he->idle_list))
		{
			printk(KERN_WARNING "%s(): [%s] entry(0x%08lx) is already in idle queue!\n",
				__FUNCTION__, ht->proc_name, (unsigned long)he);
		}
		/* ============================================== */
		
		list_del(&he->list);
		spin_unlock_bh(&b->lock);
		
        if (he->timeo > 0) {
            del_timer_sync(&he->timer);
        }
		ht->ops->release(he);
		h_table_len_dec(ht);
	}
	else
		spin_unlock_bh(&b->lock);
}

int h_table_clear(struct h_table *ht)
{
	int count = 0;
	struct h_bucket *b;
	struct h_cache *he;
	
	spin_lock_bh(&ht->idle_lock);
	while(!list_empty(&ht->idle_queue))
	{
		he = list_first_entry(&ht->idle_queue, struct h_cache, idle_list);
		b = he->bucket;

		/*
		 * NOTICE: __trylock__ MUST be used instead of __lock__,
		 *  otherwise it may stuck while racing the two locks!
		 */
		if(!spin_trylock_bh(&b->lock))
		{
			spin_unlock_bh(&ht->idle_lock);
			/* -------------------------- */
			goto out_next;
		}

		list_del(&he->idle_list);
		spin_unlock_bh(&ht->idle_lock);
		/* -------------------------- */
		list_del(&he->list);
		spin_unlock_bh(&b->lock);

		ht->ops->release(he);
		h_table_len_dec(ht);

		count++;
out_next:
		cond_resched();
		/* -------------------------- */
		spin_lock_bh(&ht->idle_lock);
	} /* while(!list_empty(&ht->idle_queue)) */
	spin_unlock_bh(&ht->idle_lock);

	return count;
}

static int h_table_clear_safe(struct h_table *ht)
{
	int i, count = 0;
	struct h_bucket *b;
	struct h_cache *he, *he_next;
	
	for(i = 0; i < ht->size; i++)
	{
		b = &ht->base[i];
		spin_lock_bh(&b->lock);
		list_for_each_entry_safe(he, he_next, &b->chain, list)
		{
            ht->ops->release(he);
            if (he->timeo > 0) {
		        spin_unlock_bh(&b->lock);
                del_timer_sync(&he->timer);
		        spin_lock_bh(&b->lock);
            }

        }
		spin_unlock_bh(&b->lock);
		
	}/* for(i = 0; i < ht->size; i++) */

out:
	return count;
}

int h_table_release(struct h_table *ht)
{
	size_t ht_len = ht->len;
	
	/* Remove `proc_fs` interface. */
	if(ht->proc_name)
		remove_proc_entry(ht->proc_name, ht->proc_parent);
	ht->proc_name = NULL;
	ht->proc_parent = NULL;
	
	if(ht->timeo_kthread)
		kthread_stop(ht->timeo_kthread);
	
	if(ht->base)
	{
		//if(h_table_clear(ht) != ht_len)
		//	return -EFAULT;
		h_table_clear(ht);
        h_table_clear_safe(ht);

		if(!ht->static_base)
			kfree(ht->base);
		ht->base = NULL;
	}
	ht->size = 0;
	
	return 0;
}

static int __h_table_timeo_kthread(void *data)
{
	struct h_table *ht = (struct h_table *)data;
	struct h_bucket *b;
	struct h_cache *he;
	
	set_current_state(TASK_RUNNING);
	while(!kthread_should_stop())
	{
		if(!list_empty(&ht->idle_queue))
		{
			spin_lock_bh(&ht->idle_lock);
			while(!list_empty(&ht->idle_queue))
			{
				he = list_first_entry(&ht->idle_queue, struct h_cache, idle_list);
				
				if( (jiffies - he->last_put <= HZ * ht->timeo) &&
					(h_table_len(ht) < ht->max_len * 9 / 10) )
					break;
				
				b = he->bucket;
				
				/*
				 * NOTICE: __trylock__ MUST be used instead of __lock__,
				 *  otherwise it may stuck while racing the two locks!
				 */
				if(!spin_trylock_bh(&b->lock))
				{
					spin_unlock_bh(&ht->idle_lock);
					//printk("-- %s(): [%s] b->lock is busy!\n", __FUNCTION__, ht->proc_name);
					/* -------------------------- */
					goto out_next;
				}
				
				// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				//if(list_entry_orphan(&he->idle_list))
				//{
				//	printk(KERN_WARNING "%s(): [%s] entry(0x%08lx) is alone, strange!!!\n",
				//		__FUNCTION__, ht->proc_name, (unsigned long)he);
				//}
				// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				list_del(&he->idle_list);
				spin_unlock_bh(&ht->idle_lock);
				/* -------------------------- */
				// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				//{
				//	if(he->refs != 0)
				//		printk(KERN_WARNING "%s(): [%s] entry(0x%08lx) has non-zero reference!!\n",
				//			__FUNCTION__, ht->proc_name, (unsigned long)he);
				//}
				// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				list_del(&he->list);
				spin_unlock_bh(&b->lock);
				
				ht->ops->release(he);
				h_table_len_dec(ht);
out_next:
				cond_resched();
				/* -------------------------- */
				spin_lock_bh(&ht->idle_lock);
			} /* while(!list_empty(&ht->idle_queue)) */
			spin_unlock_bh(&ht->idle_lock);
		}
		
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ * 1);
		set_current_state(TASK_RUNNING);
	}
	set_current_state(TASK_RUNNING);
	
	return 0;
}

int h_scalar_try_get(struct h_table *ht, void *key,
		struct h_scalar *(*create)(struct h_table *, void *),
		void (*modify)(struct h_scalar *, void *) )
{
	struct h_bucket *b = &ht->base[ht->s_ops->hash(key) & (ht->size - 1)];
	struct h_scalar *he;

	spin_lock_bh(&b->lock);
	list_for_each_entry(he, &b->chain, list)
	{
		if(ht->s_ops->comp_key(he, key) == 0)
		{
			/* Invoke the callback to do modifications. */
			if(modify)
				modify(he, key);
			spin_unlock_bh(&b->lock);
			return 0;
		}
	}
	
	/* Not found, try to create a new entry. */
	if(create == NULL)
	{
		spin_unlock_bh(&b->lock);
		return -1;
	}
	
	if((he = create(ht, key)) == NULL)
	{
		spin_unlock_bh(&b->lock);
		return 0;
	}
	/* Intialize the base class. */
	he->bucket = b;
	he->table = ht;
	init_list_entry(&he->list);
	//INIT_RCU_HEAD(&he->rcu);
	list_add_rcu(&he->list, &b->chain);
	spin_unlock_bh(&b->lock);
	
	h_table_len_inc(ht);
	
	return 0;
}

int h_scalar_try_lookup(struct h_table *ht, void *key, void *result,
		void (*action)(struct h_scalar *, void *, void *) )
{
	struct h_bucket *b = &ht->base[ht->s_ops->hash(key) & (ht->size - 1)];
	struct h_scalar *he;
	
	rcu_read_lock();
	list_for_each_entry(he, &b->chain, list)
	{
		if(ht->s_ops->comp_key(he, key) == 0)
		{
			/* Invoke the callback to do modifications or return values. */
			if(action)
				action(he, key, result);
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();
	
	/* Not found, return error code. */
	return -1;
}

static void h_scalar_free_rcu(struct rcu_head *rcu)
{
	struct h_scalar *he = container_of(rcu, struct h_scalar, rcu);
	struct h_table *ht = he->table;
	
	ht->s_ops->release(he);
	h_table_len_dec(ht);
}

int h_scalar_try_free_key(struct h_table *ht, void *key)
{
	struct h_bucket *b = &ht->base[ht->s_ops->hash(key) & (ht->size - 1)];
	struct h_scalar *he;
	
	spin_lock_bh(&b->lock);
	list_for_each_entry(he, &b->chain, list)
	{
		if(ht->s_ops->comp_key(he, key) == 0)
		{
			list_del_rcu(&he->list);
			spin_unlock_bh(&b->lock);
			call_rcu(&he->rcu, h_scalar_free_rcu);
			return 0;
		}
	}
	spin_unlock_bh(&b->lock);
	
	return -1;
}

int h_scalar_table_iterate_safe(struct h_table *ht, void (*operate)(struct h_scalar *))
{
	int i, count = 0;
	struct h_bucket *b;
	struct h_scalar *he, *he_next;
	
	for(i = 0; i < ht->size; i++)
	{
		b = &ht->base[i];
		spin_lock_bh(&b->lock);
		list_for_each_entry_safe(he, he_next, &b->chain, list)
		{
			if(operate)
				operate(he);
			count++;
		}
		spin_unlock_bh(&b->lock);
	}/* for(i = 0; i < ht->size; i++) */
	
	return count;
}

int h_scalar_table_iterate_safe2(struct h_table *ht, void *p, void (*operate)(struct h_scalar *, void *))
{
	int i, count = 0;
	struct h_bucket *b;
	struct h_scalar *he, *he_next;
	
	for(i = 0; i < ht->size; i++)
	{
		b = &ht->base[i];
		spin_lock_bh(&b->lock);
		list_for_each_entry_safe(he, he_next, &b->chain, list)
		{
			if(operate)
				operate(he, p);
			count++;
		}
		spin_unlock_bh(&b->lock);
	}/* for(i = 0; i < ht->size; i++) */
	
	return count;
}

void h_scalar_table_clear(struct h_table *ht)
{
	int i, count = 0;
	struct h_bucket *b;
	struct h_scalar *he, *he_next;
	
	for(i = 0; i < ht->size; i++)
	{
		b = &ht->base[i];
		spin_lock_bh(&b->lock);
		list_for_each_entry_safe(he, he_next, &b->chain, list)
		{
			list_del_rcu(&he->list);
			call_rcu(&he->rcu, h_scalar_free_rcu);
			count++;
		}
		spin_unlock_bh(&b->lock);
	}/* for(i = 0; i < ht->size; i++) */
}

void h_scalar_table_release(struct h_table *ht)
{
	/* Remove `proc_fs` interface. */
	if(ht->proc_name)
		remove_proc_entry(ht->proc_name, ht->proc_parent);
	ht->proc_name = NULL;
	ht->proc_parent = NULL;
	
	if(ht->base)
	{
		int i, count = 0;
		struct h_bucket *b;
		struct h_scalar *he, *he_next;
		
		for(i = 0; i < ht->size; i++)
		{
			b = &ht->base[i];
			spin_lock_bh(&b->lock);
			list_for_each_entry_safe(he, he_next, &b->chain, list)
			{
				list_del_rcu(&he->list);
				ht->s_ops->release(he);
				h_table_len_dec(ht);
				count++;
			}
			spin_unlock_bh(&b->lock);
		}/* for(i = 0; i < ht->size; i++) */
		
		if(!ht->static_base)
			kfree(ht->base);
		ht->base = NULL;
	}
	ht->size = 0;
}



/*
 * h_table_create: Initialize a new hash table.
 * Parameters: 
 *  @ht: `h_table` structure, already allocated or static,
 *  @base: optional argument, used for large sized hash table,
 *  @size: hash size,
 *  @max_len: maximum entries,
 *  @timeo: idle timeout secs.,
 *  @ops: operation collections for hash table,
 *  @proc_name: `proc_fs` interface filename,
 *  @proc_parent: `proc_fs` parent directory.
 * return value:
*   0 for success, <0 for error codes, use `errno` standards.
 */
int __h_table_create(struct h_table *ht, enum __h_table_type table_type,
		struct h_bucket *base, size_t size, size_t max_len, long timeo,
		struct h_operations *ops, gfp_t flags,
		const char *proc_name, struct proc_dir_entry *proc_parent )
{
	struct h_bucket *b;
	size_t __size;
	int i;
	struct proc_dir_entry *ent;
	
	memset(ht, 0x0, sizeof(ht[0]));
	
	for(__size = size - 1, i = 0; __size; __size >>= 1, i++);
	__size = (1UL << i);
	if(size != __size)
	{
		printk(KERN_WARNING "%s() Warning: size '%lu' is accepted as '%lu'.\n",
			__FUNCTION__, (unsigned long)size, (unsigned long)__size);
		size = __size;
	}
	
	if(base)
	{
		ht->base = base;
		ht->static_base = true;
	}
	else
	{
		if((ht->base = (struct h_bucket *)kmalloc(sizeof(struct h_bucket) * size, flags)) == NULL)
			return -ENOMEM;
		ht->static_base = false;
	}
	
	for(i = 0; i < size; i++)
	{
		b = &ht->base[i];
		INIT_LIST_HEAD(&b->chain);
		spin_lock_init(&b->lock);
	}
	ht->size  = size;
	ht->max_len   = max_len;
	ht->timeo = timeo;
	ht->ops   = ops;
	ht->len   = 0;
	rwlock_init(&ht->rwlock);
	
	/* Initialization for idle queue. */
	INIT_LIST_HEAD(&ht->idle_queue);
	spin_lock_init(&ht->idle_lock);
	
	switch(table_type)
	{
	case H_TABLE_TYPE_CACHE:
		ht->table_type = table_type;
		
		/* Setup idle queue timeout checking timer. */
		if(ht->timeo > 0)
		{


			static int ht_index = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
            static DEFINE_SPINLOCK(ht_index_lock);
#else
            static spinlock_t ht_index_lock = SPIN_LOCK_UNLOCKED;
#endif
			int n;
			
			spin_lock_bh(&ht_index_lock);
			n = ht_index++;
			spin_unlock_bh(&ht_index_lock);
			
			if((ht->timeo_kthread = kthread_create(__h_table_timeo_kthread, ht, "h_cache_%d", n)))
				wake_up_process(ht->timeo_kthread);
		}
		
		/* Register `proc_fs` operations. */
		ht->proc_parent = proc_parent;
		ht->proc_name = NULL;
		if(proc_name)
		{
			ent = proc_create_data(proc_name,
				(ops->build_line ? 0444 : 0000) | (ops->operate_cmd ? 0200 : 0000),
				proc_parent, &h_proc_fops, (void *)ht );
			if(ent)
				ht->proc_name = kstrdup(proc_name, flags);
		}
		
		break;
	case H_TABLE_TYPE_SCALAR:
		ht->table_type = table_type;
		
		/* Register `proc_fs` operations. */
		ht->proc_parent = proc_parent;
		ht->proc_name = NULL;
		if(proc_name)
		{
			struct h_scalar_operations *s_ops = (struct h_scalar_operations *)ops;
			
			ent = proc_create_data(proc_name,
				(s_ops->build_line ? 0444 : 0000) | (s_ops->operate_cmd ? 0200 : 0000),
				proc_parent, &h_proc_fops, (void *)ht );
			if(ent)
				ht->proc_name = kstrdup(proc_name, flags);
		}
		break;
	default:
		printk(KERN_ERR "Invalid table type %d.\n", table_type);
		return -EINVAL;
	}
	
	return 0;
}


/* `proc_fs` interface operations. */ 

struct h_proc_info
{
	struct h_table *h_table;
	int     hash_pos;
	char   *rbuf;
	size_t  rbuf_sz;
	size_t  rbuf_len;
	size_t  rpos;

#define H_PROC_WBUF_SZ  512
	char    wbuf[H_PROC_WBUF_SZ + 20];
	size_t  wbuf_sz;
	size_t  wpos;
};

static int h_proc_open(struct inode *inode, struct file *file)
{
	struct h_proc_info *proc;
	
	if((proc = (struct h_proc_info *)kmalloc(sizeof(struct h_proc_info), GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memset(proc, 0x0, sizeof(struct h_proc_info));
	file->private_data = proc;
	
	proc->h_table = (struct h_table *)OSEC_PDE_DATA(inode);
	proc->rbuf = NULL;
	proc->hash_pos = 0;
	proc->rbuf_sz = 0;
	proc->rbuf_len = 0;
	proc->rpos = 0;
	
	proc->wbuf_sz = H_PROC_WBUF_SZ;
	proc->wpos = 0;
	
	return 0;
}

static int h_proc_release(struct inode *inode, struct file *file)
{
	struct h_proc_info *proc = (struct h_proc_info *)file->private_data;
	struct h_table *ht = proc->h_table;
	
	if(proc->wpos > 0)
	{
		char *cmd;
		
		if((cmd = kstrndup(proc->wbuf, proc->wpos, GFP_KERNEL)))
		{
			switch(ht->table_type)
			{
			case H_TABLE_TYPE_CACHE:
				if(ht->ops->operate_cmd)
					ht->ops->operate_cmd(ht, cmd);
				break;
			case H_TABLE_TYPE_SCALAR:
				if(ht->s_ops->operate_cmd)
					ht->s_ops->operate_cmd(ht, cmd);
				break;
			}
			kfree(cmd);
		}
	}
	
	/* Release the read buffer on close */
	if(proc->rbuf)
		kfree(proc->rbuf);
	kfree(proc);
	file->private_data = NULL;
	
	return 0;
}

static ssize_t h_proc_read(struct file *file, char __user *data, size_t count, loff_t *f_pos)
{
	
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

	struct h_proc_info *proc = (struct h_proc_info *)file->private_data;
	struct h_table *ht = proc->h_table;
	struct h_bucket *b;
	struct h_cache *he;
	//size_t roffset = 0;  /* current offset of `data` */
	size_t len;
	
	switch(ht->table_type)
	{
	case H_TABLE_TYPE_CACHE:
		if(ht->ops->build_line == NULL)
			return -EIO;
		break;
	case H_TABLE_TYPE_SCALAR:
		if(ht->s_ops->build_line == NULL)
			return -EIO;
		break;
	default:
		return -EIO;
	}
	
	if(proc->rbuf == NULL)
	{
		proc->rbuf_sz = 1024;
		if((proc->rbuf = (char *)kmalloc(proc->rbuf_sz, GFP_KERNEL)) == NULL)
			return -ENOMEM;
	}
	
	if(proc->rpos >= proc->rbuf_len)
	{
		do
		{
			if(proc->hash_pos >= ht->size)
				return 0;
		} while(list_empty(&(b = &ht->base[proc->hash_pos++])->chain));
		proc->rbuf_len = 0;
		
		spin_lock_bh(&b->lock);
		list_for_each_entry(he, &b->chain, list)
		{
			char *line = NULL;
			size_t line_len;
			
			switch(ht->table_type)
			{
			case H_TABLE_TYPE_CACHE:
				if((line = ht->ops->build_line(he, GFP_ATOMIC)) == NULL)
					continue;
				break;
			case H_TABLE_TYPE_SCALAR:
				if((line = ht->s_ops->build_line((struct h_scalar *)he, GFP_ATOMIC)) == NULL)
					continue;
				break;
			default:
				return -EIO;
			}
			
			line_len = strlen(line);
			
			if(proc->rbuf_len + line_len >= proc->rbuf_sz)
			{
				/* Enlarge the buffer size */
				size_t rbuf_sz = proc->rbuf_sz;
				while(proc->rbuf_len + line_len >= rbuf_sz)
					rbuf_sz *= 2;
				if((proc->rbuf = (char *)krealloc(proc->rbuf, rbuf_sz, GFP_ATOMIC)) == NULL)
				{
					spin_unlock_bh(&b->lock);
					return -ENOMEM;
				}
				proc->rbuf_sz = rbuf_sz;
			}
			/* Write the session line to buffer */
			memcpy(proc->rbuf + proc->rbuf_len, line, line_len);
			kfree(line);
			proc->rbuf_len += line_len;
		}
		spin_unlock_bh(&b->lock);
		proc->rpos = 0;
	} /* if(proc->rpos >= proc->rbuf_len) */
	
	/* Write to userspace */
	len = proc->rbuf_len - proc->rpos;
	if(count < len)
		len = count;
	if(copy_to_user(data, proc->rbuf + proc->rpos, len))
		return -EFAULT;
	proc->rpos += len;

	return len;
}

static ssize_t h_proc_write(struct file *file, const char __user *data, size_t count, loff_t *f_pos)
{
	struct h_proc_info *proc = (struct h_proc_info *)file->private_data;
	struct h_table *ht = proc->h_table;
	size_t len;
	size_t __count = count;
	char *ln_start, *ln_end;
    if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) !=0) {
        return -EINVAL;
    }


	while(count > 0)
	{
		len = proc->wbuf_sz - proc->wpos;
		if(count < len)
			len = count;
		if(len == 0)
		{
			printk(KERN_WARNING "Warning: [%s] Command is too long.\n", ht->proc_name);
			return -EINVAL;
		}
		
		if(copy_from_user(proc->wbuf + proc->wpos, data, len))
			return -EFAULT;
		proc->wpos += len;
		
		/* Pick out each possible line */
		for(ln_start = proc->wbuf;
			ln_start < proc->wbuf + proc->wpos &&
			( ln_end = (char *)memchr(ln_start, '\n', (size_t)(proc->wbuf + proc->wpos - ln_start)) );
			ln_start = ln_end + 1)
		{
			*ln_end = '\0';
			/* Parse and do operations on current line*/
			if(ln_end - ln_start > 0)
			{
				int ret;
				
				switch(ht->table_type)
				{
				case H_TABLE_TYPE_CACHE:
					if(ht->ops->operate_cmd)
						ret = ht->ops->operate_cmd(ht, ln_start);
					else
					{
						proc->wpos = 0;
						return -EIO;
					}
					break;
				case H_TABLE_TYPE_SCALAR:
					if(ht->s_ops->operate_cmd)
						ret = ht->s_ops->operate_cmd(ht, ln_start);
					else
					{
						proc->wpos = 0;
						return -EIO;
					}
					break;
				default:
					return -EIO;
				}
				if(ret < 0)
				{
					proc->wpos = 0;
					return ret;
				}
			}
		}
		/* Move the incomplete line data ahead */
		if(ln_start > proc->wbuf)
		{
			if(ln_start < proc->wbuf + proc->wpos)
			{
				size_t remained = (size_t)(proc->wbuf + proc->wpos - ln_start);
				memmove(proc->wbuf, ln_start, remained);
				proc->wpos = remained;
			}
			else
				proc->wpos = 0;
		}
		
		data += len;
		count -= len;
	}

	return __count - count;
}

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static const struct proc_ops h_proc_fops =
{
	//.owner   = THIS_MODULE,
	.proc_read    = h_proc_read,
	.proc_write   = h_proc_write,
	.proc_open    = h_proc_open,
	.proc_release = h_proc_release,
    .proc_lseek   = default_llseek,
};
#else
static const struct file_operations h_proc_fops =
{
	.owner   = THIS_MODULE,
	.read    = h_proc_read,
	.write   = h_proc_write,
	.open    = h_proc_open,
	.release = h_proc_release,
    .llseek   = default_llseek,
};

#endif

EXPORT_SYMBOL(h_table_iterate_safe);
EXPORT_SYMBOL(__h_cache_try_get);
EXPORT_SYMBOL(h_cache_try_lookup);
EXPORT_SYMBOL(h_entry_put);
EXPORT_SYMBOL(h_entry_put_free);
EXPORT_SYMBOL(h_table_clear);
EXPORT_SYMBOL(h_table_release);

EXPORT_SYMBOL(h_scalar_try_get);
EXPORT_SYMBOL(h_scalar_try_lookup);
EXPORT_SYMBOL(h_scalar_try_free_key);
EXPORT_SYMBOL(h_scalar_table_iterate_safe);
EXPORT_SYMBOL(h_scalar_table_clear);
EXPORT_SYMBOL(h_scalar_table_release);

EXPORT_SYMBOL(__h_table_create);
