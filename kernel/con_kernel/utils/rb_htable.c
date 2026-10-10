#include "core/kvd_memcache.h"
#include "core/kvd_core.h"
#include "rb_htable.h"
#include "gnHead.h"


static struct rb_ht_entry* rb_ht_entry_create(struct vsec_rb_htable* ht,
									void* key,size_t key_len,
									void* data)
{
	int rc = -EINVAL;
	struct rb_ht_entry* entry = NULL;

	if(!ht || !key || !key_len) { goto out; }

	rc = -ENOMEM;
	//此处可能会在中断中使用，不要休眠
	entry = kvd_mem_cache_zalloc(ht->cachep,GFP_ATOMIC);
	if(!entry) { goto out; }

	rc = 0;
	entry->key = key;
	entry->data = data;
	entry->key_len = key_len;

out:
	if(rc) { entry = ERR_PTR(rc); }
	return entry;
}

static void rb_ht_entry_free(struct vsec_rb_htable* ht,struct rb_ht_entry* entry)
{
	if(!entry) { return; }

	ht->free_fn(ht,entry->key,
				entry->key_len,
				entry->data);
				
	kvd_mem_cache_free(ht->cachep,entry);
}

static int rb_ht_entry_insert(struct vsec_rb_htable* ht,
							struct rb_root *root,
							struct rb_ht_entry* entry)
{
	int rc = -EINVAL;
    struct rb_node **new = NULL;
	struct rb_node* parent = NULL;
	
	if(!root || !entry) {
		return rc;
	}

	rc = -EEXIST;
	new = &(root->rb_node);
    /* Figure out where to put new node */
    while (*new) {
		int res = 0;
        struct rb_ht_entry *this = NULL;
		
		this = container_of(*new,struct rb_ht_entry, node);
		res = ht->cmp_fn(entry->key,entry->key_len,
						this->key,this->key_len);
        parent = *new;
        if (res < 0)
            new = &((*new)->rb_left);
        else if (res > 0)
            new = &((*new)->rb_right);
        else
            return rc;
    }

    /* Add new node and rebalance tree. */
	rc = 0;
    rb_link_node(&entry->node, parent, new);
    rb_insert_color(&entry->node, root);

    return rc;
}

static struct rb_ht_entry* rb_ht_entry_search(struct vsec_rb_htable* ht,
						struct rb_root* root,void* key,size_t key_len)
{
    struct rb_node *node = NULL;
	struct rb_ht_entry* entry = ERR_PTR(-EINVAL);

	if(!ht || !root || !key || !key_len) {
		return entry;
	}
	
	entry = ERR_PTR(-ENOENT);
	node = root->rb_node;
    while (node) {
        int res = 0;
		struct rb_ht_entry* data = NULL;

		data = container_of(node,struct rb_ht_entry, node);
		res = ht->cmp_fn(key,key_len,
				data->key,data->key_len);
        if (res < 0)
            node = node->rb_left;
        else if (res > 0)
            node = node->rb_right;
        else {
			entry = data;
			break;
		}
    }

    return entry;
}

static struct rb_ht_entry* 
rb_ht_entry_pop(struct vsec_rb_htable* ht,
				struct rb_root* root,
				void* key,size_t key_len)
{
	struct rb_ht_entry* entry = NULL;

	entry = rb_ht_entry_search(ht,
				root,key,key_len);
	if(!IS_ERR(entry)) { 
		rb_erase(&entry->node,root);
	}

	return entry;
}

static unsigned rb_ht_entry_cleanup(struct vsec_rb_htable* ht,
				struct rb_root* root,void* ctx,
				int (*filter)(void* key,size_t key_len,void* data,void* ctx))
{
	unsigned count = 0;
	struct rb_node* next = NULL;
	struct rb_node* node = NULL;
	struct rb_ht_entry* entry = NULL;

	for (node = rb_first(root); node; node = next) {
		next = rb_next(node);
		entry = rb_entry(node,struct rb_ht_entry,node);

		if(filter) { 
			int bclean = filter(entry->key,
							entry->key_len,
							entry->data,ctx);
			if(!bclean) { continue; }
		}

		rb_erase(&entry->node,root);
		rb_ht_entry_free(ht,entry);
		count++;
	}

	return count;
}

static void rb_ht_entry_walk(struct rb_root* root,void* ctx,
			void (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
	struct rb_node* node = NULL;
	struct rb_ht_entry* entry = NULL;

	for (node = rb_first(root); node; node = rb_next(node)) {
		entry = rb_entry(node,struct rb_ht_entry,node);
		cb(entry->key,entry->key_len,entry->data,ctx);
	}
}

static uint32_t calc_rb_ht_idx(struct vsec_rb_htable* ht,
                        void* key,size_t key_len)
{
    uint32_t idx = 0;
    uint32_t hval = 0;

    hval = ht->hash_fn(key,key_len);
    idx = hval % ht->nbucket;

    return idx;
}

int vsec_rb_htable_insert(struct vsec_rb_htable* ht,
				void* key,size_t key_len,void* data)
{
	int rc = -EINVAL;
	uint32_t idx = 0;
    unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;
	struct rb_ht_entry* entry = NULL;

	if(!ht || !key || !key_len) {
		return rc;
	}

	rc = -ENOMEM;
	idx = calc_rb_ht_idx(ht,key,key_len);
	entry = rb_ht_entry_create(ht,key,
						key_len,data);
	if(IS_ERR(entry)) { return rc; }

	plock = ht->locks + idx;
	proot = &ht->ht_roots[idx];
	
	write_lock_irqsave(plock,flags);
	rc = rb_ht_entry_insert(ht,proot,entry);
	write_unlock_irqrestore(plock,flags);

	//这里不要调用rb_ht_entry_free，
	//因为key与data在此处失败返回后应该由外围负责直接释放
	if(rc) { kvd_mem_cache_free(ht->cachep,entry); }

	return rc;
}

int vsec_rb_htable_exist(struct vsec_rb_htable* ht,void* key,size_t len)
{
	int bexist = 0;
	uint32_t idx = 0;
    unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;
	struct rb_ht_entry* entry = NULL;

	if(!ht || !key || !len) {
		return bexist;
	}

	idx = calc_rb_ht_idx(ht,key,len);
	
	plock = ht->locks + idx;
	proot = &ht->ht_roots[idx];
	
	read_lock_irqsave(plock,flags);
	entry = rb_ht_entry_search(ht,proot,key,len);
	read_unlock_irqrestore(plock,flags);
	bexist = !IS_ERR(entry);

	return bexist;
}

int vsec_rb_htable_delete(struct vsec_rb_htable* ht,void* key,size_t len)
{
	int rc = -EINVAL;
	uint32_t idx = 0;
    unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;
	struct rb_ht_entry* entry;

	if(!ht || !key || !len) {
		return rc;
	}

	idx = calc_rb_ht_idx(ht,key,len);

	plock = ht->locks + idx;
	proot = &ht->ht_roots[idx];
	
	write_lock_irqsave(plock,flags);
	entry = rb_ht_entry_pop(ht,proot,key,len);
	write_unlock_irqrestore(plock,flags);

	if(!IS_ERR(entry)) {
		rc = 0;
		rb_ht_entry_free(ht,entry);
	} else {
		rc = PTR_ERR(entry);
	}

	return rc;
}

//此处我们通过cb将hash-data给返回，而不是将key一同返回
//是因为我们认为get操作不会做任何修改及释放操作，
//此处一定不要释放或者修改data，否则极有可能会崩溃
int vsec_rb_htable_get(struct vsec_rb_htable* ht,
			void* key,size_t key_len,void* ctx,
			void (*cb)(void* data,void* ctx))
{
	int rc = -EINVAL;
	uint32_t idx = 0;
    unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;
	struct rb_ht_entry* entry;

	if(!ht || !key || !key_len) {
		return rc;
	}

	idx = calc_rb_ht_idx(ht,key,key_len);
	plock = ht->locks + idx;
	proot = &ht->ht_roots[idx];
	
	rc = 0;
	read_lock_irqsave(plock,flags);
	//get操作不会做修改及释放操作
	//而pop会把entry从rb中移除
	//此处应使用search
	entry = rb_ht_entry_search(ht,proot,
						key,key_len);
	if(!IS_ERR(entry)) {
		cb(entry->data,ctx);
	}
	read_unlock_irqrestore(plock,flags);

	if(IS_ERR(entry)) {
		rc = PTR_ERR(entry);
	}

	return rc;
}

//此处的pop操作，我们同时通过cb返回key,data
//key,data可能被修改或者释放都不会有问题
int vsec_rb_htable_pop(struct vsec_rb_htable* ht,
        void* key,size_t key_len,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
	int rc = -EINVAL;
	uint32_t idx = 0;
    unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;
	struct rb_ht_entry* entry;

	if(!ht || !key || !key_len) {
		return rc;
	}

	idx = calc_rb_ht_idx(ht,key,key_len);
	plock = ht->locks + idx;
	proot = &ht->ht_roots[idx];
	
	rc = 0;
	write_lock_irqsave(plock,flags);
	entry = rb_ht_entry_pop(ht,proot,
						key,key_len);
	write_unlock_irqrestore(plock,flags);

	if(IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		return rc;
	}

	cb(entry->key,entry->key_len,
		entry->data,ctx);
	kvd_mem_cache_free(ht->cachep,entry);

	return rc;
}

int vsec_rb_htable_empty(struct vsec_rb_htable* ht)
{
    int i = 0;
    int rc = 1;
    unsigned long flags;
    rwlock_t* plock = NULL;
    struct rb_root* proot = NULL;

    if(!ht || !ht->name || 
        !ht->locks || !ht->ht_roots) 
    {
        return rc;
    }

    for(;i < ht->nbucket;i++) {
        plock = ht->locks + i;
        proot = ht->ht_roots + i;

        read_lock_irqsave(plock,flags);
		rc = RB_EMPTY_ROOT(proot);
        read_unlock_irqrestore(plock,flags);
		if (!rc) { break; }
    }

    return rc;
}

//清理hash表元素，
//返回值0或大于0的值-->均表示成功,此时是清理的元素个数
//小于0是错误,返回值就是错误码
int vsec_rb_htable_cleanup(struct vsec_rb_htable* ht)
{
	size_t i = 0;
	int count = 0;
    unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;

	for(;i < ht->nbucket;i++) {
		struct rb_root dup_root;
		plock = ht->locks + i;
		proot = ht->ht_roots + i;

		write_lock_irqsave(plock,flags);
		dup_root = *proot;
		proot->rb_node = NULL;
		write_unlock_irqrestore(plock,flags);
		count += rb_ht_entry_cleanup(ht,
					&dup_root,NULL,NULL);
	}

	return count;
}

//本函数只允许以只读方式遍历
int vsec_rb_htable_walk(struct vsec_rb_htable* ht,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
	size_t i = 0;
    unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;

	if(!ht || !ht->name || 
		!ht->locks || !ht->ht_roots) 
	{
		return -EINVAL;
	}

	for(;i < ht->nbucket;i++) {
		plock = ht->locks + i;
		proot = ht->ht_roots + i;

		read_lock_irqsave(plock,flags);
		rb_ht_entry_walk(proot,ctx,cb);
		read_unlock_irqrestore(plock,flags);
	}

	return 0;
}

//清理满足条件的hash表元素，
//返回值0或大于0的值-->均表示成功,此时是清理的元素个数
//小于0是错误,返回值就是错误码
//filter-->返回非0值表示满足条件，0-->表示不满足条件
int vsec_rb_htable_clean_items(struct vsec_rb_htable* ht,void* ctx,
        int (*filter)(void* key,size_t key_len,void* data,void* ctx))
{
	size_t i = 0;
	int count = 0;
    unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;

	if(!ht || !ht->name || 
		!ht->locks || !ht->ht_roots) 
	{
		return -EINVAL;
	}

	for(;i < ht->nbucket;i++) {
		plock = ht->locks + i;
		proot = ht->ht_roots + i;

		write_lock_irqsave(plock,flags);
		count += rb_ht_entry_cleanup(ht,proot,
							ctx,filter);
		write_unlock_irqrestore(plock,flags);
	}

	return count;
}

int vsec_rb_htable_init(struct vsec_rb_htable* ht,
				const char* name,
				void* ctx,int nbucket,
				vsec_rb_ht_cmp_fn_t cmp_fn,
				vsec_rb_ht_hash_fn_t hash_fn,
				vsec_rb_ht_free_fn_t free_fn)
{
	int i = 0;
    int rc = -EINVAL;
    rwlock_t* plocks = NULL;
    struct rb_root* roots = NULL;

    if(!ht || !name || nbucket <= 0) {
        return rc;
    }

    rc = -ENOMEM;
    ht->name = kstrdup(name,GFP_KERNEL);
    if(!ht->name) { return rc; }

    ht->cachep = kvd_mem_cache_create(name,
                sizeof(struct rb_ht_entry),0);
    if(!ht->cachep) {
        kfree(ht->name);
        return rc;
    }

    roots = kzalloc(nbucket * sizeof(struct rb_root),
                    GFP_KERNEL);
    if(!roots) {
        kfree(ht->name);
        kvd_mem_cache_destroy(ht->cachep);
        return rc;
    }

    plocks = kzalloc(nbucket * sizeof(rwlock_t),
                    GFP_KERNEL);
    if(!plocks) {
        kfree(roots);
        kfree(ht->name);
        kvd_mem_cache_destroy(ht->cachep);
        return rc;
    }

    for(;i < nbucket;i++) {
        roots[i].rb_node = NULL;
        rwlock_init(plocks + i);
    }

    rc = 0;
    ht->debug = 0;
	ht->ht_ctx = ctx;
    ht->nbucket = nbucket;
    ht->cmp_fn = cmp_fn;
    ht->hash_fn = hash_fn;
    ht->free_fn = free_fn;
    ht->ht_roots = roots;
    ht->locks = plocks;

    LOG_DEBUG("init rb-hash table: %s ok\n",
            ht->name);
    return rc;
}


void vsec_rb_htable_uninit(struct vsec_rb_htable* ht)
{
    if(!ht) { return; }

    if(ht->name) { 
        LOG_DEBUG("uninit rb-hash table: %s\n",
                ht->name);

        kfree(ht->name);
        ht->name = NULL;
    }

    if(ht->ht_roots) {
        kfree(ht->ht_roots);
        ht->ht_roots = NULL;
    }

    if(ht->locks) {
        kfree(ht->locks);
        ht->locks = NULL;
    }

    if(ht->cachep) {
        kvd_mem_cache_destroy(ht->cachep);
        ht->cachep = NULL;
    }
}

void vsec_rb_htable_debug(struct vsec_rb_htable* ht,int bon)
{
    if(bon) { 
        set_bit(0,&ht->debug);
    } else {
        clear_bit(0,&ht->debug);
    }
}

int vsec_rb_htable_upgrade(struct vsec_rb_htable *ht, void *key, size_t key_len,
        void *data, void (*cb)(void *old, void *data))
{
    int rc;
    uint32_t idx;
    unsigned long flags;
    rwlock_t *plock;
    struct rb_root *proot;
    struct rb_ht_entry *entry, *old = NULL;

    if (!ht || !data || !key || !key_len) {
        return -EINVAL;
    }

    entry = rb_ht_entry_create(ht, key, key_len, data);
    if (KVD_IS_ERR_OR_NULL(entry)) {
        return -ENOMEM;
    }
    idx = calc_rb_ht_idx(ht, key, key_len);
    plock = &ht->locks[idx];
    proot = &ht->ht_roots[idx];

    write_lock_irqsave(plock, flags);
    old = rb_ht_entry_pop(ht, proot, key, key_len);
    if (!KVD_IS_ERR_OR_NULL(old) && cb) {
        cb(old->data, entry->data);
    }
    rc = rb_ht_entry_insert(ht, proot, entry);
    write_unlock_irqrestore(plock, flags);

    if (!KVD_IS_ERR_OR_NULL(old)) {
        rb_ht_entry_free(ht, old);
    }
    if (rc) {
        kvd_mem_cache_free(ht->cachep, entry);
    }

    return rc;
}
