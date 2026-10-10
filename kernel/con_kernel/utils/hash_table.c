#include "hash_table.h"
#include "core/kvd_memcache.h"
#include "gnHead.h"

typedef struct {
    void* key;
    size_t key_len;
    void* data;
    struct hlist_node node;
}vsec_htable_node_t;


int vsec_htable_init(vsec_htable_t* htable,
            const char* name,
			void* htctx,
			int nbucket,
            vsec_htable_cmp_fn_t cmp_fn,
            vsec_htable_hash_fn_t hash_fn,
            vsec_htable_free_fn_t free_fn)
{
    int i = 0;
    int rc = -EINVAL;
    rwlock_t* plocks = NULL;
    kvd_blm_hval_t* pblms = NULL;
    struct hlist_head* heads = NULL;

    if(!htable || !name || nbucket <= 0) {
        return rc;
    }

    rc = -ENOMEM;
    htable->name = kstrdup(name,GFP_KERNEL);
    if(!htable->name) { return rc; }

    htable->cachep = kvd_mem_cache_create(name,
                    sizeof(vsec_htable_node_t),0);
    if(!htable->cachep) {
        kfree(htable->name);
        return rc;
    }

    heads = kzalloc(nbucket * sizeof(struct hlist_head),
                    GFP_KERNEL);
    if(!heads) {
        kfree(htable->name);
        kvd_mem_cache_destroy(htable->cachep);
        return rc;
    }

    plocks = kzalloc(nbucket * sizeof(rwlock_t),
                    GFP_KERNEL);
    if(!plocks) {
        kfree(heads);
        kfree(htable->name);
        kvd_mem_cache_destroy(htable->cachep);
        return rc;
    }

    pblms = kzalloc(nbucket * sizeof(kvd_blm_hval_t),
                    GFP_KERNEL);
    if(!pblms) {
        kfree(plocks);
        kfree(heads);
        kfree(htable->name);
        kvd_mem_cache_destroy(htable->cachep);
        return rc;
    }

    for(;i < nbucket;i++) {
        INIT_HLIST_HEAD(heads + i);
        rwlock_init(plocks + i);
    }

    rc = 0;
	htable->htctx = htctx;
    htable->nbucket = nbucket;
    htable->cmp_fn = cmp_fn;
    htable->hash_fn = hash_fn;
    htable->free_fn = free_fn;
    htable->ht_heads = heads;
    htable->ht_blms = pblms;
    htable->locks = plocks;
    atomic_set(&htable->size,0);

    LOG_DEBUG("init hash table: %s successfully\n",
            htable->name);
    return rc;
}

void vsec_htable_uninit(vsec_htable_t* htable)
{
    if(!htable) { return; }

    if(htable->name) { 
        LOG_DEBUG("uninit hash table: %s\n",
                htable->name);

        kfree(htable->name);
        htable->name = NULL;
    }

    if(htable->ht_heads) {
        kfree(htable->ht_heads);
        htable->ht_heads = NULL;
    }

    if(htable->locks) {
        kfree(htable->locks);
        htable->locks = NULL;
    }

    if(htable->cachep) {
        kvd_mem_cache_destroy(htable->cachep);
        htable->cachep = NULL;
    }
}

static vsec_htable_node_t* get_from_hlist(vsec_htable_t* htable,
                            struct hlist_head* head,
                            void* key,size_t key_len)
{
    int bexist = 0;
    struct hlist_node *pos, *next;
    vsec_htable_node_t* hnode = NULL;

    hlist_for_each_safe(pos, next,head) {
        hnode = hlist_entry(pos, vsec_htable_node_t,node);
        bexist = !(htable->cmp_fn(key,key_len,
                    hnode->key,hnode->key_len));
        if(bexist) { break; }
    }

    return (bexist ? hnode : NULL);
}

static int is_exist_in_hlist(vsec_htable_t* htable,
                            struct hlist_head* head,
                            void* key,size_t key_len)
{
    vsec_htable_node_t* hnode = NULL;

    hnode = get_from_hlist(htable,head,key,key_len);
    return (hnode != NULL);
}

static vsec_htable_node_t* pop_from_hlist(vsec_htable_t* htable,
                            struct hlist_head* head,
                            void* key,size_t key_len)
{
    vsec_htable_node_t* hnode;

    hnode = get_from_hlist(htable,head,key,key_len);
    if(hnode) { hlist_del(&hnode->node); }

    return hnode;
}

static uint32_t get_htable_idx(vsec_htable_t* htable,
                void* key,size_t key_len,uint64_t* hkey)
{
    uint32_t idx = 0;
    uint32_t hval = 0;

    hval = htable->hash_fn(key,key_len);
    idx = hval % htable->nbucket;
    *hkey = hval;

    return idx;
}

static vsec_htable_node_t* create_hnode(vsec_htable_t* htable,
                        void* key,size_t key_len,void* data)
{
    vsec_htable_node_t* hnode = NULL;
    //这些函数可能会在软中断情况下调用，所以不能睡眠
    hnode = kvd_mem_cache_zalloc(htable->cachep,
                            GFP_ATOMIC);
    if(!hnode) { return hnode; }

    hnode->key = key;
    hnode->data = data;
    hnode->key_len = key_len;
    INIT_HLIST_NODE(&hnode->node);

    return hnode;
}

static void destroy_hnode(vsec_htable_t* htable,
                        vsec_htable_node_t* hnode)
{
    htable->free_fn(htable,
				hnode->key,
                hnode->key_len,
                hnode->data);
    kvd_mem_cache_free(htable->cachep,hnode);
}

static void get_lock_and_hlist(vsec_htable_t* htable,
                        rwlock_t** plock,
                        struct hlist_head** phead,
                        void* key,size_t key_len,
                        uint64_t* hkey,kvd_blm_hval_t** pblm)
{
    uint32_t idx = 0;
    rwlock_t* lock = NULL;
    struct hlist_head* head = NULL;

    idx = get_htable_idx(htable,
                key,key_len,hkey);
    lock = htable->locks + idx;
    head = htable->ht_heads + idx;
    *pblm = htable->ht_blms + idx;

    *phead = head;
    *plock = lock;
}

static void set_blm(uint64_t hval,kvd_blm_hval_t* blm)
{
    if((blm->hmin == 0) || (hval < blm->hmin)) {
        blm->hmin = hval;
    }

    if((blm->hmax == 0) || (hval > blm->hmax)) {
        blm->hmax = hval;
    }
}

static void clear_blm(kvd_blm_hval_t* blm)
{
    blm->hmin = blm->hmax = 0;
}

static int check_blm(uint64_t hval,kvd_blm_hval_t* blm)
{
    return ((hval >= blm->hmin) &&
            (hval <= blm->hmax));
}

int vsec_htable_exist(vsec_htable_t* htable,void* key,size_t key_len)
{
    int bexist = 0;
    uint64_t hval = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;

    get_lock_and_hlist(htable,
                &plock,&head,
                key,key_len,
                &hval,&pblm);
    read_lock_irqsave(plock,flags);
    if(check_blm(hval,pblm)) {
        bexist = is_exist_in_hlist(htable,head,
                            key,key_len);
    }
    read_unlock_irqrestore(plock,flags);

    return bexist;
}

int vsec_htable_upgrade(vsec_htable_t* htable,void* key,size_t key_len,void* data)
{
    int rc = -EINVAL;
    uint64_t hval = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;
    vsec_htable_node_t* hnode = NULL;
    vsec_htable_node_t* old_hnode = NULL;

    if(!htable || !key || !data || !key_len) {
        return rc;
    }

    rc = -ENOMEM;
    hnode = create_hnode(htable,key,
                key_len,data);
    if(!hnode) { return rc; }

    rc = 0;
    //先在添加前+1,防止pop_from_list返回后
    //由于计数器未增加导致其他人清理后大小出现负值
    atomic_inc(&htable->size);
    get_lock_and_hlist(htable,&plock,
            &head,key,key_len,
            &hval,&pblm);

    write_lock_irqsave(plock,flags);
    if(check_blm(hval,pblm)) {
        old_hnode = pop_from_hlist(htable,head,
                                key,key_len);
    }
    hlist_add_head(&hnode->node,head);
    set_blm(hval,pblm);
    write_unlock_irqrestore(plock,flags);

    if(old_hnode) {
        atomic_dec(&htable->size);
        destroy_hnode(htable,old_hnode);
    }

    return rc;
}

int vsec_htable_modify_data(vsec_htable_t* htable,
                	void* key,size_t key_len,void* ctx,
					void (*cb)(void* data,void* ctx))
{
    int rc = -EINVAL;
    uint64_t hval = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;
    vsec_htable_node_t* hnode = NULL;

    if(!htable || !key || !key_len) {
        return rc;
    }

    rc = -ENOENT;
    get_lock_and_hlist(htable,&plock,
            &head,key,key_len,
            &hval,&pblm);

    write_lock_irqsave(plock,flags);
    if(check_blm(hval,pblm)) {
	    hnode = get_from_hlist(htable,head,
                        key,key_len);
        if(hnode) { cb(hnode->data,ctx); }
    }
    write_unlock_irqrestore(plock,flags);
                                         
    if(hnode) { rc = 0; }

    return rc;
}

int vsec_htable_upgrade2(vsec_htable_t* htable,size_t nmax,
                void* key,size_t key_len,void* data,
                void* ctx,void (*cb)(void* data,void* ctx))
{
    int size = 0;
    int rc = -EINVAL;
    uint64_t hval = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;
    vsec_htable_node_t* hnode = NULL;
    vsec_htable_node_t* old_hnode = NULL;

    if(!htable || !key || !data || !key_len) {
        return rc;
    }

    rc = -E2BIG;
    size = atomic_read(&htable->size);
    if(nmax && (size >= nmax)) {
        return rc;
    }

    rc = -ENOMEM;
    hnode = create_hnode(htable,key,
                key_len,data);
    if(!hnode) { return rc; }

    rc = 0;
    atomic_inc(&htable->size);
    get_lock_and_hlist(htable,&plock,
            &head,key,key_len,
            &hval,&pblm);

    write_lock_irqsave(plock,flags);
    if(check_blm(hval,pblm)) {
        old_hnode = pop_from_hlist(htable,head,
                                key,key_len);
        if(old_hnode && cb) { cb(old_hnode->data,ctx); }
    }
    hlist_add_head(&hnode->node,head);
    set_blm(hval,pblm);
    write_unlock_irqrestore(plock,flags);

    if(old_hnode) {
        atomic_dec(&htable->size);
        destroy_hnode(htable,old_hnode);
    }

    return rc;
}

int vsec_htable_del(vsec_htable_t* htable,void* key,size_t key_len)
{
    int rc = -EINVAL;
    uint64_t hval = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;
    vsec_htable_node_t* hnode = NULL;

    if(!htable || !key || !key_len) {
        return rc;
    }

    rc = -ENOENT;
    get_lock_and_hlist(htable,&plock,
            &head,key,key_len,
            &hval,&pblm);

    //此处只在链表为空时才更改布隆过滤器的值
    //因为删除元素时如果不为空最多只能让blm.hmin变大或者blm.hmax变小,布隆过滤器的值区间变小而已
    //但整个布隆过滤器的值区间仍然会落在原来的区间内,所以不会有问题的
    write_lock_irqsave(plock,flags);
    if(check_blm(hval,pblm)) {
        hnode = pop_from_hlist(htable,head,
                            key,key_len);
        if(hnode && hlist_empty(head)) {
            clear_blm(pblm);
        }
    }
    write_unlock_irqrestore(plock,flags);

    if(hnode) {
        rc = 0;
        atomic_dec(&htable->size);
        destroy_hnode(htable,hnode);
    }

    return rc;
}

int vsec_htable_get(vsec_htable_t* htable,
            void* key,size_t key_len,void* ctx,
            void (*cb)(void* data,void* ctx))
{
    int rc = -EINVAL;
    uint64_t hval = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;
    vsec_htable_node_t* hnode = NULL;

    if(!htable || !key || !key_len || !cb) {
        return rc;
    }

    rc = -ENOENT;
    get_lock_and_hlist(htable,&plock,
            &head,key,key_len,
            &hval,&pblm);
    read_lock_irqsave(plock,flags);
    if(check_blm(hval,pblm)) {
        hnode = get_from_hlist(htable,head,
                        key,key_len);
        if(hnode) { cb(hnode->data,ctx); }
    }
    read_unlock_irqrestore(plock,flags);

    if(hnode) { rc = 0; }

    return rc;
}

int vsec_htable_pop(vsec_htable_t* htable,
            void* key,size_t key_len,void* ctx,
            void (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
    int rc = -EINVAL;
    uint64_t hval = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;
    vsec_htable_node_t* hnode = NULL;

    if(!htable || !key || !key_len || !cb) {
        return rc;
    }

    rc = -ENOENT;
    get_lock_and_hlist(htable,&plock,
            &head,key,key_len,
            &hval,&pblm);
    write_lock_irqsave(plock,flags);
    if(check_blm(hval,pblm)) {
        hnode = pop_from_hlist(htable,head,
                            key,key_len);
        if(hnode && hlist_empty(head)) {
            clear_blm(pblm);
        }
    }
    write_unlock_irqrestore(plock,flags);

    //此处不要调用destroy_hnode,
    //因为我们要通过cb将hnode标识的hash节点值给返回
    //而不是直接destroy hash node
    if(hnode) {
        rc = 0;
        atomic_dec(&htable->size);
        cb(hnode->key,hnode->key_len,hnode->data,ctx);
        kvd_mem_cache_free(htable->cachep,hnode);
    }

    return rc;
}

static void hlist_move(struct hlist_head* old,
                    struct hlist_head* new)
{
    new->first = old->first;
	if (new->first)
		new->first->pprev = &new->first;
	old->first = NULL;
}

static void hlist_move_init(struct hlist_head* old,
                    struct hlist_head* new)
{
    hlist_move(old,new);
    INIT_HLIST_HEAD(old);
}

static int cleanup_hlist(vsec_htable_t* htable,
                struct hlist_head* head,
                void* ctx,
                int (*filter)(void* key,size_t key_len,void* data,void* ctx),
                void (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
    int bdel = 0;
    int count = 0;
    vsec_htable_node_t* hnode;
    struct hlist_node *pos, *next;

    hlist_for_each_safe(pos,next,head) {
        bdel = 1;
        hnode = hlist_entry(pos, vsec_htable_node_t,node);
        if(filter) {
            bdel = filter(hnode->key,
                    hnode->key_len,
                    hnode->data,ctx);
        }
        if(!bdel) { continue; }

        hlist_del(&hnode->node);
        if(!cb) {
            destroy_hnode(htable,hnode);
        } else {
            cb(hnode->key,hnode->key_len,
                hnode->data,ctx); 
            //hnode已移除,key与data由cb处理,需释放cache
            kvd_mem_cache_free(htable->cachep, hnode);
        }
        count++;
    }

    return count;
}

int vsec_htable_cleanup(vsec_htable_t* htable)
{
    int i = 0;
    int count = 0;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head dup_head;
    struct hlist_head* head = NULL;

    if(!htable || !htable->name || 
        !htable->locks || !htable->ht_heads) 
    {
        return -EINVAL;
    }

    for(;i < htable->nbucket;i++) {
        unsigned long flags;
        plock = htable->locks + i;
        head = htable->ht_heads + i;
        pblm = htable->ht_blms + i;

        INIT_HLIST_HEAD(&dup_head);
        write_lock_irqsave(plock,flags);
        hlist_move_init(head,&dup_head);
        clear_blm(pblm);
        write_unlock_irqrestore(plock,flags);

       count += cleanup_hlist(htable,
                        &dup_head,
                        NULL,NULL,NULL);
    }

    if(count > 0) {
        atomic_sub(count,&htable->size);
    }

    LOG_DEBUG("cleanup hash table: %s,affect item: %d\n",
                htable->name,count);
    return count;
}

static void walk_hlist(struct hlist_head* head,void* ctx,
                void (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
    vsec_htable_node_t* hnode;
    struct hlist_node *pos, *next;

    hlist_for_each_safe(pos,next,head) {
        hnode = hlist_entry(pos, vsec_htable_node_t,node);
        cb(hnode->key,hnode->key_len,hnode->data,ctx);
    }
}

int vsec_htable_walk(vsec_htable_t* htable,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
    int i = 0;
    rwlock_t* plock = NULL;
    struct hlist_head* head = NULL;

    if(!htable || !htable->name || 
        !htable->locks || !htable->ht_heads) 
    {
        return -EINVAL;
    }

    for(;i < htable->nbucket;i++) {
        unsigned long flags;
        plock = htable->locks + i;
        head = htable->ht_heads + i;

        read_lock_irqsave(plock,flags);
        walk_hlist(head,ctx,cb);
        read_unlock_irqrestore(plock,flags);
    }

    return 0;
}

static int walk_hlist2(struct hlist_head* head,void* ctx,
                int (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
    int rc = 0;
    vsec_htable_node_t* hnode;
    struct hlist_node *pos, *next;

    hlist_for_each_safe(pos,next,head) {
        hnode = hlist_entry(pos, vsec_htable_node_t,node);
        rc = cb(hnode->key,hnode->key_len,hnode->data,ctx);
        //返回非0值停止遍历操作
        if(rc) { break; }
    }
    return rc;
}

int vsec_htable_walk2(vsec_htable_t* htable,void* ctx,
        int (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
    int i = 0;
    rwlock_t* plock = NULL;
    struct hlist_head* head = NULL;

    if(!htable || !htable->name || 
        !htable->locks || !htable->ht_heads) 
    {
        return -EINVAL;
    }

    for(;i < htable->nbucket;i++) {
        int cb_rc = 0;
        unsigned long flags;
        plock = htable->locks + i;
        head = htable->ht_heads + i;

        read_lock_irqsave(plock,flags);
        cb_rc = walk_hlist2(head,ctx,cb);
        read_unlock_irqrestore(plock,flags);
        //返回非0值停止遍历操作
        if(cb_rc) { break; }
    }

    return 0;
}

int vsec_htable_empty(vsec_htable_t* htable)
{
    int i = 0;
    int rc = 1;
    unsigned long flags;
    rwlock_t* plock = NULL;
    struct hlist_head* head = NULL;

    if(!htable || !htable->name || 
        !htable->locks || !htable->ht_heads) 
    {
        return rc;
    }

    for(;i < htable->nbucket;i++) {
        plock = htable->locks + i;
        head = htable->ht_heads + i;

        read_lock_irqsave(plock,flags);
		rc = hlist_empty(head);
        read_unlock_irqrestore(plock,flags);
		if (!rc) { break; }
    }

    return rc;
}

size_t vsec_htable_size(vsec_htable_t* htable)
{
    int size = 0;

    if(!htable || !htable->name || 
        !htable->locks || !htable->ht_heads) 
    {
        return size;
    }

    size = atomic_read(&htable->size);
    if(size < 0) { size = 0; }
    return size;
}

int vsec_htable_walk_step(vsec_htable_t* htable,void* ctx,
        void (*cb)(void* key,size_t key_len,void* data,void* ctx),
		unsigned int *cur_pos)
{
    unsigned long flags;
    rwlock_t* plock = NULL;
    struct hlist_head* head = NULL;

    if(!htable || !htable->name || 
        !htable->locks || !htable->ht_heads) {
        return -EINVAL;
    } else {
		if ((*cur_pos) >= htable->nbucket)
			return -EINVAL;
	}

	if (cur_pos) {
		plock = htable->locks + (*cur_pos);
		head = htable->ht_heads + (*cur_pos);

		read_lock_irqsave(plock,flags);
		walk_hlist(head,ctx,cb);
		read_unlock_irqrestore(plock,flags);
	}	
    return 0;
}

int vsec_htable_clean_items(vsec_htable_t* htable,void* ctx,
        int (*filter)(void* key,size_t key_len,void* data,void* ctx))
{
    int i = 0;
    int count = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;

    if(!htable || !htable->name ||
        !htable->locks || !htable->ht_heads) 
    {
        return -EINVAL;
    }

    for(;i < htable->nbucket;i++) {
        plock = htable->locks + i;
        head = htable->ht_heads + i;
        pblm = htable->ht_blms + i;

        write_lock_irqsave(plock,flags);
        count += cleanup_hlist(htable,
                    head,ctx,filter,NULL);
        if(hlist_empty(head)) { clear_blm(pblm); }
        write_unlock_irqrestore(plock,flags);
    }

    if(count > 0) {
        atomic_sub(count,&htable->size);
    }

    return count;
}

int vsec_htable_pop_items(vsec_htable_t* htable,void* ctx,
        int (*filter)(void* key,size_t key_len,void* data,void* ctx),
        void (*cb)(void* key,size_t key_len,void* data,void* ctx))
{
    int i = 0;
    int count = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    kvd_blm_hval_t* pblm = NULL;
    struct hlist_head* head = NULL;

    if(!htable || !htable->name ||
        !htable->locks || !htable->ht_heads) 
    {
        return -EINVAL;
    }

    for(;i < htable->nbucket;i++) {
        plock = htable->locks + i;
        head = htable->ht_heads + i;
        pblm = htable->ht_blms + i;

        write_lock_irqsave(plock,flags);
        count += cleanup_hlist(htable,
                    head,ctx,filter,cb);
        if(hlist_empty(head)) { clear_blm(pblm); }
        write_unlock_irqrestore(plock,flags);
    }

    if(count > 0) {
        atomic_sub(count,&htable->size);
    }

    return count;
}


static int walk_modify_hlist(vsec_htable_t* htable,
                struct hlist_head* head,
                void* ctx,
                int (*cb)(void* data,void* ctx))
{
    int rc = 0;
    vsec_htable_node_t* hnode;
    struct hlist_node *pos, *next;

    hlist_for_each_safe(pos,next,head) {
        hnode = hlist_entry(pos, vsec_htable_node_t,node);
        rc = cb(hnode->data,ctx);
        if(rc) { break; }
    }

    return rc;
}

void vsec_htable_walk_modify_data(vsec_htable_t* htable,
       void* ctx,int (*cb)(void* data,void* ctx))
{
    int i = 0;
    int rc = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    struct hlist_head* head = NULL;

    if(!htable || !htable->name ||
        !htable->locks || !htable->ht_heads) 
    {
        return;
    }

    for(;i < htable->nbucket;i++) {
        plock = htable->locks + i;
        head = htable->ht_heads + i;

        write_lock_irqsave(plock,flags);
        rc = walk_modify_hlist(htable,
                        head,ctx,cb);
        write_unlock_irqrestore(plock,flags);
        if(rc) { break; }
    }
}

int vsec_htable_upgrade3(vsec_htable_t *ht,
        void *key, size_t key_len, void *data,
        void (*cb)(void *old, void *data))
{
    uint64_t hval = 0;
    rwlock_t *plock = NULL;
    kvd_blm_hval_t *pblm = NULL;
    struct hlist_head *head = NULL;
    vsec_htable_node_t *node, *old = NULL;
    unsigned long flags;

    if (!ht || !data || !key || !key_len) {
        return -EINVAL;
    }

    node = create_hnode(ht, key, key_len, data);
    if (!node) {
        return -ENOMEM;
    }
    get_lock_and_hlist(ht, &plock, &head,
            key, key_len, &hval, &pblm);

    write_lock_irqsave(plock, flags);
    if (check_blm(hval, pblm)) {
        old = pop_from_hlist(ht, head, key, key_len);
        if (old && cb) cb(old->data, node->data);
    }
    hlist_add_head(&node->node, head);
    set_blm(hval, pblm);
    if (!old) atomic_inc(&ht->size);
    write_unlock_irqrestore(plock, flags);

    if (old) {
        destroy_hnode(ht, old);
    }
    return 0;
}
