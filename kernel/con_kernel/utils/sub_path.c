#include <linux/types.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include "core/kvd_core.h"
#include "sub_path.h"
#include "rb_htable.h"
#include "gnHead.h"

#define SUBPATH_LOG_INFO     LOG_INFO
#define SUBPATH_LOG_ERROR    LOG_ERROR

#define SUBPATH_LOG_DEBUG(ht,fmt, args...) {  \
            if(test_bit(0,&ht->debug)) { \
                printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args); \
            } else { LOG_DEBUG(fmt,##args); } }


/*
 *我们在此处基于路径层级进行hash计算，构造一个hash表
 *一切都是为了方便我们进行子路径的查找
 */
//最大支持16级目录
//#define MAX_DIR_LEVEL 16

//针对路径层级做计算
uint32_t calc_path_level(void* key,size_t len)
{
	size_t n = 0;
	char* path = key;
	uint32_t level = 0;

	//我们只支持绝对路径
	if(!path || (*path != '/')) { return level; }

	//对于以/结尾或者以多个//结尾，或者有多个/
	//我们不认为该级是一个目录层级
	while(len > 0 && path[len - 1] == '/') { len--; }
	
	level = 0;
	while(*path && n++ < len) {
		char c = *path++;
		if(c != '/') { continue; }

		
		if(!*path || (*path == '/')) {
			continue;
		}

		level++;
	}

	//大于hash表的buckets,我们就将其放到最后一个bucket中
	//这样做是因为在子路径查找时需要按层级采用顺序结构
	if(level >= MAX_DIR_LEVEL) {
		level = MAX_DIR_LEVEL - 1;
	}

	return level;
}

static int path_cmp(void* key1,size_t len1,void* key2,size_t len2)
{
	int rc = 0;
	size_t nmin = min(len1,len2);

	//按查找子路径的方式比较大小
	//先比较长度相同的部分
	rc = memcmp(key1,key2,nmin);
	if(rc) { return rc; }

	//如果长度相同的部分一样，则比较长度
	return (len1 - len2);
}

static void path_free(struct vsec_rb_htable* ht,void* key,size_t len,void* data)
{
	SUBPATH_LOG_DEBUG(ht,"rb-htable: %s,path_free: %s,data: %p\n",
			    ht->name,(char*)key,data);
    kfree(key);
}

//path 大于等于 data->key表示的路径
static int do_subpath_cmp1(struct vsec_rb_htable* ht,
                    const char* path,size_t pathlen,
					struct rb_ht_entry* data)
{
	int res = 0;
	int is_dir = 0;
	char* pkey = data->key;
	SUBPATH_LOG_DEBUG(ht,"subpath_cmp1: path: %s,key: %s\n",
				path,(char*)data->key);
	
	//外围调用者要保证是目录的情况下要以/结尾
	//否则肯定不会是预期的匹配行为
	is_dir = (pkey[data->key_len - 1] == '/');
	if(!is_dir) {
		//不是目录就按文件全路径匹配
		res = strcmp(path,data->key);
	} else {
		//是目录则按子目录匹配
		res = memcmp(path,data->key,
				data->key_len);
	}

	return res;
}

//此时一定要是: pathlen == (data->key_len - 1)且data表示目录
static int do_subpath_cmp2(struct vsec_rb_htable* ht,
                const char* path,size_t pathlen,
				struct rb_ht_entry* data)
{
	int res = 0;
	SUBPATH_LOG_DEBUG(ht,"subpath_cmp2: path: %s,key: %s\n",
					path,(char*)data->key);

	res = memcmp(path,data->key,
			data->key_len - 1);

	return res;
}

/*
 *@path -->target match path
 *@pathlen -->target path length
 */
static int subpath_cmp(const char* path,size_t pathlen,
					struct vsec_rb_htable* ht,
					struct rb_ht_entry* data)
{
	int res = 0;
	char* pkey = data->key;
	//此处分为为三种情况

	//1.path长度大于等于data->key表示的路径
	if(pathlen >= data->key_len) {
		res = do_subpath_cmp1(ht,path,pathlen,data);
	}
	else if((pkey[data->key_len - 1] == '/') && 
			(pathlen == (data->key_len - 1))) {
		res = do_subpath_cmp2(ht,path,pathlen,data);
	}
	//3.path表示的路径比data->key表示的路径长
	else {
		SUBPATH_LOG_DEBUG(ht,"htable cmp_fn: %s,key: %s\n",
				path,(char*)data->key);
		res = ht->cmp_fn((void*)path,pathlen,
				data->key,data->key_len);
	}

	return res;
}

static struct rb_ht_entry* subpath_search(struct vsec_rb_htable* ht,
						struct rb_root* root,const char* path,size_t pathlen)
{
    struct rb_node *node = NULL;
	struct rb_ht_entry* entry = ERR_PTR(-EINVAL);

	if(!ht || !root || !path || !pathlen) {
		return entry;
	}
	
	entry = ERR_PTR(-ENOENT);
	node = root->rb_node;
    while (node) {
        int res = 0;
		struct rb_ht_entry* data = NULL;

		data = container_of(node,struct rb_ht_entry,node);
		
		/*此处要进行特殊比较：
		* 但比较的整体逻辑仍然与ht->cmp基本相似，
		* 只是做了一些细节上的逻辑处理
		*
		*a.我们要判断path是否为data->key标识的子目录
		*b.如果不是需要判断出大小关系,以便进行下次查找
		*/
		res = subpath_cmp(path,pathlen,ht,data);
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

int vsec_path_rbht_init(struct vsec_rb_htable* ht,
            const char* name,void* ctx)
{
    int rc = -EINVAL;
    if(!ht || !name) {
        return rc;
    }

    rc = vsec_rb_htable_init(ht,name,NULL,MAX_DIR_LEVEL,
                path_cmp,calc_path_level,path_free);
    SUBPATH_LOG_DEBUG(ht,"init path_rbht: %s,rc: %d\n",name,rc);

    return rc;    
}

int vsec_path_rbht_init2(struct vsec_rb_htable *ht,
        const char *name, void *ctx,
        vsec_rb_ht_cmp_fn_t cmp_fn,
        vsec_rb_ht_hash_fn_t hash_fn,
        vsec_rb_ht_free_fn_t free_fn)
{
    int rc = -EINVAL;

    if (!ht || !name) {
        return rc;
    }
    rc = vsec_rb_htable_init(ht, name, NULL, MAX_DIR_LEVEL,
            (cmp_fn ? cmp_fn : path_cmp),
            (hash_fn ? hash_fn : calc_path_level),
            (free_fn ? free_fn : path_free));
    SUBPATH_LOG_DEBUG(ht,"init path_rbht: %s,rc: %d\n",name,rc);

    return rc;
}

void vsec_path_rbht_uninit(struct vsec_rb_htable* ht)
{
    if(!ht) { return; }

    SUBPATH_LOG_DEBUG(ht,"uninit path_rbht: %s\n",ht->name);
    vsec_path_rbht_cleanup(ht);
    vsec_rb_htable_uninit(ht);
}

int vsec_path_rbht_cleanup(struct vsec_rb_htable* ht)
{
    int count = 0;
    int rc = -EINVAL;

    if(!ht) { return rc; }

    count = vsec_rb_htable_cleanup(ht);

    SUBPATH_LOG_DEBUG(ht,"cleanup rbht: %s,"
        "cleanup %d items\n",
        ht->name,count);

    return count;
}

size_t revise_pathlen(const char* path,
							size_t len)
{
	if(!path) { return len; }
	
	if(!len) { 
		len = strlen(path); 
		return len;
	}
	
	while(len > 0 && !path[len - 1]) {
		len--;
	}

	return len;
}

int vsec_path_rbht_insert(struct vsec_rb_htable* ht,
                        const char* path,size_t len)
{
    int rc = -EINVAL;
    void* key = NULL;

    if(!ht || !path) { return rc; }

	//长度允许为0，我们自己计算
	//另外len可能不准确: 应用层发给内核的策略路径带了\0
	//这个非常恶心，我们在此处做兼容处理
	len = revise_pathlen(path,len);
	if(!len) { return rc; }

    rc = -ENOMEM;
	//此处可能会在中断中使用，不要休眠
    key = kstrndup(path,len,GFP_ATOMIC);
    if(!key) { return rc; }
    
    //此处我们不需要data
    rc = vsec_rb_htable_insert(ht,key,
                len,NULL);
	if(rc) { kfree(key); }
	
    return rc;
}

int vsec_path_rbht_delete(struct vsec_rb_htable* ht,
                        const char* path,size_t len)
{
    int rc = -EINVAL;

    if(!ht || !path) { return rc; }

	len = revise_pathlen(path,len);
	if(!len) { return rc; }

    rc = vsec_rb_htable_delete(ht,
            (void*)path,len);
    return rc;
}

//path是否为ht中目录的子路径
int vsec_path_rbht_is_sub(struct vsec_rb_htable* ht,const char* path,size_t len)
{
	int i = 0;	
	int bsub = 0;
	uint32_t level = 0;
	unsigned long flags;
	rwlock_t* plock = NULL;
	struct rb_root* proot = NULL;
	struct rb_ht_entry* entry = NULL;

	if(!ht || !path) { return bsub; }

	len = revise_pathlen(path,len);
	if(!len) { return bsub; }

	level = calc_path_level((void*)path,len);
	if(level >= ht->nbucket) {
		level = ht->nbucket - 1;
	}

	SUBPATH_LOG_DEBUG(ht,"check path:%s,"
            "level: %d is subpath or not "
            "in path_rbht: %s\n",
            path,level,ht->name);
	
	for(i = level;i >= 0;i--) {
		plock = ht->locks + i;
		proot = &ht->ht_roots[i];

		read_lock_irqsave(plock,flags);
		entry = subpath_search(ht,proot,
						path,len);
		if(!IS_ERR(entry)) {
			SUBPATH_LOG_DEBUG(ht,"%s is sub-path of: %s\n",
					    path,(char*)entry->key);
		}
		read_unlock_irqrestore(plock,flags);
		bsub = !IS_ERR(entry);
		if(bsub) { break; }
	}

	return bsub;
}

int vsec_path_rbht_sub_and_get(struct vsec_rb_htable *ht, const char *path, size_t len,
        void (*cb)(void *data, void *ctx), void *ctx)
{
    int i;
    int rc;
    uint32_t level;
    unsigned long flags;
    rwlock_t *plock;
    struct rb_root *proot;
    struct rb_ht_entry *entry;

    if (!ht || !path ||!cb || !ctx) {
        return -EINVAL;
    }

    len = revise_pathlen(path, len);
    if (!len) {
        return -EINVAL;
    }
    level = calc_path_level((void *)path, len);
    if (level >= ht->nbucket) {
        level = ht->nbucket - 1;
    }

    rc = -ENOENT;
    for (i = level; i >= 0; i--) {
        int bhit = 0;
        plock = ht->locks + i;
        proot = &ht->ht_roots[i];

        read_lock_irqsave(plock, flags);
        entry = subpath_search(ht, proot, path, len);
        if (!IS_ERR(entry)) {
            cb(entry->data, ctx);
            bhit = 1;
        }
        read_unlock_irqrestore(plock, flags);
        if (bhit) {
            rc = 0;
            break;
        }
    }
    return rc;
}

