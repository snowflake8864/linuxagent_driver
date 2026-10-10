#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>
#include "core/kvd_core.h"
#include "core/kvd_memcache.h"
#include "utils/utils.h"
#include "gnkernel.h"
#include "clientexit/client_exit.h"
#include "flag_cache.h"
#include "gnHead.h"


#ifdef CONFIG_64BIT
    #define LONG_BTYE 8
#else
    #define LONG_BTYE 4
#endif

/////////////////////////////////////////////////////////////////////////////////
#define HASH_BUCKET_SIZE 32
static struct kmem_cache* flag_cachep = NULL; //memory cache for struct wait_flag
static spinlock_t flag_locks[HASH_BUCKET_SIZE];
static struct list_head wait_flags[HASH_BUCKET_SIZE];

static void free_wait_flag(struct wait_flag*);

static int init_wait_flag_cache(void)
{
    int rc = -ENOMEM;
    flag_cachep = kvd_mem_cache_create("wait_flag_cache",
                        sizeof(struct wait_flag),0);
    if(!flag_cachep) { return rc; }
    rc = 0;

    return rc;
}

static void destroy_flag_cache(void)
{
    if(flag_cachep) {
        kvd_mem_cache_destroy(flag_cachep);
        flag_cachep = NULL;
    }
}

static void init_wait_flag_list(void)
{
	size_t i = 0;
    spinlock_t* plock = NULL;
    struct list_head* phead = NULL;
    size_t size = HASH_BUCKET_SIZE;

    for(i = 0; i < size;i++) {
     	phead = wait_flags + i;
        plock = flag_locks + i;
    	INIT_LIST_HEAD(phead);
        spin_lock_init(plock);
    }
}

static void try_cleanup_wait_flag(struct wait_flag* flag)
{
    //此处要小心
    if(atomic_cmpxchg(&flag->ref,0,0)) {
        KOSEC_WARN_ON("we try to cleanup wait flag,"
            "but it is still referred\n");
    } else {
	    free_wait_flag(flag);
    }
}

static void cleanup_wait_flags(void)
{
	size_t i = 0;
    size_t size = 0;
    struct wait_flag* next = NULL;
    struct wait_flag* flag = NULL;

    size = HASH_BUCKET_SIZE;
    for(i = 0;i < size;i++) {
    	spin_lock_irq(&flag_locks[i]);
    	list_for_each_entry_safe(flag,next,
    				&wait_flags[i],node)
    	{
    		list_del(&flag->node);
            //到此处wait_flag的引用计数应该减为0了，不然就是有问题
            try_cleanup_wait_flag(flag);
    	}
    	spin_unlock_irq(&flag_locks[i]);
    }
}

static void gen_wait_key(struct wait_flag* flag)
{
    uint64_t nsec = 0;
    uint64_t nval = 0;
    pid_t pid = current->pid;

    nsec = vsec_get_now_nsec();
    nval = nsec + pid;
    #if LONG_BTYE == 4
        //防止溢出
        nval = kvd_murmur_hash2((u_char*)&nval,sizeof(nval));
    #endif
	flag->key = (void*)(nval);
}

/*
 *Note:
 *使用当前单调时间(Nonsec) + pid组成唯一的key
 *我们此处不使用wait_flag分配的地址，是因为从kmem_cache中分配的地址
 *很容易就会被重用，在超时时可能会引起问题
 */

static struct wait_flag* alloc_wait_flag(void* extra, Tkerncallback callback)
{
	struct wait_flag* flag = NULL;

	if (!flag_cachep) goto out;
	flag = kvd_mem_cache_zalloc(flag_cachep,
                                GFP_ATOMIC);
	if(!flag) { goto out; }

    init_completion(&flag->comp);

    gen_wait_key(flag);
    flag->callback = callback;
    flag->extra = extra;

    atomic_set(&flag->ref, 1);

	//此处的key不要使用%p,内核对指针的输出有特殊处理
    LOG_DEBUG("alloc wait flag: %p,key: %lx,extra: %p\n",
            flag,(ulong)flag->key,extra);

out:
	return flag;
}

static void free_wait_flag(struct wait_flag* flag)
{
    if(!flag) { return; }

    LOG_DEBUG("free wait flag: %p,key: %lx,extra: %p\n",
                    flag,(ulong)flag->key,flag->extra);
	kvd_mem_cache_free(flag_cachep,flag);
}

static uint32_t calc_htable_index(void* pkey,size_t len)
{
    uint32_t idx = 0;
    uint32_t size = 0;
    uint32_t hash_val = 0;

    size = HASH_BUCKET_SIZE;
    hash_val = kvd_murmur_hash2((u_char*)pkey,len);
    idx = hash_val % size;

    return idx;
}

static void hold_wait_flag(struct wait_flag* new_node)
{
    uint32_t idx = 0;
    //此处计算的是new_node->key值本身的hash
    idx = calc_htable_index(&new_node->key,
                    sizeof(new_node->key));

    spin_lock_irq(&flag_locks[idx]);
    list_add_tail(&new_node->node,&wait_flags[idx]);
    spin_unlock_irq(&flag_locks[idx]);
}

//使用外部必须加Hash锁
static int unhold_callback_flag_ptr(struct wait_flag* flag, struct list_head *tlist)
{
	int rc = -EFAULT;
    if (NULL == flag || (NULL==flag->callback)) {
        return rc;
    }

    if(atomic_cmpxchg(&flag->ref,0,0)) {
        rc = -EBUSY;
    } else {
        rc = 0;
        list_del(&flag->node);
        list_add_tail(&flag->node, tlist);
    }

    if(!rc) {
        LOG_DEBUG("unhold wait flag ptr: %p,key: %lx,extra: %p\n",
                    flag,(ulong)flag->key,flag->extra);
        //已加入tlist在锁外部释放
        //free_wait_flag(flag);
    } else {
        KOSEC_WARN_ON("unhold wait flag failed ptr: %p,key: %lx,extra: %p\n",
                    flag,(ulong)flag->key,flag->extra);
    }
    
    return rc;
}

//根据target的值去查找，并将其从hash表中移除
//target此处就是key对应的值
static int unhold_wait_flag(void* target)
{
	int rc = -EFAULT;
    uint32_t idx = 0;
    struct wait_flag* next = NULL;
    struct wait_flag* flag = NULL;

    idx = calc_htable_index(&target,
                    sizeof(target));

    spin_lock_irq(&flag_locks[idx]);
    list_for_each_entry_safe(flag,next,
				&wait_flags[idx],node)
    {
    	if(target != flag->key) { continue; }

        if(atomic_cmpxchg(&flag->ref,0,0)) {
            rc = -EBUSY;
        } else {
            rc = 0;
            list_del(&flag->node);
        }
        break;
    }
    spin_unlock_irq(&flag_locks[idx]);

    if(!rc) {
        LOG_DEBUG("unhold wait flag: %p,key: %lx,extra: %p\n",
                    flag,(ulong)flag->key,flag->extra);
        free_wait_flag(flag); 
    } else {
        KOSEC_WARN_ON("unhold wait flag failed,key: %lx,rc: %d\n",
                    (ulong)target,rc);
    }

    return rc;
}

static void do_wake_wait_flag(struct wait_flag* flag)
{
    if (!flag) { return; }

//如说有回调说明是异步的，不需要地唤醒
    if (flag->callback) {
        //放在锁外部调用
        //flag->callback(flag->extra);
        return ;
    }

    complete(&flag->comp);
}

//Note:此处要小心，这个函数调用期间要保证flag不被destroy
static int may_wake_wait_flag(struct wait_flag* flag,int wake, struct list_head *tlist)
{
    int rc = 0;
    int old = 0;
    int ref = 0;
    int count = 0;

    if((ref = atomic_read(&flag->ref)) > 0) {
        //wake为0,表示不做唤醒操作
        if(wake) { do_wake_wait_flag(flag); }
        /*
         *尽力而为吧: 此处引用计数要减1,最多尝试3次,
         *只所以这样做:我们要保证flag->ref大于0时才减1
         */
        do {
            old = ref;
            ref = atomic_cmpxchg(&flag->ref,ref,ref - 1);
        }while((ref > 0) && (old != ref) && (++count < 3));
    } else {
        rc = -EBADR;
        KOSEC_WARN_ON("warning: bad response message,duplicated\n");
    }

    //唤醒的要自动释放，因为原send_nl_data_callback不会卡着去调用put_wait了
    if (wake && flag->callback) {
        atomic_dec(&flag->ref);
        unhold_callback_flag_ptr(flag, tlist);
    }

    return rc;
}

/*
 *接收到客户端进程退出时需要调用这个函数,从而唤醒所有正在等待的flag;
 *因为客户端进程一旦退出这些等待的flag根本不可能获得回应
 *所以我们要直接唤醒，从而对已进入等待状态的进程放行
 */
void wake_all_wait_flags(void)
{
    size_t i = 0;
    size_t size = 0;
    size_t count = 0;
    struct wait_flag* next = NULL;
    struct wait_flag* flag = NULL;
    struct list_head tlist;

    INIT_LIST_HEAD(&tlist);
    size = HASH_BUCKET_SIZE;
    for(i = 0;i < size;i++) {
    	spin_lock_irq(&flag_locks[i]);
    	list_for_each_entry_safe(flag,next,
    				&wait_flags[i],node)
    	{
            count++;
            may_wake_wait_flag(flag,1, &tlist);
    	}
    	spin_unlock_irq(&flag_locks[i]);

        //callback情况放在锁外部调用释放,避免在锁内调用callback出问题
        list_for_each_entry_safe(flag, next, &tlist, node) {
            if (flag->callback) {
                flag->callback(flag->extra);
            }
            list_del(&flag->node);
            free_wait_flag(flag);
        }
    }

    LOG_INFO("wake up all wait flags,"
        "%lu processes are affected\n",count);
}

//此处target对应的就是key
static int try_wake_wait_flag(void* target,int wake)
{
    int rc = -ESRCH;
    uint32_t idx = 0;
    struct wait_flag* next = NULL;
    struct wait_flag* flag = NULL;
    struct list_head tlist;

    idx = calc_htable_index(&target,
                    sizeof(target));

    INIT_LIST_HEAD(&tlist);
    spin_lock_irq(&flag_locks[idx]);
    list_for_each_entry_safe(flag,next,
				&wait_flags[idx],node)
    {
    	if(target != flag->key) { continue; }

        rc = may_wake_wait_flag(flag,wake, &tlist);
        LOG_DEBUG("comm: %s,wake flag: %p,key: %lx,extra: %p,rc: %d",
                CURRENT_COMM,flag,(ulong)flag->key,flag->extra,rc);

        break;
    }
    spin_unlock_irq(&flag_locks[idx]);

    //callback情况放在锁外部调用释放,避免在锁内调用callback出问题
    list_for_each_entry_safe(flag, next, &tlist, node) {
        if (flag->callback) {
            flag->callback(flag->extra);
        }
        list_del(&flag->node);
        free_wait_flag(flag);
    }


    return rc;
}
///////////////////////////////////////////////////////////////////////////////
void put_wait(void* key)
{
    (void)unhold_wait_flag(key);
}

struct wait_flag* get_wait_flag(void* extra, Tkerncallback callback)
{
    struct wait_flag* flag = NULL;

    flag = alloc_wait_flag(extra, callback);
	if(flag) {
		//先增加引用计数，防止wait_flag加入hash表后		
        //客户端进程退出导致flag被destroy,从而在使用时崩溃
		atomic_inc(&flag->ref);			
        hold_wait_flag(flag);
	}

    return flag;
}

static int do_wait(struct wait_flag* flag)
{
    int err = 0;
	ulong ns_start = 0;
	ulong ns_end = 0;

	ns_start = vsec_get_now_nsec();
    LOG_DEBUG("comm: %s,do wait flag: %p,key: %lx,extra: %p\n",
            CURRENT_COMM,flag,(ulong)flag->key,flag->extra);
    
    //wait_for_completion_timeout成功返回大于0的值，超时返回0,其他错误返回小于的错误码
    //针对wait_for_completion_timeout返回值为了处理方便我们做一下转化
    //Note: 这里一定要采用可中断的，不然会导致被挂起的用户态进程无法被系统结束引起关机，待机，休眠异常
    //超时时间由40变更为42: 由于用户态加入弹窗处理最大超时时间为40,这里要稍大于用户态
    err = wait_for_completion_interruptible_timeout(&flag->comp, 42 * HZ);
    //err > 0表示成功
    if(err > 0) { err = 0; } 
    //err == 0表示超时
    else if(err == 0) { err = -ETIME; }

    if (likely(err == 0)) {
        LOG_DEBUG("comm: %s,wait success,flag: %p,key: %lx,extra: %p\n",
                CURRENT_COMM,flag,(ulong)flag->key,flag->extra);
    } else if (unlikely(err == -ETIME)) {
		ns_end = vsec_get_now_nsec();

        KOSEC_WARN_ON("comm: %s,wait timedout,ns_start: %lu,ns_end: %lu,"
                "flag: %p,key: %lx,extra: %p\n",
                CURRENT_COMM,ns_start,ns_end,
                flag,(ulong)flag->key,flag->extra);
    } else {
        KOSEC_WARN_ON("comm: %s,wait error,flag: %p,key: %lx,extra: %p,err: %d\n",
                CURRENT_COMM,flag,(ulong)flag->key,flag->extra,err);
    }

    return err;
}

static int try_wait(struct wait_flag* flag,int no_wait)
{
    int rc = 0;

    if(!no_wait) {
        rc = do_wait(flag);
    }
    
    //无需要等待或者等待失败时,尝试自行唤醒
    //我们只是尝试自行唤醒，但将wake标识置为0,不做实际的唤醒动作
    if(rc || no_wait) { 
        try_wake_wait_flag(flag->key,0); 
    }
    //wait结束后减少引用计数
    atomic_dec(&flag->ref);

    return rc;
}

int waiting_flag(struct wait_flag* flag)
{
    LOG_DEBUG("comm: %s,waiting flag: %p,key: %lx,extra: %p\n",
            CURRENT_COMM,flag,(ulong)flag->key,flag->extra);
    return try_wait(flag,0);
}

void no_waiting(struct wait_flag* flag)
{
    LOG_INFO("no waiting flag: %p,key: %lx,extra: %p\n",
            flag,(ulong)flag->key,flag->extra);
	//自行唤醒
	try_wait(flag,1);
	//减少引用记数
    unhold_wait_flag(flag->key);
}

void wake_wait_flag(void* key)
{
    try_wake_wait_flag(key,1);
}

//根据key查找wait_flag
void* get_wait_extra(void* key)
{
    uint32_t idx = 0;
    void* extra = NULL;
    bool bfound = false;
    struct wait_flag* next = NULL;
    struct wait_flag* flag = NULL;

    idx = calc_htable_index((void*)&key,
                sizeof(key));

    spin_lock_irq(&flag_locks[idx]);
    list_for_each_entry_safe(flag,next,
				&wait_flags[idx],node)
    {
    	if(key != flag->key) { continue; }

        extra = flag->extra;
        bfound = true;
        break;
    }
    spin_unlock_irq(&flag_locks[idx]);
    if(extra) {
        LOG_DEBUG("comm: %s,pid: %d,get wait extra: %p,key: %lx, extra: %p\n",
                CURRENT_COMM,CURRENT_PID,flag,(ulong)key,extra);
    } else {
        KOSEC_WARN_ON("comm: %s,pid:%d,get wait extra failed,key: %lx,%s\n",
                CURRENT_COMM,CURRENT_PID,(ulong)key,
                (bfound ? "extra is NULL" : "not existing"));
    }

    return extra;
}

///////////////////////////////////////////////////////////////////////////////
//ts可能为空
static int client_exit_notify_fn(struct notifier_block* nb,
            unsigned long val,void* data)
{
    pid_t pid = -1;
    struct task_struct* task = data;

    wake_all_wait_flags();
    if(task)  { pid = PID(task); }

    LOG_INFO("flag_cache receive client[%d] exit notify\n",pid);
    return 0;
}

static struct notifier_block flag_notifier = {
    .notifier_call = client_exit_notify_fn,
};

//////////////////////////////////////////////////////////////////////////////
int init_wait_flags(void)
{
    int rc = 0;
    rc = init_wait_flag_cache();
    if(rc) { return rc; }

    register_client_exit_notify(&flag_notifier);
	init_wait_flag_list();
    LOG_INFO("init wait flags\n");
	return rc;
}


void uninit_wait_flags(void)
{
	cleanup_wait_flags();
    unregister_client_exit_notify(&flag_notifier);
    destroy_flag_cache();
    LOG_INFO("uninit wait flags\n");
}
