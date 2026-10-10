#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include "kvd_syscall.h"
#include "khookframe.h"
#include "core/kvd_core.h"
#include "hook_ops.h"

static rwlock_t* ops_locks = NULL;
//每个系统调用一个链表，这样能够加快执行速度
static uint8_t* ops_counts = NULL;
static struct list_head* hook_opses = NULL;

int init_hook_ops(void)
{
    int i = 0;
    rwlock_t* locks = NULL;
    uint8_t* counts = NULL;
    struct list_head* opses = NULL;

    locks = kzalloc(sizeof(*locks) * KVD_NR_SYSCALLS,GFP_KERNEL);
    if(!locks) { return -ENOMEM; }

    opses = kzalloc(sizeof(*opses) * KVD_NR_SYSCALLS,GFP_KERNEL);
    if(!opses) {
        kfree(locks);
        return -ENOMEM;
    }

    counts = kzalloc(sizeof(*counts) * KVD_NR_SYSCALLS,GFP_KERNEL);
    if(!counts) {
        kfree(locks);
        kfree(opses);
        return -ENOMEM;
    }

    for(;i < KVD_NR_SYSCALLS;i++) {
        rwlock_init(locks + i);
        INIT_LIST_HEAD(opses + i);
    }

    ops_locks = locks;
    hook_opses = opses;
    ops_counts = counts;

	return 0;
}

int uninit_hook_ops(void)
{
    if(ops_locks) { kfree(ops_locks); }
    if(hook_opses) { kfree(hook_opses); }
    if(ops_counts) { kfree(ops_counts); }

	return 0;
}

static int do_register_one(struct list_head* list,struct kvd_hook_ops* ops)
{
    struct kvd_hook_ops* elem = NULL;

    if(ops_counts[ops->syscall_idx] >= KVD_HOOK_OPS_SIZE) {
        return -E2BIG;
    }

    ops->idx = ops_counts[ops->syscall_idx];
    ops_counts[ops->syscall_idx] += 1;

	list_for_each_entry(elem,list,lh) {
		if(ops->prority < elem->prority)
            break;
	}
	list_add(&ops->lh, elem->lh.prev);
   
    return 0;
}

static bool is_valid_syscall_idx(int syscall_idx)
{
    return ((syscall_idx >= 0) && 
            (syscall_idx < KVD_NR_SYSCALLS));
}

static bool is_valid_hook_ops(struct kvd_hook_ops* ops)
{
    return (ops && 
            is_valid_syscall_idx(ops->syscall_idx) && 
            (ops->post_cb || ops->pre_cb)); 
}

static int register_one_hook_ops(struct kvd_hook_ops* ops)
{
    int rc = -EINVAL;
    unsigned long flags;
    rwlock_t* plock = NULL;
    struct list_head* plist = NULL;

    if(!is_valid_hook_ops(ops)) 
    {
        WARN_ON(1);
        return rc;
    }

    rc = 0;
    plock = ops_locks + ops->syscall_idx;
    plist = hook_opses + ops->syscall_idx;

    LOG_DEBUG("register hook syscall_name: %s,syscall_index: %d\n",
        kvd_hook_syscall_name(ops->syscall_idx),ops->syscall_idx);

    write_lock_irqsave(plock,flags);
    rc = do_register_one(plist,ops);
    write_unlock_irqrestore(plock,flags);

    return rc;
}

//此处的opses是一个数组，count为该数组的大小
int kvd_register_hook_ops(struct kvd_hook_ops* opses,int count)
{
    int i = 0;
    int rc = 0;

    BUG_ON(!opses || (count <= 0));
   
    for(;i < count;i++) {
        struct kvd_hook_ops* ops = opses + i;
        //很多平台上有些系统调用根本就是未定义
        //此时syscall_idx就是-1,我们在此处做特殊处理
        if(ops->syscall_idx < 0) { continue; }

        rc = register_one_hook_ops(ops);
        if(rc) { break; }
    }
    return rc;
}

static void unregister_one_hook_ops(struct kvd_hook_ops* ops)
{
    int syscall_idx = 0;
    unsigned long flags;
    rwlock_t* plock = NULL;
    struct list_head* plist = NULL;

    if(!is_valid_hook_ops(ops)) {
        WARN_ON(1);
        return;
    }

    syscall_idx = ops->syscall_idx;
    plock = ops_locks + syscall_idx;
    plist = hook_opses + syscall_idx;

    LOG_DEBUG("unregister hook syscall_name: %s,syscall_index: %d\n",
       kvd_hook_syscall_name(syscall_idx),syscall_idx);

    write_lock_irqsave(plock,flags);
    list_del(&ops->lh);
    ops_counts[syscall_idx] -= 1;
    write_unlock_irqrestore(plock,flags);
}

void kvd_unregister_hook_ops(struct kvd_hook_ops* opses,int count)
{
    int i = 0;
    
    BUG_ON(!opses || (count <= 0));
    //不支持在模块运行时进行unregister
    BUG_ON(THIS_MODULE->state == MODULE_STATE_LIVE);

    for(;i < count;i++) {
        struct kvd_hook_ops* ops = opses + i;
        //很多平台上有些系统调用根本就是未定义
        //此时syscall_idx就是-1,我们在此处做特殊处理
        if(ops->syscall_idx < 0) { continue; }
        unregister_one_hook_ops(ops);
    }
}

typedef void (*fn_cb)(kvd_regs_t* regs,kvd_hook_ctx_t* ctx);
static void do_hook_ops(int post,kvd_regs_t* regs,
            kvd_hook_ctx_t ctxs[KVD_HOOK_OPS_SIZE])
{
    fn_cb fn = NULL;
    unsigned long flags;
    rwlock_t* plock = NULL;
    struct kvd_hook_ops* elem = NULL;
    struct kvd_hook_ops* next = NULL;
    struct list_head* plist = NULL;
    int syscall_idx = regs->syscall_idx;

    if(!is_valid_syscall_idx(syscall_idx)) {
        WARN_ON(1);
        return; 
    }

    plock = ops_locks + syscall_idx;
    plist = hook_opses + syscall_idx;
    /*
     *Note:
     *此处为了保证每个回调hook的上下文不会相互污染
     *我们针对每个hook ops都创建一个ctx
     */
    read_lock_irqsave(plock,flags);
    list_for_each_entry_safe(elem,next,plist,lh) {
        uint8_t idx = elem->idx;
        fn = (post ? elem->post_cb : elem->pre_cb);
        if(!fn) { continue; }

        //先获取模块,阻止模块进入卸载逻辑,防止fn成为无效地址
        if(!kvd_try_self_module_get()) { continue; }
        read_unlock_irqrestore(plock,flags);

		fn(regs,ctxs + idx);
        kvd_self_module_put();
        read_lock_irqsave(plock,flags);

        //停止调用后续hook点
        if(regs->flag & KVD_FLAG_STOP_NEXT) { break; }
	}
    read_unlock_irqrestore(plock,flags);
}

void kvd_precall_hook_ops(kvd_regs_t* regs,
        kvd_hook_ctx_t ctxs[KVD_HOOK_OPS_SIZE])
{
    do_hook_ops(0,regs,ctxs);
}

void kvd_postcall_hook_ops(kvd_regs_t* regs,
        kvd_hook_ctx_t ctxs[KVD_HOOK_OPS_SIZE])
{
    //post_call不需要关心最后的返回值
    do_hook_ops(1,regs,ctxs);
}

void kvd_set_hook_args(kvd_regs_t* regs,
                u_int i,u_int n,u_long* args)
{
    BUG_ON(i + n > KVD_SYSCALL_MAX_ARGS);

    memcpy(regs->args + i,args,n);
}

const char* get_syscall_name(int index);
const char* kvd_hook_syscall_name(u_int index)
{
    return get_syscall_name(index);
}
