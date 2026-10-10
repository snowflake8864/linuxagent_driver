/*
 *hook_syscalls 2019-06-07 created by qudreams
 *Hook住我们需要的系统调用,后续所有的hook点必须都在该文件中
 *各功能模块绝对不再允许单独hook系统调用
 */
#include <linux/types.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#ifdef CONFIG_DYNAMIC_FTRACE
#include <linux/ftrace.h>
#endif

#include "core/kvd_core.h"
#include "hook/hook_ops.h"
#include "khookframe.h"


typedef struct kvd_sc_hook_s {
    struct list_head entry;
#ifdef FTRACE_HOOK_ENABLED
    bool ft_hooked;
    struct ftrace_ops ft_ops;
#endif
    int syscall_idx;
    void* hook_fn;
    void** org_fn;
}kvd_sc_hook_t;

static struct list_head sc_hooks;
static DEFINE_RWLOCK(sc_hook_lock);

static u_int __fh_enabled = 0;
static int __force_syscall_hook = 0;

#include "ftrace.c"

extern int cleanup_system_call_hooks(void);
static int do_hook_syscalls(void);

static unsigned long this_mod_got = 0;

//ftrace-hook是否启用
u_int kvd_fh_enabled(void)
{
    return __fh_enabled;
}

int kvd_syscall_hook_forced(void)
{
    return __force_syscall_hook;
}

int kvd_hook_syscalls(void)
{
    int rc = 0;
    int gotmod = 0;

    //进入hook syscalls的逻辑，获取模块引用计数
    //防止执行hook期间模块进入卸载逻辑
    rc = -EFAULT;
    gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    /*
     *此处注意:
     *首先检测this_mod_got标识，如果已经设置过该标识
     *说明已经调用过或正在调用Hook syscalls操作
     *本次肯定是一个异常调用,直接返回错误即可
     */
    rc = -EAGAIN;
    if(test_and_set_bit(0,&this_mod_got)) {
        kvd_self_module_put();
        return rc;
    }

    rc = 0;

    if(!__fh_enabled) {
        rc = do_hook_syscalls();
        //返回成功要保持内核的引用计数
        if(!rc) { return rc; }

        cleanup_system_call_hooks();

        //it must be failed here,so clean it up
        clear_bit(0,&this_mod_got);
        kvd_self_module_put();
    } else {
        ftrace_hook_enable();
    }

    return rc;
}

//客户端进程退出通知时会调用该函数
//清理HOOK syscalls
void kvd_cleanup_syscalls(void)
{
    int rc = 0;
    int gotmod = 0;

    gotmod = test_bit(0,&this_mod_got);
    if(!gotmod) { return; }
    
    //此处一定要先清理掉HOOK syscalls
    //然后再clear this_mod_got标识
    //进而再减少模块引用计数
    //清理hook点失败，引用计数保持不变，
    //以便阻止外围卸载内核模块
    if(!__fh_enabled) {
        rc = cleanup_system_call_hooks();
        if(rc) { return; }
    } else {
        ftrace_hook_disable();
    }

    gotmod = test_and_clear_bit(0,&this_mod_got);
    if(gotmod) { kvd_self_module_put(); }
}

extern int hook_system_call(int index,void* hook_func,
             void **org_handler);

static int do_hook_syscalls(void)
{
    int rc = -EAGAIN;
    unsigned long flags;
    kvd_sc_hook_t* cur = NULL;

    write_lock_irqsave(&sc_hook_lock,flags);
    //为空是我们认为是成功
    if(list_empty(&sc_hooks)) { rc = 0; }
    list_for_each_entry(cur,&sc_hooks,entry)
    {
        int hook_rc = 0;
        hook_rc = hook_system_call(cur->syscall_idx,
                        cur->hook_fn,cur->org_fn);

        //有一个成功我们认为是成功
        if(hook_rc == 0) { rc = 0; }
    }
    write_unlock_irqrestore(&sc_hook_lock,flags);

    return rc;
}

static int do_ftrace_hook_syscalls(void)
{
    int rc = -EAGAIN;
    kvd_sc_hook_t* cur = NULL;

    //只支持在模块初始化时进行ftrace hook
    BUG_ON(THIS_MODULE->state != MODULE_STATE_COMING);

    //为空是我们认为是成功
    if(list_empty(&sc_hooks)) { rc = 0; }
    list_for_each_entry(cur,&sc_hooks,entry)
    {
        int hook_rc = 0;
        hook_rc = ftrace_install_hook(cur);
        // //有一个成功我们认为是成功
        if(hook_rc == 0) { rc = 0; }
    }

    return rc;
}

int __kvd_register_sc_hook(int syscall_idx,
            void* hook_fn,void** pporg_fn)
{
    int rc = 0;
    int bexist = 0;
    unsigned long flags;
    kvd_sc_hook_t* cur = NULL;
    kvd_sc_hook_t* sc_hook = NULL;

    BUG_ON(THIS_MODULE->state != MODULE_STATE_COMING);

    //小于0时我们仍然返回成功
    //因为在不同平台的系统上syscall
    //有些根本就是未定义的
    if(syscall_idx < 0) {
        goto out;
    }
    if(hook_fn == NULL) {
        rc = -EINVAL;
        goto out;
    }

    sc_hook = kzalloc(sizeof(*sc_hook),GFP_KERNEL);
    if(!sc_hook) {
        rc = -ENOMEM;
        goto out;
    }

    sc_hook->hook_fn = hook_fn;
    sc_hook->org_fn = pporg_fn;
    sc_hook->syscall_idx = syscall_idx;

    rc = -EEXIST;
    write_lock_irqsave(&sc_hook_lock,flags);
    list_for_each_entry(cur,&sc_hooks,entry)
    {
        bexist = (cur->syscall_idx == syscall_idx);
        if(bexist) { break; }
    }

    if(!bexist) {
        rc = 0;
        list_add_tail(&sc_hook->entry,&sc_hooks);
    }
    write_unlock_irqrestore(&sc_hook_lock,flags);

    if(rc && sc_hook) { kfree(sc_hook); }

out:
    return rc;
}

void __kvd_unregister_sc_hook(int syscall_idx)
{
    int bexist = 0;
    unsigned long flags;
    kvd_sc_hook_t* cur = NULL;
    kvd_sc_hook_t* next = NULL;

    //不支持在模块运行时进行unregister
    BUG_ON(THIS_MODULE->state == MODULE_STATE_LIVE);

    write_lock_irqsave(&sc_hook_lock,flags);
    list_for_each_entry_safe(cur,next,
                &sc_hooks,entry)
    {
        bexist = (cur->syscall_idx == syscall_idx);
        if(bexist) { list_del(&cur->entry); break; }
    }
    write_unlock_irqrestore(&sc_hook_lock,flags);

    if(bexist) {
        if(__fh_enabled) { 
            ftrace_remove_hook(cur); 
        }

        kfree(cur); 
    }
}

static void do_cleanup_sc_hooks(struct list_head* head)
{
    kvd_sc_hook_t* cur = NULL;
    kvd_sc_hook_t* next = NULL;

    list_for_each_entry_safe(cur,next,
                        head,entry)
    {
        if(__fh_enabled) {
            ftrace_remove_hook(cur);
        }
    
        list_del(&cur->entry);
        kfree(cur);
    }
}

static void cleanup_sc_hooks(void)
{
    unsigned long flags;
    struct list_head dup_list;

    INIT_LIST_HEAD(&dup_list);

    write_lock_irqsave(&sc_hook_lock,flags);
    list_splice_init(&sc_hooks,&dup_list);
    write_unlock_irqrestore(&sc_hook_lock,flags);

    do_cleanup_sc_hooks(&dup_list);
}

int is_syscall_table_hooked(void);
int kvd_init_sc_hook(u_int fh_if_supported)
{
    //默认情况下syscall-hook优先,因为其适用范围更广
    //外围允许ftrace-hook开启并且系统调用表已被其他hook
    //则我们采用ftrace-hook,以避免与其他模块冲突
    //除非明确指定ftrace-hook优先(KVD_FH_PREFERENCE)
#ifdef FTRACE_HOOK_ENABLED
    __fh_enabled = (((fh_if_supported == KVD_FH_SUPPOSED)
                && is_syscall_table_hooked()) ||
                (fh_if_supported == KVD_FH_PREFERENCE));
    if(__fh_enabled) {
        LOG_INFO("ftrace hook enabled\n");
    }
#else
    if (fh_if_supported) {
        LOG_INFO("User selected to use ftrace but currently not supported !\n");
    }
#endif

    INIT_LIST_HEAD(&sc_hooks);
    return init_hook_ops();
}

int kvd_init_sc_hook2(u_int fh_if_supported, int force_syscall_hook)
{
    //强制使用syscall-hook时,不再判断ftrace-hook
    if (force_syscall_hook) {
        __force_syscall_hook = 1;
        goto end;
    }
    //默认情况下syscall-hook优先,因为其适用范围更广
    //外围允许ftrace-hook开启并且系统调用表已被其他hook
    //则我们采用ftrace-hook,以避免与其他模块冲突
    //除非明确指定ftrace-hook优先(KVD_FH_PREFERENCE)
#ifdef FTRACE_HOOK_ENABLED
    __fh_enabled = (((fh_if_supported == KVD_FH_SUPPOSED)
                && is_syscall_table_hooked()) ||
                (fh_if_supported == KVD_FH_PREFERENCE));
    if(__fh_enabled) {
        LOG_INFO("ftrace hook enabled\n");
    }
#else
    if (fh_if_supported) {
        LOG_INFO("User selected to use ftrace but currently not supported !\n");
    }
#endif

end:
    INIT_LIST_HEAD(&sc_hooks);
    return init_hook_ops();
}

void kvd_uninit_sc_hook(void)
{
    //这行代码要在kvd_sc_hook_stop调用更合适，
    //但由于旧版本的驱动不会调用kvd_sc_hook_stop
    //所以才在这里保持不变
    cleanup_sc_hooks(); 
    uninit_hook_ops();
}

extern int _hook_lsm_on;
int kvd_sc_hook_start(void)
{
    int rc = 0;

    if(!_hook_lsm_on && __fh_enabled) {
        rc = do_ftrace_hook_syscalls();
    }

    return rc;
}

void kvd_sc_hook_stop(void)
{
    if(!_hook_lsm_on && __fh_enabled) {
        LOG_INFO("stop ftrace hook\n");
    }
}

const char* kvd_sc_hook_mode(void)
{
    if(__fh_enabled) {
        return "ftrace-hook";
    } else {
        return "syscall-hook";
    }
}
