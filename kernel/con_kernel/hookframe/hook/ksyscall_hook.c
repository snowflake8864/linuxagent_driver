#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/err.h>
#include "core/kvd_memcache.h"
#include "khookframe.h"

#if defined(__x86_64__) || defined(__i386__)
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,14)
    #include <asm/special_insns.h>
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
    #include <asm/system.h>
#endif
#endif

#include "find_syscall_table.c"
#include "arch/hook_arch.h"

typedef struct hook_info {
    int index;
    volatile void* hook_func;
    volatile void* origin_func;
    volatile void** psys_table; //可能会是syscall_table或者comat_syscall_table
    struct list_head entry;
} hook_info_t;

static DEFINE_SPINLOCK(hook_list_lock);
static struct list_head hook_info_head;
static struct kmem_cache* hook_cachep = NULL;
static volatile void** syscall_table = NULL;

//core_kernel_text
static int (*kvd_ckt_fn)(unsigned long addr) = NULL;
extern const char* get_syscall_name(int index);

//系统调用表是否已被其他模块hook
int is_syscall_table_hooked(void)
{
    unsigned i = 0;
    int bhooked = 0;

    if(!syscall_table) { 
        return bhooked; 
    }

    for(;i < KVD_NR_SYSCALLS;i++) {
        u_long addr = (u_long)(syscall_table[i]);
        bhooked = (addr && kvd_ckt_fn && !kvd_ckt_fn(addr));
        if(bhooked) {
            LOG_INFO("syscall[%u] is hooked by "
                "at 0x%lx\n",i,addr);
            break;
        }
    }

    return bhooked;
}

static int hook_system_call_inner(int index,volatile void** psys_table,
                volatile void* hook_func,volatile void** org_handler)
{
    int rc = -EFAULT;
    unsigned long old_v;
    unsigned long addr = 0;
    volatile void* old_handler = NULL;

    if(!psys_table || !hook_func || !org_handler) {
        return rc;
    }

    addr = (unsigned long)(psys_table[index]);
    //syscall-hook，系统调用在别人hook后，要是继续hook的话，不再进行检测
    if(!kvd_syscall_hook_forced()) {
        if(kvd_ckt_fn && !kvd_ckt_fn(addr)) {
            LOG_INFO("badly: someone has hooked the syscall[%s] at: 0x%lx,"
                "it's not a core-kernel-text address\n",
                get_syscall_name(index),addr);
            return rc;
        }     
    }

    //注意:
    //此处一定要先设置org_handler的原始指针,然后再进行替换
    //从而保证一旦替换完之后org_handler标识的原始syscall不为空
    //否则的话在syscall调用很频繁的情况下,由于调用原始syscall为空出现调用崩溃
    rc = disable_wp(&old_v);
    if(rc) {
        LOG_INFO("syscall-hook: disable wp failed,"
            "rc: %d\n",rc);
        return rc; 
    }

    (void)xchg(org_handler,psys_table[index]);
    old_handler = cmpxchg(&psys_table[index],
                        *org_handler,hook_func);
    restore_wp(old_v);

    if(old_handler != *org_handler) {
        rc = -EAGAIN;
    }

    return rc;
}

static int restore_system_call(const hook_info_t* hi)
{
    int rc = 0;
    unsigned long old_v;
    unsigned long addr = 0;
    volatile void* cur_syscall = NULL;

    rc = disable_wp(&old_v);
    if(rc) {
        LOG_ERROR("syscall-restore: disable wp failed,"
            "rc: %d\n",rc);
        return rc; 
    }
    
    cur_syscall = cmpxchg(&hi->psys_table[hi->index],
                    hi->hook_func,hi->origin_func);
    restore_wp(old_v);

    if(cur_syscall != hi->hook_func) {
        //此时如果系统调用在内核正常地址范围内，可以进行卸载
        addr = (unsigned long)(hi->psys_table[hi->index]);
        if(kvd_ckt_fn && !kvd_ckt_fn(addr)) {
            rc = -EAGAIN;
            LOG_ERROR("badly: someone has changed the syscall[%s],"
                "we expect: 0x%lx,but it's 0x%lx\n",
                get_syscall_name(hi->index),
                (u_long)(hi->hook_func),
                (u_long)cur_syscall);
        }
    }

    return rc;
}

static int init_syscall_table(void)
{
    int rc = -EFAULT;

    syscall_table = (volatile void**)find_sys_call_table();
    LOG_INFO("the sys_call_table:0x%lx\n",(u_long)syscall_table);
    if(syscall_table) { rc = 0; }

    return rc;
}

static hook_info_t* create_hook_info(void)
{
    hook_info_t* pinfo = NULL;
    pinfo = (hook_info_t*)kvd_mem_cache_zalloc(hook_cachep,
                                             GFP_KERNEL);
    if(!pinfo) { pinfo = ERR_PTR(-ENOMEM); }

    return pinfo;
}

static void free_hook_info(const hook_info_t* hi)
{
    if(!hi || IS_ERR(hi)) { return; }
    kvd_mem_cache_free(hook_cachep,(void*)hi);
}

static int init_hook_cache(void)
{
    int rc = -ENOMEM;
    hook_cachep = kvd_mem_cache_create("hook_cache",
                                sizeof(hook_info_t),0);
    if(hook_cachep) { rc = 0; }

    return rc;
}

static void destroy_hook_cache(void)
{
    if(hook_cachep) {
        kvd_mem_cache_destroy(hook_cachep);
        hook_cachep = NULL;
    }
}

static int do_hook_system_call(const char* name,int index,volatile void** psys_table,
        volatile void* hook_func, volatile void **org_handler)
{
    int rc = -EINVAL;
    hook_info_t* hi = NULL;

    if((index <= 0) || !psys_table || 
        !hook_func || !org_handler)
    {
        return rc;
    }

    hi = create_hook_info();
    if(IS_ERR(hi)) {
        rc = PTR_ERR(hi);
        goto out;
    }

    spin_lock_irq(&hook_list_lock);
    rc = hook_system_call_inner(index,
        psys_table,hook_func,org_handler);
    if(!rc) {
        hi->index = index;
        hi->hook_func = hook_func;
        hi->origin_func = *org_handler;
        hi->psys_table = psys_table;
        list_add(&hi->entry,&hook_info_head);
    }
    spin_unlock_irq(&hook_list_lock);

    if(rc == 0) {
        LOG_DEBUG("the %s hook index:%d,syscall: %s,origin :0x%lx,new: 0x%lx\n",
            name,index,get_syscall_name(index),
            (u_long)*org_handler,(u_long)hook_func);
    }

out:
    if(rc && !IS_ERR(hi)) {
       free_hook_info(hi);
    }

    return rc;
}

int hook_system_call(int index,void* hook_func, void **org_handler)
{
    return do_hook_system_call("syscall_table",index,
            syscall_table,(volatile void*)hook_func,(volatile void**)org_handler);
}

//新版本的内核中调用这个，以便判断其返回值，做进一步逻辑处理
int cleanup_system_call_hooks(void)
{
    int rc = 0;
    hook_info_t* hi = NULL;
    hook_info_t* next = NULL;

    spin_lock_irq(&hook_list_lock);
    list_for_each_entry_safe(hi,next,
                &hook_info_head,entry)
    {
        rc = restore_system_call(hi);
        if(rc) { break; }

        list_del(&hi->entry);
        free_hook_info(hi);
    }
    spin_unlock_irq(&hook_list_lock);

    LOG_DEBUG("cleanup system call hooks,rc: %d\n",rc);

    return rc;
}

extern void uninit_syscall_names(void);
int uinit_system_call_hook(void)
{
    cleanup_system_call_hooks();
    uninit_hook_arch();
    destroy_hook_cache();
    uninit_syscall_names();

    return 0;
}

int hook_search_ksym(const char *sym_name, unsigned long *sym_addr);
extern void init_syscall_names(void);
int init_system_call_hook(void)
{
    int rc = -EAGAIN;
    unsigned long addr = 0;

    if (syscall_table) {
        return rc;
    }

    init_syscall_names();
    rc = init_hook_cache();
    if(rc) { return rc; }

    rc = hook_search_ksym("core_kernel_text",&addr);
    if(rc == 0) { kvd_ckt_fn = (void*)addr; }

    INIT_LIST_HEAD(&hook_info_head);
    rc = init_syscall_table();
    if(rc) { goto failed; }

    return rc;

failed:
    destroy_hook_cache();
    return rc;
}


volatile void** kvd_find_syscall_table(void)
{
    return syscall_table;
}
