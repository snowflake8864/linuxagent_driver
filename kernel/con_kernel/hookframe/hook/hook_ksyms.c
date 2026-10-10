
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/list.h>
#include "khookframe.h"
#include "core/kvd_blm.h"
#include "hook_ksyms.h"
#include "kallsyms.h"


#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
    #if defined(__aarch64__)
        #define SYS_CALL_WRAPPER(name) "__arm64_"name
    #elif defined(__x86_64__)
        #define SYS_CALL_WRAPPER(name) "__x64_"name
    #else
        #define SYS_CALL_WRAPPER(name) name
    #endif
#else
    #define SYS_CALL_WRAPPER(name) name
#endif


#define SYS_CALL_CLOSE_NAME SYS_CALL_WRAPPER("sys_close")
//syms
typedef struct {
    struct list_head lh;
    long addr;
    char sym_name[];
} ksym_addr_t;

static DEFINE_RWLOCK(ksyms_lock);
static struct list_head ksyms;


static const char* target_ksyms[] = {
                SYS_CALL_CLOSE_NAME,
                "security_ops",
                "sys_call_table",
                "security_hook_heads",
                "security_secondary_ops",
                "__init_begin",
                "__start_rodata",
                "rodata_enabled",
                "update_mapping_prot",
                "rtnl_msg_handlers",
                "core_kernel_text",
            };
static kvd_blm_hval_t target_ksyms_hval;

static int add_ksym_addr(const char* name,
                    int size, long addr);

static bool is_target_ksym(const char* name)
{
    size_t i = 0;
    size_t size = 0;
    bool bhit = false;

    bhit = kvd_check_blm_hval(name,strlen(name),
                            &target_ksyms_hval);
    if(!bhit) { return bhit; }

    size = ARRAY_SIZE(target_ksyms);
    for(;i < size;i++) {
        bhit = !strcmp(name,target_ksyms[i]);
        if(bhit) { break; }
    }

    return bhit;
}

static int ksym_get_cb(const char* data,size_t len)
{
    u_long addr = 0; 
    char type = 0;
    char name[256] = {0};

    int n = sscanf(data,"%lx %c %s",
                &addr,&type,name);
    if(n != 3) { return 0; }

    if (is_target_ksym(name)) {
        add_ksym_addr(name,strlen(name),addr);
    }

    return 0;
}

static int hook_search_ksym_bylist(const char* sym_name,
                                unsigned long *sym_addr)
{
    int rc = -EINVAL;
    unsigned long flags = 0;
    ksym_addr_t* cur = NULL;
    ksym_addr_t* next = NULL;

    if (NULL == sym_name) {
        return rc;
    }

    rc = -ENOENT;
    read_lock_irqsave(&ksyms_lock,flags);
    list_for_each_entry_safe(cur,next,
                        &ksyms,lh) {
        if (strcmp(cur->sym_name,sym_name) == 0) {
            *sym_addr = cur->addr;
            rc = 0;
            break;
        }
    }
    read_unlock_irqrestore(&ksyms_lock,flags);

    return rc;
}

extern int load_sysmap(const char* sysmaps[],size_t size,
                int (*cb)(const char* data,size_t len));
extern void refix_ksym_addr(void);

//只有高版本的内核上才有地址随机化功能，低于3.10以下的内核不用考虑地址随机化
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    static long distance = -1;
    static u_long sys_close_addr = 0;

    static int proc_kallsyms_cb(const char* data,size_t len)
    {
        u_long addr = 0;                          	
        char type = 0;
        char name[256] = {0};
                                                
        int n = sscanf(data,"%lx %c %s",          	
                    &addr,&type,name);
        if(n != 3) { return 0; }

        if(!strcmp(name,SYS_CALL_CLOSE_NAME))
        {
            sys_close_addr = addr;	
            return 1; //stop find
        }
                                                
        return 0;
    }

    static u_long get_sys_close_addr(void) 
    {
        int rc = 0;
        char kallsyms[256] = {0};

        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	    #if 0
            unsigned len = 0;
            const char* appcwd;
            appcwd = kvd_get_pwd_pathname(&len);
            if(IS_ERR(appcwd)) { return 0; }

            kvd_snprintf(kallsyms,sizeof(kallsyms),
                    "%s/Data/kallsyms",appcwd);
            kvd_put_pathname(appcwd);
	   #else
            strcpy(kallsyms,"/opt/osec/Data/kallsyms");
	   #endif
        #else
            strcpy(kallsyms,"/proc/kallsyms");
        #endif
	LOG_INFO("=======kallsyms[%s]\n", kallsyms);
        rc = kvd_load_kallsyms(kallsyms,proc_kallsyms_cb);
        if(rc) {
            LOG_ERROR("load kallsyms failed,rc: %d\n",rc);
        } else {
            LOG_INFO("%s addr in /proc/kallsyms: %lx\n",
                    SYS_CALL_CLOSE_NAME,sys_close_addr);
        }

        return sys_close_addr;
    }

    static int init_revise_sysmap_addr(void)
    {
        int rc = -EFAULT;
        u_long real_addr = 0; //真实地址
        u_long sysmap_addr = 0; //Sysmap文件中的静态地址

        real_addr = (u_long)kallsyms_lookup_name(SYS_CALL_CLOSE_NAME);
        //再尝试从/proc/kallsyms文件中直接找地址
        if(real_addr == 0) { real_addr = get_sys_close_addr(); }
        //再失败就是game over
        if(real_addr == 0) {
            LOG_ERROR("can't get %s real-addr\n",
                        SYS_CALL_CLOSE_NAME);
            return rc;
        }

        if (0 == hook_search_ksym_bylist(SYS_CALL_CLOSE_NAME,&sysmap_addr)) {
            rc = 0;
            //计算出地址随机化时使用的偏移
            distance = real_addr - sysmap_addr;
            LOG_INFO("kernel-address offset is: %lx\n",distance);
        } else {
            LOG_ERROR("failed to search %s sysmap-addr\n",
                    SYS_CALL_CLOSE_NAME);
        }

        return rc;
    }

    //对从Sysmap文件中读取的静态地址进行修正，因为当内核开启地址随机化后，
    //内核实际运行中的地址与Sysmap中的地址是不同的
    static int revise_sysmap_addrs(void)
    {
        int rc = -EFAULT;
        unsigned long flags = 0;
        ksym_addr_t* cur = NULL;
        ksym_addr_t* next = NULL;

        if(distance == -1) {
            return rc;
        }

        rc = 0;
        write_lock_irqsave(&ksyms_lock,flags);
        list_for_each_entry_safe(cur,next,
                            &ksyms,lh)
        {
            cur->addr += distance;
            LOG_INFO("%s revised address: %lx\n",
                    cur->sym_name,cur->addr);
        }
        write_unlock_irqrestore(&ksyms_lock,flags);

        return rc;
    }
#else
    static int init_revise_sysmap_addr(void)
    { return 0; }

    static int revise_sysmap_addrs(void)
    { return 0; }
#endif

void init_syms_opt(const char* sysmaps[],size_t size)
{
    int rc = 0;
    LOG_INFO("syms init..\n");
    INIT_LIST_HEAD(&ksyms);

    kvd_array_blm_hval(target_ksyms,
            ARRAY_SIZE(target_ksyms),
            &target_ksyms_hval);
    rc = load_sysmap(sysmaps,size,
                    ksym_get_cb);
    if(rc) { return; }

    rc = init_revise_sysmap_addr();
    if(rc) { goto out; }
    //修正从Sysmap文件中读取的地址
    revise_sysmap_addrs();
    //修正每个平台上获取的内核地址
    refix_ksym_addr(); 
    return;

out:
    clear_syms_opt();
}

static void clear_ksyms(struct list_head* head)
{
    int count = 0;
    ksym_addr_t* cur = NULL;
    ksym_addr_t* next = NULL;

    list_for_each_entry_safe(cur,next,
                        head,lh)
    {
        count++;
        list_del(&cur->lh);
        kfree(cur);
    }

    LOG_INFO("clean up ksyms,"
        "affect items: %d\n",count);
}

int clear_syms_opt(void)
{
    unsigned long flags;
    struct list_head dup_list;

    INIT_LIST_HEAD(&dup_list);

    write_lock_irqsave(&ksyms_lock,flags);
    list_splice_init(&ksyms,&dup_list);
    write_unlock_irqrestore(&ksyms_lock,flags);

    clear_ksyms(&dup_list);
    LOG_INFO("syms finish clear item list \n");

    return 0;
}

static ksym_addr_t* create_ksym(const char* name,
                            int size, long addr)
{
    ksym_addr_t* pksym = NULL;

    pksym = kzalloc(sizeof(*pksym) + size + 1,GFP_ATOMIC);
    if (pksym == NULL) {
        pksym = ERR_PTR(-ENOMEM);
        return pksym;
    }

    pksym->addr = addr;
    strncpy(pksym->sym_name,name, size);
    return pksym;
}

extern int preset_ksym_addr(const char* symname,
                            unsigned long addr);
int add_ksym_addr(const char* name, int size, long addr)
{
    int rc = -EINVAL;
    long old_addr = 0;
    unsigned long flags = 0;
    ksym_addr_t* pksym = NULL;
    ksym_addr_t* cur = NULL;
    ksym_addr_t* next = NULL;

    if (NULL == name) {
        return rc;
    }

    rc = preset_ksym_addr(name,addr);
    if(rc == 0) { return rc; }

    pksym = create_ksym(name,size,addr);
    if(IS_ERR(pksym)) { 
        return PTR_ERR(pksym); 
    }

	rc = 0;
    write_lock_irqsave(&ksyms_lock,flags);
    list_for_each_entry_safe(cur,next,
                        &ksyms,lh){
        if (strcmp(cur->sym_name, name) == 0) {
            //对于mips我们在2.6.32-0.54.1207_12.ns6.mips64el #1 SMP Tue Nov 28 15:07:26 CST 2017的版本上发现
            //其sys_call_table有两个不同地址的，我们使用第一个，否则会有问题的
        #if defined(__mips__) && (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
            rc = -EEXIST;
            old_addr = cur->addr;
        #else
            cur->addr = addr;
            rc = -EEXIST;
        #endif
            
            break;
        }
    }

    if(rc == 0) {
        list_add_tail(&pksym->lh, &ksyms);
    }
    write_unlock_irqrestore(&ksyms_lock,flags);

    if(rc == 0) {
        LOG_INFO("add item ksym name = %s "
            "size = %d, addr=%lx\n", 
            name, size, addr);
    } else {
    #if defined(__mips__) && (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
        LOG_INFO("use old ksym: %s addr: %lx,"
            "don't use the new addr: %lx\n",
            name,old_addr,addr);
    #else
        LOG_INFO("update item ksym name = %s "
            "size = %d, addr=%lx\n", 
            name, size, addr);
    #endif
        kfree(pksym);
        rc = 0; //此处依旧返回成功
    }

    return rc;
}

/*
 *Note:!!!!!
 *MIPS64 3.10.0内核上要开启这个DONT_REMAP_ON宏，
 *否则在采用vmap方式修改LSM hook时，在进程退出时调用cleanup_hook_ops会导致内核崩溃
 */
#if defined(CONFIG_MACH_LOONGSON3) || defined(CONFIG_CPU_LOONGSON3)
#define DONT_REMAP_ON
#endif

#ifndef DONT_REMAP_ON
int remap_replace_pointer(void** pp_addr,void* pointer)
{
    struct page *p[1];
    void *mapped;
    unsigned long addr = (unsigned long)pp_addr & PAGE_MASK;

    p[0] = virt_to_page(addr);
	mapped = vmap(p, 1, VM_MAP, PAGE_KERNEL);
	if (mapped == NULL) {
        return -1;
    }
    LOG_INFO("mapped writeable  adress = %p\n" ,
			mapped + offset_in_page(pp_addr));
    *(void **)(mapped + offset_in_page(pp_addr)) = pointer;
    vunmap(mapped);

    return 0;
}
#endif

int hook_replace_pointer(void **pp_addr, void *pointer)
{
    int rc = -1;
    LOG_INFO("pp_addr  = %p\n" , pp_addr);

    if (pointer == NULL) {
        return rc;
    }

    rc = 0;
#ifdef DONT_REMAP_ON
	(void)xchg(pp_addr,pointer);
#else
	rc = remap_replace_pointer(pp_addr,pointer);
#endif
    return rc;
}

    //3.10.0以上的版本才需要
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    //另外如果查找不成功不要修改sym_addr的值
    int hook_search_ksym(const char *sym_name, unsigned long *sym_addr)
    {
        int rc = 0;
        unsigned long addr = 0;
        //3.10.0以上的版本才需要
        addr = (unsigned long)kallsyms_lookup_name(sym_name);
        LOG_DEBUG("kallsyms:name:%s, sym_addr:0x%lx",sym_name, addr);

        if (addr) {
            *sym_addr = addr;
            return rc;
        }
    
        rc = hook_search_ksym_bylist(sym_name,&addr);
        if(rc) { return rc; }

        *sym_addr = addr;
        LOG_INFO("search result:name:%s, sym_addr:0x%lx",
                sym_name, *sym_addr);

        return rc;
    }
#else
    int hook_search_ksym(const char *sym_name, unsigned long *sym_addr)
    {
        return hook_search_ksym_bylist(sym_name,sym_addr);;
    }
#endif
