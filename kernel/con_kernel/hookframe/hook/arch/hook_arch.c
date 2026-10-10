/*
 *hook_arch.c: 2019-07-24 created by qudreams
 *hook syscalls by CPU architecture
 */

#include <linux/types.h>
#include <linux/errno.h>
#include "hook_arch.h"
#include "khookframe.h"


static int def_init_hook_arch(void) 
{ 
    LOG_INFO("default hook arch init\n");
    return 0; 
}
static void def_uninit_hook_arch(void) {}
static int def_disable_wp(unsigned long* pflags) 
{ 
    (void)pflags; 
    return 0;
}
static void def_restore_wp(unsigned long flags) {}
static int def_set_ksym_addr(const char* name,
                            unsigned long addr)
{
    (void)name;
    (void)addr;

    return -EAGAIN;
}

//hao is a shortname for hook-arch-opertion
static struct hook_arch_operations def_hao = {
    .name = "def_hook_arch",
    .fn_init = def_init_hook_arch,
    .fn_uninit = def_uninit_hook_arch,
    .fn_disable_wp = def_disable_wp,
    .fn_restore_wp = def_restore_wp,
    .fn_set_ksym_addr = def_set_ksym_addr,
};


#if defined(CONFIG_X86)
    //x86,x86_64
    #include "hook_x86.c"
//针对华为arm64 kirin 990处理器平台uos系统，我们不需要关闭写保护，
//因为系统默认已经开启了对lsm的写操作,我们在这个平台上只用lsm,不用hook syscall
#elif defined(CONFIG_ARM64) && !defined(CONFIG_HUAWEI_ARMPC_PLATFORM)      
    #if defined(CONFIG_KALLSYMS_ALL) && (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
        #if !defined(RHEL_RELEASE_CODE)
		    #include "hook_arm64.c"
        #else 
            #include "hook_arm642.c" 
        #endif
    #else
        #include "hook_arm642.c"
    #endif
#else
	static struct hook_arch_operations* pha_operation = &def_hao;
#endif

int init_hook_arch(void)
{
	(void)def_hao; //just to avoid warning on x86
#if defined(CONFIG_HUAWEI_ARMPC_PLATFORM) 
    #if defined(CONFIG_SECURITY_KYLIN_EXTEND) || \
        defined(CONFIG_SECURITY_WRITABLE_HOOKS)
        return pha_operation->fn_init();
    #else
	    LOG_INFO("this is a HUAWEI arm-pc,"
			    "but no SECURITY_WRITEABLE_HOOKS;"
			    "we can't support it\n");
        return -ENOTSUPP;
    #endif
#else	
    return pha_operation->fn_init();
#endif
}

void uninit_hook_arch(void)
{
    pha_operation->fn_uninit();
}

int preset_ksym_addr(const char* name,unsigned long addr)
{
    return pha_operation->fn_set_ksym_addr(name,addr);
}

int disable_wp(unsigned long* pflags)
{
    if (kvd_wp_disabled()) {
        return -ENOTSUPP;
    }
    return pha_operation->fn_disable_wp(pflags);
}

void restore_wp(unsigned long flags)
{
    if (kvd_wp_disabled()) {
        return;
    }
    pha_operation->fn_restore_wp(flags);
}

void refix_ksym_addr(void)
{
    if(pha_operation->fn_refix_ksym_addr)
    {
        pha_operation->fn_refix_ksym_addr();
    }
}
