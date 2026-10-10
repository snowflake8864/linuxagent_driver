#include <linux/module.h>
#include <linux/version.h>
#include <linux/irqflags.h>

#if defined(__x86_64__) || defined(__i386__)
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,14)
    #include <asm/special_insns.h>
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
    #include <asm/system.h>
#endif
#endif
#include "khookframe.h"

#if defined(CONFIG_X86_64)
static const char arch_name[] = "x86_64_hook";
#else
static const char arch_name[] = "i386_hook";
#endif

#ifndef X86_CR0_WP
#define X86_CR0_WP 0x00010000
#endif

//2.6.32-3.10.0以下redhat体系x64/x86内核上如果运行在xen虚拟机模式下
//即使关闭cr0寄存器的写保护在进行hook替换时仍然会崩溃
#if (defined(CONFIG_X86) || defined(CONFIG_X86_64)) && defined(RHEL_RELEASE_CODE) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)) && \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0))

    extern struct start_info *xen_start_info;

    int is_running_in_xen(void)
    {
        return (NULL != xen_start_info);
    }
#else
    int is_running_in_xen(void) { return 0; }
#endif

    /*这里直接使用汇编
    *因为驱动6.0.2.2305版本有重大bug
    *在凝思4.2.40上发现：
    *因错误hook renameat2(在3.10以下版本的内核上根本就没有这个系统调用)
    *导致使用read_cr0/write_cr0访问CR0,MSR_LSTAR这些寄存器时直接引起系统异常崩溃了
    *我们不得不再此处做处理，恶心啊!!!!!!!!!!
    */
#if CR0_ASM_SYNTAX_BUILD == 1
    static unsigned long my_read_cr0(void)
    {
        unsigned long cr0;
	    asm volatile("movq %%cr0,%0" : "=r" (cr0));
	    return cr0;
    }

    static void my_write_cr0(unsigned long val)
    {
        asm volatile("movq %0,%%cr0" :: "r" (val));
    }

#else
#if !defined(CONFIG_X86_64) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
    #define my_read_cr0     read_cr0
    static void my_write_cr0(unsigned long val)
    {
        //这里我们自己直接操作CR0，不要调用write_cr0这个内核提供的接口
        //因为在5.3及更新版本的内核上发现write_cr0会做检验，
        //在系统启动后默认是不让关闭WP的
        //uos1060,4.19.90内核增加了新版本write_cr0的检验
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0) || \
            (defined(CONFIG_SECURITY_HOOKMANAGER) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,90))
        #ifdef __FORCE_ORDER
        //这是内核5.9.2引入的新写法，之前的写法gcc有BUG
        asm volatile("mov %0,%%cr0": : "r" (val) : "memory");
        #else
        asm volatile("mov %0,%%cr0": "+r" (val), "+m" (__force_order));
        #endif
    #else
        write_cr0(val);
    #endif
    }
#else
    static unsigned long my_read_cr0(void)
    {
        unsigned long cr0;
	    asm volatile("movq %%cr0,%0" : "=r" (cr0));
	    return cr0;
    }

    static void my_write_cr0(unsigned long val)
    {
        asm volatile("movq %0,%%cr0" :: "r" (val));
    }
#endif
#endif

static int disable_x86_wp (unsigned long* pflags)
{
    int rc = -EINVAL;
    unsigned long cr0;

    if(!pflags) { 
        return rc; 
    }

    if(is_running_in_xen()) {
        return rc;
    }

    rc = 0;
    local_irq_disable();
    barrier();

    cr0 = my_read_cr0();
    my_write_cr0(cr0 & ~X86_CR0_WP);
    *pflags = cr0;

    return rc;
}

static void restore_x86_wp(unsigned long cr0)
{
    my_write_cr0(cr0);

    barrier();
    local_irq_enable();
}


static int set_x86_ksym_addr(const char* symname,
                unsigned long addr)
{ 
    (void)symname; (void)addr; 
    return -EAGAIN;
}

//do hook init by cpu architecture
static int init_x86_hook(void) 
{ 
    LOG_INFO("init %s\n",
        arch_name);
    if(is_running_in_xen()) {
        LOG_INFO("running in xen,"
            "we can't disable wp");
    }
    return 0;
}

static void uninit_x86_hook(void) {}

static struct hook_arch_operations x86_hao = {
		.name = arch_name,
		.fn_init = init_x86_hook,
		.fn_uninit = uninit_x86_hook,
		.fn_disable_wp = disable_x86_wp,
		.fn_restore_wp = restore_x86_wp,
		.fn_set_ksym_addr = set_x86_ksym_addr,
	};

static struct hook_arch_operations* pha_operation = &x86_hao;

