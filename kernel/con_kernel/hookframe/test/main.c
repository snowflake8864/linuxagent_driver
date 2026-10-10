#include <linux/version.h>
#include <linux/vermagic.h> //for UTS_RELEASE
#include <linux/module.h>
#include <linux/utsname.h>
#include "core/kvd_core.h"
#include "khookframe.h"


//需要注意的是mips64 3.10.0版本的系统上没有UTS_VERSION
//另外suse 3.12.0版本的内核上连generated/compile.h文件都没有
//我们此处为了处理方便全部限定只有4.0.0以上的内核才引入下面的文件
#if ((!defined(CONFIG_MACH_LOONGSON3)  && !defined(CONFIG_X86_32)) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)))

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
        #include <generated/compile.h> //for UTS_VERSION
    #else
        #include <linux/compile.h> //UTS_VERSION
    #endif
#endif


unsigned long debug_flag = 0;
static int test_flag  = 10;

extern void init_fake_test(void);
extern void uninit_fake_test(void);
extern int do_hook_syscalls(void);
extern void test_sysfs_init(void);
extern void test_sysfs_uninit(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
struct new_utsname* get_init_utsname(void)
{
    return init_utsname();
}
#else
struct new_utsname* get_init_utsname(void)
{
    return &system_utsname;
}
#endif

static char* get_pwd_pathname(unsigned* plen)
{
    struct path pwd;
    char* kpathname = ERR_PTR(-EINVAL);

    if(!plen) { goto out; }

    kvd_get_fs_pwd(current->fs,&pwd);
    kpathname = kvd_get_pathname(&pwd,plen);
    kvd_path_put(&pwd);

out:
    return kpathname;
}

static int do_kvd_init(void)
{
    int rc = -EFAULT;
    size_t count = 0;
    char* pwd = NULL;
    unsigned len = 0;
    char boot_sysmap[256] = {0};
    char custom_sysmap[256] = {0};
    const char* sysmaps[8] = {NULL}; 
    struct new_utsname* uts = NULL;

    uts = get_init_utsname();
    if(!uts) { return rc; }

    pwd = get_pwd_pathname(&len);
    if(IS_ERR(pwd)) { return PTR_ERR(pwd); }
    
    /*这里不要使用UTS_RELEASE，在中标kylin mips64上发现:
     *UTS_RELEASE与实际的release不一样,真是垃圾
    */
    kvd_snprintf(boot_sysmap,sizeof(boot_sysmap),
                "/boot/System.map-%s",
                uts->release);
    sysmaps[count++] = boot_sysmap;

    kvd_snprintf(custom_sysmap,sizeof(custom_sysmap),
                "%s/Data/System.map-%s",
                pwd,uts->release);
    LOG_INFO("custom sysmap file: %s\n",custom_sysmap);
    sysmaps[count++] = custom_sysmap;

    //sysmaps这个数组中的文件
    //只要有一个打开成功后面的就不再处理了
    rc = kvd_init(sysmaps,count);
    kvd_put_pathname(pwd);

    return rc;
}

//khframe is a short-name for kernel-hook frame
static int __init khframe_init(void)
{
    int rc = 0;

    rc = do_kvd_init();
    if(rc < 0) {
        goto out;
    }

    //test_sysfs_init();
    do_hook_syscalls();
    init_fake_test();
    LOG_INFO("init ok,exit fn: %p\n",THIS_MODULE->exit);
out:
    return rc;
}

static void __exit khframe_exit(void)
{
    LOG_INFO("hook exit ............\n");

    uninit_fake_test();
    //test_sysfs_uninit();

	kvd_uninit();
}


MODULE_AUTHOR("qudreams");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khookframe");
//DEVICE_VERSION由Makefile中的宏定义
#ifdef DEVICE_VERSION
MODULE_VERSION(DEVICE_VERSION);
#endif

module_init(khframe_init);
module_exit(khframe_exit);
