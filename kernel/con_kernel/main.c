#include <linux/version.h>
#include <linux/module.h>
#include <linux/utsname.h>
#if 0
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

#else
#ifndef UTS_VERSION
    #define SAFE_UTS_VERSION init_uts_ns.name.release
#else
    #define SAFE_UTS_VERSION UTS_VERSION
#endif
#endif
#include <linux/vmalloc.h>

#include "config.h"
#include "gnHead.h"
#include "hook/hook.h"
#include "core/gnkernel.h"
#include "core/kvd_core.h"
#include "abnormal/abnormal.h"
#include "defense/defense_hook.h"
#include "kthread/kthread.h"
#include "stack/stack.h"
#include "clientexit/client_exit.h"
#include "utils/utils.h"
#include "core/cpu.h"
#include "utils/task_cmdline.h"
#include "khookframe.h"
#include "rules/rules.h"
#include "defense/network_dos.h"
#include "forward/forward.h"
#include "md5hash/md5hash.h"
#include "ref_manager/module_ref.h"
#include "log_manager/log_mgr.h"

//#include "nf_ring/nf_ring.h"

static int protocol = 20;
static char* cdev_name = KOSEC_CDEV_NAME;

/*
 *可选值: KVD_FH_DISABLED,KVD_FH_SUPPOSED,KVD_FH_PREFERENCE
 */
static int fh_supported = KVD_FH_DISABLED; //ftrace hook supported
//用户指定强制使用syscall-hook
static int force_syscall_hook = 0;

#if LSM_VERSION_BUILD == 1
int _hook_lsm_on = 1;
#else
#if 0
#if 1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#if 0
#if defined (KOSEC_LSM_HOOK_ENABLED)
int _hook_lsm_on = 1;
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
    int _hook_lsm_on = 1;
#else
    int _hook_lsm_on = 0;
#endif

#endif
#else
    int _hook_lsm_on = 1;
#endif
#else
    int _hook_lsm_on = 0;
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
    int _hook_lsm_on = 1;
#else
    int _hook_lsm_on = 0;
#endif
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
    int _hook_lsm_on = 1;
#else
    int _hook_lsm_on = 0;
#endif

#endif

#endif


static char _appcwd[256] = {0};
static unsigned _appcwd_len = 0;

//内核模块文件路径
static const char* _kmod_path = NULL;
static unsigned _kmod_pathlen = 0;
//主程序版本(9999 << 45 + 9999 << 30 + 9999 << 15 + 9999)
static uint64_t _appver = 0;
//版本号最多是这种:9999.9999.9999.9999
static char _str_appver[32] = "";

#define CDEV_HELP \
        "This is used to specify the character device name for vd_base driver," \
        "The default is \"" KOSEC_CDEV_NAME "\".\t"

module_param(protocol, int, S_IRUGO);
module_param(cdev_name,charp,0640);
module_param_named(hook_lsm,_hook_lsm_on,int,S_IRUGO);
module_param(fh_supported,int, S_IRUGO);
module_param_named(use_syshook,force_syscall_hook,int,S_IRUGO);
MODULE_PARM_DESC(cdev_name,CDEV_HELP);

struct new_utsname* get_init_utsname(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
    return init_utsname();
#else
    return &system_utsname;
#endif
}

//获取当前进程的工作路径
const char* vsec_get_appcwd(unsigned* len)
{
    *len = _appcwd_len;
    return _appcwd;
}

static int init_appcwd(void)
{
    unsigned len = 0;
    char* pwd = kvd_get_pwd_pathname(&len);
    if(IS_ERR(pwd)) { 
        return PTR_ERR(pwd); 
    }

    if(len >= sizeof(_appcwd)) {
        return -ENAMETOOLONG;
    }
    _appcwd_len = len;
    memcpy(_appcwd,pwd,len);
    kvd_put_pathname(pwd);

    LOG_INFO("current work directory: %s\n",_appcwd);

    return 0;
}



static int do_kvd_init(void)
{
    int rc = -EFAULT;
    size_t count = 0;
    unsigned len = 0;
    const char* pwd = NULL;
    char boot_sysmap[256] = {0};
    char custom_sysmap[256] = {0};
    const char* sysmaps[8] = {NULL}; 
    struct new_utsname* uts = NULL;

    uts = get_init_utsname();
    if(!uts) { return rc; }

    pwd = vsec_get_appcwd(&len);
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
    rc = kvd_init_ftrace_commlsm2(sysmaps,count,fh_supported,force_syscall_hook);
    if(rc == 0) {
        __hook_mode = kvd_sc_hook_mode();
    }

    return rc;
}

#ifndef UTS_VERSION
#define UTS_VERSION ""
#endif


static void print_module_addr(void)
{
    u_long init_beg,init_end;
    u_long core_beg,core_end;

    kvd_module_init_addr(THIS_MODULE,&init_beg,&init_end);
    kvd_module_core_addr(THIS_MODULE,&core_beg,&core_end);

    LOG_INFO( "module init address[0x%lx,0x%lx),"
            "module core addr[0x%lx,0x%lx)\n",
            init_beg,init_end,
            core_beg,core_end);
}

/*
 *在arm64_4.14.0-115.5.1.el7a.08.aarch64上发现的我们编译时使用的GCC5.4.0,
 *而实际部署环境中操作系统内核编译时使用的是GCC4.8.0，由于高版本GCC中引入了CC_HAVE_ASM_GOTO宏
 *导致struct module结构体定义时多了两个成员，导致我们的内核模块引用计数异常，引起无法卸载的问题。
 */
static int check_init_refcnt(void)
{
    int rc = 0;
    struct module* this = THIS_MODULE;
    u_int refcnt = module_refcount(this);

    if(refcnt > 1) {
        rc = -EFAULT;
        LOG_ERROR("badly: init refcnt check failed,"
            "refcnt: %u; we may use wrong compiler\n",refcnt);
    }

    return rc;
}

static void set_kmod_pathname(void)
{
    int err = 0;
    char* p = NULL;
    struct path path;
    unsigned argc = 8;
    char* argv[8] = {NULL};
    unsigned len = PAGE_SIZE;

    char* buf = kzalloc(len,GFP_KERNEL);
    if(!buf) { return; }

    p = vsec_get_task_cmdline2(current,buf,&len,
                                &argc,argv);
    if(KVD_IS_ERR_OR_NULL(p) || (argc < 2)) { 
        goto out; 
    }

    err = kvd_path_lookup(argv[1],
				LOOKUP_FOLLOW,&path);
    if(err) { goto out; }

    len = 0;
    p = kvd_get_pathname(&path,&len);
    kvd_path_put(&path);
    if(!KVD_IS_ERR_OR_NULL(p)) {
        _kmod_path = p;
        _kmod_pathlen = len;
    }

out:
    kfree(buf);
}

const char* get_kmod_pathname(unsigned* plen)
{
    *plen = _kmod_pathlen;
    return _kmod_path;
}

static void free_kmod_pathname(void)
{
    if(_kmod_path) {
        kvd_put_pathname(_kmod_path);
        _kmod_pathlen = 0;
    }
}

void vsec_net_init(void);
void vsec_net_uninit(void);

static int __init vd_base_init(void)
{
    int rc = 0;
    int err_stat = 0;
    struct new_utsname* putsname = NULL;

    LOG_INFO("init action,version: %s,kernel-version: %s %s,"
            "build by compiler: %s %s at: %s\n",
            DEVICE_VERSION,
            UTS_RELEASE,UTS_VERSION,
            COMPILER,__VERSION__,BUILD_TIME);
    rc = check_init_refcnt();
    if(rc < 0) {
        err_stat = 1;
        goto out;
    }

    md5_module_init(); 
    vsec_cpu_init();
    putsname = get_init_utsname();
    LOG_INFO("current kernel_version: %s %s\n",
            putsname->release,putsname->version);
    rc = init_appcwd();
    if(rc) {
        LOG_ERROR("init app cwd failed,"
                    "rc: %d\n",rc);
        err_stat = 2;
        goto out;
    }

    rc = abnormal_check_init();
    if (rc) { 
        err_stat = 3;
        goto out;
    }

    vsec_utils_init();
    set_kmod_pathname();

    rc = gnkernel_init(protocol,cdev_name);
    if(rc < 0) {
        free_kmod_pathname();
        LOG_ERROR("gnkernel_init failed,rc: %d\n",rc);
        err_stat = 4;
		goto out;
    }
    rc = rules_init();
    if (rc < 0) {
		LOG_ERROR("=======rules_init failed,rc: %d\n",rc);
        gnkernel_exit();
        free_kmod_pathname();
        err_stat = 5;
        goto out;
    }

    rc = do_kvd_init();
    if(rc < 0) {
        LOG_ERROR("kvd_init failed,rc: %d\n",rc);
        rules_exit();
        gnkernel_exit();
        free_kmod_pathname();
        err_stat = 6;
        goto out;
    }
	
	rc = vsec_hook_init();
	if(rc < 0) {
		LOG_ERROR("kvd_init failed,rc: %d\n",rc);
		kvd_uninit_ftrace_commlsm();
        rules_exit();
        gnkernel_exit();
        free_kmod_pathname();
        err_stat = 7;
        goto out;
	}
    /* 功能初始化请在框架初始化之后进行 */

    rc = defense_init();
    if (rc < 0) {
        LOG_ERROR("defense_init failed,rc: %d\n",rc);
        vsec_hook_exit();
   		kvd_uninit_ftrace_commlsm();
        rules_exit();
        gnkernel_exit();
        free_kmod_pathname();
        err_stat = 8;
        goto out;
	}
    rc = network_dos_init();
    if (rc < 0) {
		LOG_ERROR("network_dos_init failed,rc: %d\n",rc);
        defense_exit();
        vsec_hook_exit();
   		kvd_uninit_ftrace_commlsm();
        rules_exit();
        gnkernel_exit();
        free_kmod_pathname();
        err_stat = 9;
        goto out;
	}	
    vsec_kthread_init(); //audit flow monitor audit thread init
	rc = vsec_stack_init();
    if (rc < 0) {
		LOG_ERROR("vsec_kthread_init failed,rc: %d\n",rc);
        network_dos_exit();
        defense_exit();
        vsec_hook_exit();
   		kvd_uninit_ftrace_commlsm();
        rules_exit();
        gnkernel_exit();
        free_kmod_pathname();
        err_stat = 10;
        goto out;
	}
    rc = forward_init();
    if (rc < 0) {
		LOG_ERROR("forward_init failed,rc: %d\n",rc);
        vsec_stack_uninit();
        network_dos_exit();
        defense_exit();
        vsec_hook_exit();
   		kvd_uninit_ftrace_commlsm();
        rules_exit();
        gnkernel_exit();
        free_kmod_pathname();
        err_stat = 11;
        goto out;
	}
    
    vsec_client_exit_init();

    LOG_INFO("init ok,__this_module[0x%lx],exit fn: 0x%lx\n",
        (u_long)THIS_MODULE,(u_long)(THIS_MODULE->exit));
    
    print_module_addr();
    rc = kvd_sc_hook_start();
    if (rc < 0) {
		LOG_ERROR("kvd_sc_hook_start failed,rc: %d\n",rc);
        vsec_stack_uninit();
        network_dos_exit();
        defense_exit();
        vsec_hook_exit();
   		kvd_uninit_ftrace_commlsm();
        rules_exit();
        gnkernel_exit();
        free_kmod_pathname();
        err_stat = 12;
        goto out;
	}

    module_ref_init();
    log_manager_init();
    return rc;
out:

    abnormal_set_fail_status(err_stat);
    return rc;
}

static void __exit vd_base_exit(void)
{
    LOG_INFO("hook exit \n");

    kvd_sc_hook_stop();

    log_manager_exit();
    module_ref_exit(); 
    //Note: 这个一定要比defense_exit早
    //否则进程退出时还会调用自保相关的清理函数导致问题
    vsec_client_exit_uninit();

    vsec_stack_uninit();
    vsec_kthread_exit();

    defense_exit();
    network_dos_exit();

  

	vsec_hook_exit();
    kvd_uninit_ftrace_commlsm();
    gnkernel_exit();
    
    free_kmod_pathname();
    vsec_utils_uninit();
    abnormal_check_exit();
    vsec_cpu_uninit();
    forward_exit();
    rules_exit();
    md5_module_exit(); 
}


MODULE_AUTHOR("veda");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("osec_base");
//DEVICE_VERSION由Makefile中的宏定义
MODULE_VERSION(DEVICE_VERSION);

module_init(vd_base_init);
module_exit(vd_base_exit);
