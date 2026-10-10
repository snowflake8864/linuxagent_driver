#include <linux/types.h>
#include <linux/list.h>
#include <linux/compiler.h>  //likely & unlikely
#include <linux/module.h>
#include <linux/profile.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/pid.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/binfmts.h>

#include "gnHead.h"
#include "gnkernel.h"
#include "flag_cache.h"
#include "clientexit/client_exit.h"
#include "netlink/netlink.h"
#include "cdev/cdev.h"
#include "cdev/mmcdev.h"
#include "utils/utils.h"
#include "core/kvd_core.h"
#include "notify/client_notify.h"
#include "sysfs/sysfs_core.h"

#define CHECK_ERROR_COUNT(NUM,is_abnormal,logflag) { \
        wait_error_count ++;\
        if (wait_error_count > NUM) {\
            notifier_abnormal(&is_abnormal,&bad_time,bad_time_limit,logflag);\
            wait_error_count = 0;\
        }\
        }\


/*驱动通信逻辑
 *获取用户层端口号:
 *r3层发送自己的通信端口及其他可能需要的必要信息给驱动，驱动验证r3身份后发送回应.
 *事件拦截：hook到事件时将事件信息以及监听标记的地址发向r3，r3判断是否放行，将放行结果及
 *监听标记的地址发回kernel，kernel根据放行结果设置监听标记的值并唤醒进程。
 */


// TODO: this should be locked when use or modify
static atomic_t snd_user_portid = ATOMIC_INIT(0);    // user process port
static atomic_t user_service_pid = ATOMIC_INIT(0);      // user service pid
static unsigned long wait_nl_abnormal = 0;
static unsigned long nowait_nl_abnormal = 0;


u32 get_snd_portid(void)
{
    return atomic_read(&snd_user_portid);
}

pid_t get_service_pid(void)
{
    return atomic_read(&user_service_pid);
}

int check_snd_portid(u32 portid)
{
    u32 user_portid = atomic_read(&snd_user_portid);
    return likely(user_portid == portid);
}

void set_debug_flag(int flag);
void set_portid_service_pid(u32 portid,pid_t pid)
{
    atomic_set(&user_service_pid,pid);
    atomic_set(&snd_user_portid,portid);
    clear_bit(0,&wait_nl_abnormal);
    clear_bit(0,&nowait_nl_abnormal);
    set_debug_flag(0);
}

void clear_portid_service_pid(void)
{
    set_portid_service_pid(0,0);
}

int user_active(void)
{
    return (get_snd_portid() > 0);
}

static void notifier_recovery(const char* logflag,
                        unsigned long* is_abnormal,
                        u_long* bad_time)
{
    int is_set = test_and_clear_bit(0,is_abnormal);
    if(!is_set) { return; }

    *bad_time = 1;
    LOG_INFO("client notifier recory for %s\n",logflag);
}

/*
 *Note:
 *此处不要清理snd_user_portid与user_service_pid
 *因为及时发送异常，我们还是想接收来自应用层的消息
 */
static void notifier_abnormal(unsigned long* is_abnormal,
                    u_long* bad_time,int tlimit,
                    const char* logflag)
{
    u32 portid = get_snd_portid();
    pid_t pid = get_service_pid();
    LOG_INFO("client %s-notifier abnormal,stop to send msg %d seconds,"
            "service pid [%d], snd_user_portid %u\n",
            logflag,tlimit,pid,portid);

    set_bit(0,is_abnormal);
    *bad_time = vsec_get_now_sec();
}

static int is_notifier_ok(unsigned long* is_abnormal,
                    u_long bad_time,int tlimit)
{
    int ok = 0;
    u_long now;

    //异常标识未置位
    ok = !test_bit(0,is_abnormal);
    if(ok) { return ok; }

    now = vsec_get_now_sec();
    ok = (now >= (bad_time + tlimit));
    return ok;
}

int send_nl_data(int cmd, void* data, int nsize)
{
    int ok = 1;
    int rc = -EINVAL;
    static int bad_time_limit = 60;    
    static u_long bad_time = 0;
    static volatile int wait_error_count = 0;

    ok = (get_service_pid() > 0);
    if(!ok) { return rc; }

    ok = is_notifier_ok(&nowait_nl_abnormal,bad_time,
                    bad_time_limit);
    if(!ok) { return rc; }

    rc = vsec_notify_client(cmd & 0xFFFF,data,(u32)nsize);
    if (!rc) {
        wait_error_count = 0;
        notifier_recovery("nowait-notifier",
            &nowait_nl_abnormal,&bad_time);
    } else {
        //针对-EAGAIN一定要特殊处理
        if(rc != -EAGAIN) {
            CHECK_ERROR_COUNT(128,nowait_nl_abnormal,"nowait");
        }
    }

    return rc;
}

int send_nowait_nl_data(int cmd, void* data, int nsize)
{
    int ok = 1;
    int rc = -EINVAL;
    void* key = NULL;
    static struct timespec bad_time = {0,0};
    static volatile int wait_error_count = 0;
    static int bad_time_limit = 3600;//3600 seconds

    ok = ((get_service_pid() > 0));
    if(!ok) { return rc; }

    ok = is_notifier_ok(&nowait_nl_abnormal,&bad_time,
                    bad_time_limit);
    if(!ok) { return rc; }
    rc = vsec_notify_client(cmd, data, nsize);
    //消息发送失败，不再等待，直接结束
    if (rc) {
        return rc;
    }

//    printk("send_nowait_nl_data==\n");
     return rc;
}
int send_nl_data_callback(int cmd, void* data, int nsize, void** ppwait,
                          void* extra, Tkerncallback callback)
{
    int ok = 1;
    int rc = -EINVAL;
    void* key = NULL;
    struct wait_flag* p_wait_flag;
    static u_long bad_time = 0;
    static volatile int wait_error_count = 0;
    static int bad_time_limit = 3600;//3600 seconds
    
    ok = (ppwait && (get_service_pid() > 0));
    if(!ok) { return rc; }

    ok = is_notifier_ok(&wait_nl_abnormal,bad_time,
                    bad_time_limit);
    if(!ok) { return rc; }

    p_wait_flag = get_wait_flag(extra, callback);
    if (!p_wait_flag) { 
        rc = -ENOMEM;
        return rc; 
    }

    //此处使用*ppwait将key的值给返回，
    //不要直接返回p_wait_flag的值
    key = p_wait_flag->key;
    *ppwait = key;
    /*
     *此处针对-EAGAIN不做特殊处理
     *因为在wait-reply模式下，如果返回-EAGAIN就表明应用层无法及时处理了
     *我们要及时对后续等待的进程放行，否则后导致非常严重的问题
     */
    rc = vsec_notify_client(cmd, data, nsize);
    //消息发送失败，不再等待，直接结束
    if (rc) {
        no_waiting(p_wait_flag);
        return rc;
    }

    //有回调就不使用同步等待
    if (!callback) {
        rc = waiting_flag(p_wait_flag);
        if (rc) {
            LOG_ERROR("gnKernel: Wait reply fail, %d\n", rc);
            CHECK_ERROR_COUNT(3,wait_nl_abnormal,"wait");
        } else {
            wait_error_count = 0;
            notifier_recovery("wait-notifier",
                &wait_nl_abnormal,&bad_time);
        }
        //不要直接使用p_wait_flag，因为到此处p_wait_flag可能已被释放
        put_wait(key);
    }

    return rc;
}

int send_wait_nl_data(int cmd, void* data, int nsize, void** ppwait, void* extra)
{
    return send_nl_data_callback(cmd, data, nsize, ppwait, extra, NULL);
}





int is_self_process2(pid_t pid)
{
    int rc = 0;
    pid_t srv_pid = get_service_pid();

    if(srv_pid <= 0) {
        return rc;
    }

    rc = (srv_pid == pid);
    if(rc) { return rc; }

    rc = is_self_comm();
    if(rc) { return rc; }
   
    rc = match_pid_family(pid,srv_pid);
    return rc;
}

//是否是自身进程
int is_self_process(void)
{
    int rc = 0;
    pid_t pid = get_service_pid();

    if(pid <= 0) {
        return rc;
    }

    rc = is_self_comm();
    if(rc) { return rc; }

    rc = match_task_family(current,pid);
    return rc;
}

static char sysproc[128] = {0};
static void system_process_init(void)
{
    int i;
    const char *pinit[] = {
        "/sbin/init",
        "/usr/sbin/init",
    };

    for (i = 0; i < sizeof(pinit)/sizeof(pinit[0]); i++) {
        int rc;
        int len = 0;
        char *rname;
        struct path path;
        rc = kvd_path_lookup(pinit[i], LOOKUP_FOLLOW, &path);
        if (rc) continue;
        rname = kvd_get_pathname(&path, &len);
        kvd_path_put(&path);
        if (IS_ERR(rname)) continue;
        strncpy(sysproc, rname, sizeof(sysproc)-1);
        kvd_put_pathname(rname);
        break;
    }
    LOG_INFO("system process init: %s\n", sysproc);
}

int is_system_process(struct task_struct *tsk)
{
    int rc = 0;
    int len;
    char *exe_name;

    if (!tsk) return 0;
    exe_name = kvd_get_task_pathname(tsk, &len);
    if (IS_ERR(exe_name)) {
        return 0;
    }
    if (strcmp(sysproc, exe_name) == 0) {
        rc = 1;
    }
    kvd_put_pathname(exe_name);

    return rc;
}

int register_cmd_handlers(void);
void unregister_cmd_handlers(void);

int gnkernel_init(int protocol,const char* cdev_name)
{
    int rc = -1;

    rc = init_wait_flags();
    if(rc) { return rc; }

    vsec_init_client_notifer();

    rc = init_netlink(protocol);
    if(rc) {
        vsec_uninit_client_notifier();
        uninit_wait_flags();
        return rc; 
    }

    rc = vsec_cdev_init(cdev_name);
    if(rc) {
        uninit_netlink();
        vsec_uninit_client_notifier();
        uninit_wait_flags();
        return rc;
    }

    rc = vsec_sysfs_core_init();
    if(rc) {
        vsec_cdev_uninit();
        uninit_netlink();
        vsec_uninit_client_notifier();
        uninit_wait_flags();
        return rc;
    }

    vsec_mmc_init();

    register_cmd_handlers();
    system_process_init();
    return rc;
}

void gnkernel_exit(void)
{
    unregister_cmd_handlers();
    vsec_mmc_exit();
    vsec_sysfs_core_uninit();
    vsec_cdev_uninit();
    uninit_netlink();
    vsec_uninit_client_notifier();
    uninit_wait_flags();
}
