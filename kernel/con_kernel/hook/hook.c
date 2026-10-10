#include <linux/ctype.h>
#include "hook.h"
#include "gnHead.h"
#include "utils/utils.h"
#include "clientexit/client_exit.h"
#include "core/gnkernel.h"
#include "fs/file_access.h"
#include "core/kvd_core.h"
#include "khookframe.h"
#include "lsm/kvd_commlsm.h"


int init_system_call_hook(void);
int uinit_system_call_hook(void);

static int vsec_hook_ctrl(int enable)
{
    int rc = 0;
    //明确使用lsm hook后，不再使用syscall-hook
    if(enable) {
        if(_hook_lsm_on == 0) {
            //do real hook system-calls
            rc = kvd_hook_syscalls();
        } else {
           rc = kvd_enable_commlsm_hook();
        }
    } else {
        if(_hook_lsm_on == 0) {
            kvd_cleanup_syscalls();
        } else {
            kvd_disable_commlsm_hook();
        }
    }

    return rc;
}

static int client_exit_notify_fn(struct notifier_block* nb,
                            unsigned long val, void* data)
{
    pid_t pid = -1;
    struct task_struct* task = data;

    vsec_hook_ctrl(0);

    if(task) { pid = PID(task); }
    LOG_INFO("hook receive client[%d] exit notify\n",pid);
    return 0;
}

static struct notifier_block hook_notifier = {
    .notifier_call = client_exit_notify_fn,
};

static int hook_echo_notifier_fn(struct notifier_block* nb,
                        unsigned long ecn,void* data)
{
    if((ecn != ECN_SET_PID) && (ecn != ECN_CLEAR_PID)) { 
        return NOTIFY_DONE; 
    }

    vsec_hook_ctrl(ecn == ECN_SET_PID);

    return NOTIFY_DONE;
}

static struct notifier_block hook_echo_notifier = {
    .notifier_call = hook_echo_notifier_fn
};


extern const char* __hook_mode;

int vsec_hook_init(void)
{
    int rc = 0;
    int lsm_forced = 0;
    LOG_INFO("vd hook init ............\n");
    
    //不用关心该调用的返回值
    register_client_exit_notify(&hook_notifier);
    register_echo_notifier(&hook_echo_notifier);

    /*_hook_lsm_on是外围传入的内核模块参数
     *1._hook_lsm_on被设置表示调用者希望直接使用lsm-hook方式
     *2.当_hook_lsm_on未被设置，则内核模块根据内核参数来决定是否需要强制使用lsm-hook方式,
     *  当强制使用lsm-hook方式时我们同时将_hook_lsm_on置位，以便于其他功能模块判断当前的hook方式
     */
    if (!_hook_lsm_on) {

#if CLOSE_LSM_FORCED == 0
        lsm_forced = kvd_enable_commlsm_forced();
#endif
        _hook_lsm_on = lsm_forced;
    }

    if (_hook_lsm_on) {
        __hook_mode = kvd_commlsm_hook_mode();
    } else {
        //写保护操作不安全的情况下syscall-hook不起作用,
        //修改hook_mode告知用户态采用fanotify
        //(不是syscall和ftrace都使用fanotify)
        if (kvd_wp_disabled() && strcmp(__hook_mode, "syscall-hook") == 0) {
            __hook_mode = "fakesyscall";
        }
    }

    /* _hook_lsm_on要在此函数之前确定,
     * 函数内(com_notify_init)依据此值是否启用mount的lsm hook */
    rc = init_file_access();
    if(rc < 0) {
        unregister_client_exit_notify(&hook_notifier);
    }

    return rc;
}

void vsec_hook_exit(void)
{
    uninit_file_access();
    unregister_echo_notifier(&hook_echo_notifier);
    unregister_client_exit_notify(&hook_notifier);
}
