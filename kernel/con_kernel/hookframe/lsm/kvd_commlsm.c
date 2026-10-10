#include <linux/version.h>
#include <linux/kallsyms.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h> //fo SEND_SIG_FORCED
#endif
#include "gnHead.h"
#include "core/kvd_core.h"
#include "core/gnkernel.h"
#include "hook/hook.h"
#include "khookframe.h"
#include "kvd_commlsm.h"

extern const char * __hook_mode;
static struct list_head new_hooks;
static DEFINE_RWLOCK(new_hooks_lock);
static unsigned long commlsm_inited = 0;
static u_long lsm_type_use = 0;

#if !defined(SEND_SIG_FORCED)
    #define SEND_SIG_FORCED 2
#endif

#if defined(RHEL_RELEASE_CODE) && defined(RHEL_RELEASE_VERSION)
    //Neokylin 4.18的内核上发现使用了redhat8.0的内核,
    //引入了4.19以后版本内核的修改
    #if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,0))
        #define KVD_COMMLSM_FILE_OPEN
        #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 2)
            #define KVD_COMMLSM_TASK_KILL
        #endif
    #endif
#endif

#define call_hook_begin(FUNC) \
    do { \
        unsigned long __flags; \
        struct kvd_security_operations *hooks, *nops; \
        \
        if ((current->flags & PF_EXITING) && \
                strcmp(#FUNC, "task_free") != 0) { \
            break; \
        } \
        if (!test_bit(LSM_STATE_ENABLED, &commlsm_inited)) { \
            break; \
        } \
        if (!kvd_try_self_module_get()) { \
            break; \
        } \
        read_lock_irqsave(&new_hooks_lock, __flags); \
        list_for_each_entry_safe(hooks, nops, &new_hooks, list) { \
            if (!hooks->FUNC) { \
                continue; \
            } \
            read_unlock_irqrestore(&new_hooks_lock, __flags);

#define call_int_hook_end(RC) \
            read_lock_irqsave(&new_hooks_lock, __flags); \
            if (RC != 0) { \
                break; \
            } \
        } \
        read_unlock_irqrestore(&new_hooks_lock, __flags); \
        kvd_self_module_put(); \
    } while (0)

#define call_void_hook_end() \
            read_lock_irqsave(&new_hooks_lock, __flags); \
        } \
        read_unlock_irqrestore(&new_hooks_lock, __flags); \
        kvd_self_module_put(); \
    } while (0)

static int comm_lsm_register_do(struct kvd_security_operations *hooks)
{
    int found = 0;
    unsigned long flags;
    struct kvd_security_operations *pos;

    write_lock_irqsave(&new_hooks_lock, flags);
    list_for_each_entry(pos, &new_hooks, list) {
        if (pos == hooks) {
            found = 1;
            break;
        }
    }
    if (!found) {
        list_add_tail(&hooks->list, &new_hooks);
    }
    write_unlock_irqrestore(&new_hooks_lock, flags);

    return (found ? -EEXIST : 0);
}

static int comm_lsm_unregister_do(struct kvd_security_operations *hooks)
{
    int found = 0;
    unsigned long flags;
    struct kvd_security_operations *pos;

    write_lock_irqsave(&new_hooks_lock, flags);
    list_for_each_entry(pos, &new_hooks, list) {
        if (pos == hooks) {
            list_del(&hooks->list);
            found = 1;
            break;
        }
    }
    write_unlock_irqrestore(&new_hooks_lock, flags);

    return (found ? 0 : -ENOENT);
}

/*
 *lsm-hook有优先顺序:
 *a)先判断是否开启kylin-lsm,uos-lsm
 *b)再判断CONFIG_SECURITY_WRITABLE_HOOKS宏是否开启(即允许我们修改lsm的链表,针对的是华为arm64 海思平台)
 *c)4.2及以上内核优先判断是否启用内核卫士(kws-lsm),否则才考虑采用关闭写保护后修改内核lsm链表
 *b)4.2以下版本的内核lsm不是链表
 */
#if defined CONFIG_SECURITY_HOOKMANAGER
    #include "kvd_commlsm_list.c"
#elif defined KOSEC_LSM_HOOK_ENABLED
    #if defined CONFIG_SECURITY_KYLIN_EXTEND
        #include "kvd_commlsm_kylin.c"
    #else
        // CONFIG_SECURITY_WRITABLE_HOOKS
        // CONFIG_HUAWEI_ARMPC_PLATFORM
        #include "kvd_commlsm_list.c"
    #endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    #include "kvd_commlsm_list.c"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    #include "kvd_commlsm_ops.c"
#else
    #include "kvd_commlsm_empty.c"
#endif

int kvd_init_commlsm_hook(void)
{
    int rc;

    if (test_and_set_bit(LSM_STATE_INITED, &commlsm_inited)) {
        return -EAGAIN;
    }

    INIT_LIST_HEAD(&new_hooks);
    rc = comm_lsm_init_hook();
    if (rc != 0) {
        clear_bit(LSM_STATE_INITED, &commlsm_inited);
    }
    LOG_INFO("osec lsm fun init: %d\n", rc);

    return rc;
}

void kvd_uninit_commlsm_hook(void)
{
    if (!test_bit(LSM_STATE_INITED, &commlsm_inited)) {
        return;
    }

    comm_lsm_uninit_hook();
    clear_bit(LSM_STATE_INITED, &commlsm_inited);
    LOG_INFO("osec lsm uninit\n");
}

int kvd_enable_commlsm_hook(void)
{
    int rc;
    int gotmod;

    rc = -EFAULT;
    if (!test_bit(LSM_STATE_INITED, &commlsm_inited)) {
        return rc;
    }
    //进入hook LSM-OPS的逻辑，获取模块引用计数
    //防止执行hook期间模块进入卸载逻辑
    gotmod = kvd_try_self_module_get();
    if (!gotmod) {
        return rc;
    }

    rc = comm_lsm_enable();
    if (rc != 0) {
        kvd_self_module_put();
    } else {
        //标记启用LSM,未启用时不调用注册的功能函数
        set_bit(LSM_STATE_ENABLED, &commlsm_inited);
    }
    LOG_INFO("========================kvd_enable_commlsm_hook\n");
    return rc;
}

void kvd_disable_commlsm_hook(void)
{
    int rc;

    if (!test_bit(LSM_STATE_INITED, &commlsm_inited)) {
        return;
    }
    clear_bit(LSM_STATE_ENABLED, &commlsm_inited);
    //先释放hook再减少引用计数
    rc = comm_lsm_disable();
    if (rc == 0) {
        kvd_self_module_put();
    }
}

int kvd_commlsm_is_enabled(void)
{
    return comm_lsm_is_enabled();
}

char* kvd_commlsm_hook_mode(void)
{
    return comm_lsm_hook_mode();
}

int kvd_register_commlsm_hook(struct kvd_security_operations *hooks)
{
    int rc = -EFAULT;

    if (test_bit(LSM_STATE_INITED, &commlsm_inited)) {
        rc = comm_lsm_register_hook(hooks);
    }
    LOG_INFO("commlsm register: %s, %d\n", hooks->name, rc);

    return rc;
}

void kvd_unregister_commlsm_hook(struct kvd_security_operations *hooks)
{
    int rc = -EFAULT;

    if (test_bit(LSM_STATE_INITED, &commlsm_inited)) {
        if (test_bit(LSM_STATE_ENABLED, &commlsm_inited)) {
            //LSM未关闭时不允许移除以防崩溃
            rc = -EAGAIN;
        } else {
            rc = comm_lsm_unregister_hook(hooks);
        }
    }
    LOG_INFO("commlsm unregister: %s, %d\n", hooks->name, rc);
}

/* 以下情况hook默认使用LSM, 不使用syscall
 *  1. 内核卫士存在时:
 *      test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)
 *  2. kylin lsm开启后(非华为pc平台):
 *      CONFIG_SECURITY_KYLIN_EXTEND && !CONFIG_HUAWEI_ARMPC_PLATFORM
 *  3. 华为pc平台, 以下情况支持lsm, 其他均不支持;
 *      CONFIG_HUAWEI_ARMPC_PLATFORM
 *          a. 有定义SECURITY_WRITEABLE_HOOKS
 *              此时可开启写保护操作LSM(否则lsm导致崩溃);
 *          b. kylin lsm开启: CONFIG_SECURITY_KYLIN_EXTEND;
 *  4. uos lsm开启后:
 *      CONFIG_SECURITY_HOOKMANAGER
 */
int kvd_enable_commlsm_forced(void)
{
    int lsm_forced = 0;

#if defined(CONFIG_SECURITY_KYLIN_EXTEND) && \
        !defined(CONFIG_HUAWEI_ARMPC_PLATFORM)
    lsm_forced = 1;
#endif

#if defined(CONFIG_HUAWEI_ARMPC_PLATFORM)
    #if defined(CONFIG_SECURITY_KYLIN_EXTEND) || \
            defined(SECURITY_WRITEABLE_HOOKS)
        lsm_forced = 1;
    #else
        if (!test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)) {
            LOG_INFO("commlsm: this is a HUAWEI arm-pc, "
                    "but no SECURITY_WRITEABLE_HOOKS; "
                    "we can't support it\n");
        }
    #endif
#endif

#if defined(CONFIG_SECURITY_HOOKMANAGER)
    lsm_forced = 1;
#endif

    return (test_bit(COMMLSM_TYPE_KWS, &lsm_type_use) || lsm_forced);
}
