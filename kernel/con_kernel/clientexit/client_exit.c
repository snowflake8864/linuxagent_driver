#include <linux/types.h>
#include <linux/timer.h>
#include <linux/notifier.h>
#include <linux/profile.h>
#include <linux/pid.h>
#include <linux/err.h>
#include <linux/ktime.h>

#include "client_exit.h"
#include "core/gnkernel.h"
#include "gnHead.h"


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
    #define PROFILE_EVENT_REMOVED_NOTIFY 1
#else
    #ifdef RHEL_RELEASE_CODE
        #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,2)
            #define PROFILE_EVENT_REMOVED_NOTIFY 1
        #endif
    #endif
#endif

extern int check_user_client_exit(struct notifier_block *nb, 
                        unsigned long action,
                        void *data);

static int is_task_exit(struct task_struct* tsk)
{
    int ok = 0;

    rcu_read_lock();
    if(tsk) { ok = (tsk == tsk->group_leader); }
    rcu_read_unlock();

    return ok;
}

static void vsec_client_exit_notify(struct task_struct* tsk);

static void do_client_exit(struct task_struct* ts)
{
    u32 portid = get_snd_portid();
    pid_t pid = get_service_pid();

    LOG_INFO("client exit,so clear service pid [%d],"
        " snd_user_portid %d \n",pid,portid);

    clear_portid_service_pid();
    //通知其他功能模块
    vsec_client_exit_notify(ts);
}

//检查应用层客户端进程是否已退出
#if !defined(CONFIG_PROFILING) || defined(PROFILE_EVENT_REMOVED_NOTIFY)
    static int is_task_runnability(struct task_struct* tsk)
    {
        unsigned int state = tsk->exit_state &
                            (EXIT_ZOMBIE | EXIT_DEAD);

        return (!state);
    }

    extern void cleanup_exited_tasks(void);
    int check_user_client_exit(struct notifier_block *nb, 
                        unsigned long action,
                        void *data)
    {
        int tsk_ok = 0;
        struct task_struct* tsk = NULL;

        //pid=0表明是未做初始化操作
        //我们不认为是进程退出
        pid_t pid = get_service_pid();
        if(pid <= 0) { return NOTIFY_DONE; }

        cleanup_exited_tasks();
        
        rcu_read_lock();
        tsk = kvd_get_task_struct_locked(pid);
        if(tsk) { 
            tsk_ok = is_task_runnability(tsk);
        }
        rcu_read_unlock();

        if(!tsk) {
            LOG_INFO("failed to get task for"
                    " user client pid: %d\n",pid);
            goto user_exit; 
        }

        if(tsk_ok) { return NOTIFY_DONE; }

    user_exit:
        LOG_INFO("user client exited,pid: %d\n",pid);
        do_client_exit(NULL);
        return NOTIFY_OK; //suite me
    }
#else
    // 进程退出事件通知
    //extern void defense_unhold_task(struct task_struct* task);

    //Note: 此处一定要返回NOTIFY_DONE,不能影响别人继续感知进程退出通知
    int check_user_client_exit(struct notifier_block *nb, 
                            unsigned long action,
                            void *data) 
    {
		struct task_struct *ts = NULL;
        pid_t pid = get_service_pid();
        u32 portid = get_snd_portid();

        //pid=0表明是未做初始化操作
        //我们不认为是进程退出
        if(pid <= 0) { goto out; }

        ts = (struct task_struct *)data;
        //当线程退出时也会调用该函数,此处要判断是否真的为进程退出
        if(!is_task_exit(ts)) { goto out; }

        //进程退出时从自保进程链表中将对应进程pid删除
        //defense_unhold_task(ts);
        //是否为客户端进程退出
        if(pid != PID(ts)) { goto out; }

        LOG_DEBUG("User service stop, clear service pid [%d],"
            "snd_user_portid %u \n",
            pid, portid);
        do_client_exit(ts);

    out:
        return NOTIFY_DONE;
    }
#endif //end define CONFIG_PROFILING

static ATOMIC_NOTIFIER_HEAD(client_exit_chain);;

#if !defined(CONFIG_PROFILING) || defined(PROFILE_EVENT_REMOVED_NOTIFY)
    static u_int _exit_timer_on = 0;
    static void handle_timer(void);
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
        static void timer_fun(struct timer_list* timer)
        {
            int rc = 0;
            (void)timer;

            handle_timer();
        }

        static DEFINE_TIMER(client_exit_timer,timer_fun);
    #else
        static void timer_fun(unsigned long data)
        {
            (void)data;
            handle_timer();
        }
        static DEFINE_TIMER(client_exit_timer,timer_fun,0,0);
    #endif

    void handle_timer(void)
    {
        int rc = check_user_client_exit(NULL,0,NULL);
        if(!rc && _exit_timer_on) {
            mod_timer(&client_exit_timer,jiffies + HZ);
        }
    }

    static void client_start(void)
    {
        mod_timer(&client_exit_timer,jiffies + HZ);
        (void)xchg(&_exit_timer_on,1);
    }

    static int client_set_pid_notifier_fn(struct notifier_block* nb,
                            unsigned long val,void* data)
    {
        ecn_data_pid_t* ecn_data = data;

        if(val != ECN_SET_PID) { 
            return NOTIFY_DONE; 
        }

        client_start();
        LOG_INFO("client start\n");

        return NOTIFY_DONE;
    }

    static struct notifier_block ecn_set_pid_notifier = {
        .notifier_call = client_set_pid_notifier_fn
    };

    static void do_client_exit_init(void) 
    { 
        register_echo_notifier(&ecn_set_pid_notifier);
    }

    static void do_client_exit_uninit(void) 
    {
        if(xchg(&_exit_timer_on,0)) {
            del_timer_sync(&client_exit_timer);
        }
        unregister_echo_notifier(&ecn_set_pid_notifier);
    }
#else
    static u_int _client_exit_inited = 0;

    static struct notifier_block client_exit_nb = {
        .notifier_call = check_user_client_exit,
    };

    static void do_client_exit_init(void) 
    { 
        int rc = 0;
        //task_exit notify注册失败我们也不care,返回0
        rc = profile_event_register(PROFILE_TASK_EXIT,
                                  &client_exit_nb);
        if(rc) {
            LOG_INFO("kernel profile_event_register failed,"
                "rc: %d,we may not be notified when process exit\n",rc);
            return;   
        }

        _client_exit_inited = 1;
    }

    void do_client_exit_uninit(void) 
    {
        int rc;
        
        if(!_client_exit_inited) { return; }
       	rc = profile_event_unregister(PROFILE_TASK_EXIT,
                                  &client_exit_nb); 
        LOG_DEBUG("kernel profile_event_unregister rc=%d\n", rc);
    }
#endif //end define CONFIG_PROFILING

int register_client_exit_notify(struct notifier_block* notifier)
{
    int rc = -EINVAL;
    
    if(!notifier || !notifier->notifier_call) {
        return rc;
    }

    rc = atomic_notifier_chain_register(&client_exit_chain,notifier);

    return rc;
}

void unregister_client_exit_notify(struct notifier_block* notifier)
{
    atomic_notifier_chain_unregister(&client_exit_chain,notifier);
}

/*Note:
 *tsk可能为NULL,如果有些内核模块没有开启CONFIG_PROFILING宏
 *则我们会使用定时器来检查客户端进程是否退出，此时tsk为NULL
 */
void vsec_client_exit_notify(struct task_struct* tsk)
{
    atomic_notifier_call_chain(&client_exit_chain,0,tsk);
}

void vsec_client_exit_init(void)
{
    do_client_exit_init();
}

void vsec_client_exit_uninit(void)
{
    do_client_exit_uninit();
}
