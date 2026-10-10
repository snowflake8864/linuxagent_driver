/*
 *defense_task.c: 2020-05-25 created by qudreams
 *defense task to be killed
 */


#include <linux/module.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/slab.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h> //fo get_task_struct,put_task_struct
#endif
#include "core/gnkernel.h"
#include "core/kvd_core.h"
#include "utils/hash_table.h"
#include "defense_inner.h"


static vsec_htable_t _pid_ht;

static uint32_t ht_hash_fn(void* key,size_t len)
{
    uint32_t hval = 0;
    long pid = (long)key;

    hval = kvd_murmur_hash2((u_char*)&pid,sizeof(pid));
    return hval;
}

static int ht_cmp_fn(void* key1,size_t len1,
                    void* key2,size_t len2)
{
    return ((long)key1 - (long)key2);
}

static void ht_free_fn(vsec_htable_t* ht,
                    void* key,size_t key_len,
                    void* data)
{
}

static int init_pid_ht(void)
{
    return vsec_htable_init(&_pid_ht,
                "defense_pids",
                NULL,8,
                ht_cmp_fn,
                ht_hash_fn,
                ht_free_fn);
}

static void uninit_pid_ht(void)
{
    vsec_htable_cleanup(&_pid_ht);
    vsec_htable_uninit(&_pid_ht);
}

static int upgrade_hold_task(struct task_struct* task)
{
    long pid = PID(task);
    return vsec_htable_upgrade(&_pid_ht,(void*)pid,
						    sizeof(pid),(void*)pid);
}

static int del_hold_task(struct task_struct* task)
{
    long pid = PID(task);
    return vsec_htable_del(&_pid_ht,
                (void*)pid,sizeof(pid));
}

void cleanup_hold_procs(void)
{
    unhold_all_procs();
    vsec_htable_cleanup(&_pid_ht);
}


struct pid_cb_ctx {
    ssize_t len;
    size_t buflen;
    char* buf;
};

static void walk_pids_cb(void* key,size_t key_len,
                    void* data,void* ctx)
{
    ssize_t n = 0;
    struct pid_cb_ctx* pid_ctx = ctx;

    n = pid_ctx->buflen - pid_ctx->len;
    n = kvd_snprintf(pid_ctx->buf + pid_ctx->len,
                    n,"%ld,",(long)key);
    pid_ctx->len += n;
}

ssize_t get_all_hold_procs(char* buf,size_t len)
{
    struct pid_cb_ctx ctx;

    ctx.len = 0;
    ctx.buf = buf;
    ctx.buflen = len;

    vsec_htable_walk(&_pid_ht,&ctx,walk_pids_cb);

    return ctx.len;
}


//SIGNAL_UNKILLABLE is added from 2.6.26
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
static int do_hold_one_proc(struct task_struct* task)
{
	int rc = -ESRCH;
    unsigned int* pflags = NULL;
    struct signal_struct* sig = NULL;
    struct sighand_struct *sighand = NULL;

    sig = task->signal;
    if(!sig) { goto out; }

    sighand = task->sighand;
    spin_lock_irq(&sighand->siglock);
    pflags = &(sig->flags);
    if(pflags) {
    	*pflags |= SIGNAL_UNKILLABLE;
    	rc = 0;
    }
    spin_unlock_irq(&sighand->siglock);

out:
	return rc;
}

//bhold-->表是是否执行进程保护操作,如果不执行，
//则仅仅将相应进程加到受保护列表中,后续自保开关来时再进行保护
//这个是因为用户态在启动时不关是否开启自保都会先将要保护的pid通过策略下来
int hold_one_proc(struct task_struct* task,bool bhold)
{
    int rc = 0;

    if(bhold) { rc = do_hold_one_proc(task); }
    if(rc == 0) { upgrade_hold_task(task); }

    return rc;
}

static int do_unhold_one_proc(struct task_struct* task)
{
	int rc = -ESRCH;
	unsigned int* pflags = NULL;
	struct signal_struct* sig = NULL;
	struct sighand_struct *sighand = NULL;

	sig = task->signal;
	if(!sig) { goto out; }

	sighand = task->sighand;
	spin_lock_irq(&sighand->siglock);
	pflags = &(sig->flags);
	if(pflags) {
		*pflags &= ~SIGNAL_UNKILLABLE;
		rc = 0;
	}
	spin_unlock_irq(&sighand->siglock);

out:
	return rc;
}

int unhold_one_proc(struct task_struct* task)
{
	int rc = -ESRCH;
    rc = del_hold_task(task);
    if(rc == 0) {
	    rc = do_unhold_one_proc(task);
    }

	return rc;
}

int init_defense_task(void)
{
    return init_pid_ht();
}

void uninit_defense_task(void)
{
    uninit_pid_ht();
}

static void unhold_pids_cb(void* key,size_t key_len,
                    void* data,void* ctx)
{
    int* pcount = ctx;
    long pid = (long)key;

    struct task_struct* task;
    rcu_read_lock();
    task = kvd_get_task_struct_locked(pid);
    if(task) { 
        int rc = do_unhold_one_proc(task); 
        if(rc == 0) { *pcount += 1; }
    }
    rcu_read_unlock();
}

static void hold_pids_cb(void* key,size_t key_len,
                    void* data,void* ctx)
{
    int* pcount = ctx;
    long pid = (long)key;

    struct task_struct* task;
    rcu_read_lock();
    task = kvd_get_task_struct_locked(pid);
    if(task) {
        int rc = do_hold_one_proc(task); 
        if(rc == 0) { *pcount += 1; }
    }
    rcu_read_unlock();
}

void unhold_all_procs(void)
{
    int count = 0;
    vsec_htable_walk(&_pid_ht,&count,
                    unhold_pids_cb);
    DEFENSE_LOG_INFO("defense unhold %d procs\n",count);
}

void hold_all_procs(void)
{
    int count = 0;
    vsec_htable_walk(&_pid_ht,&count,
                    hold_pids_cb);
    DEFENSE_LOG_INFO("defense hold %d procs\n",count);
}

#else
/*Note:
 * security_ops在2.6.24以前的版本是在security.h有声明;
 * 但在2.6.24及2.6.25开始security_ops指针虽然类型没有变化，但不在security.h中声明了
 * 所以在此处要进行前置声明
 *
 * 从2.6.26版本开始security_ops不再是指针，而是在security.c中类似如下形式的定义:
 * static struct security_operations security_ops;
 * 所以从2.6.26版本的内核开始不能再使用下面的形式实现进程自保
 */
extern struct security_operations *security_ops;
typedef int (*task_kill_handler_t)(struct task_struct*,struct siginfo*,int,u32);
task_kill_handler_t org_handler = NULL;

static int is_need_signal(int sig)
{
	int bcare = 0;

    bcare = (sig == SIGINT ||
             sig == SIGTERM ||
             sig == SIGQUIT ||
             sig == SIGABRT);
    return bcare;
}

//send by sigqueue
#define SI_FROMQUEUE(siptr) ((siptr)->si_code == SI_QUEUE)

static int need_intercept(pid_t pid,int sig,struct siginfo* info)
{
    pid_t spid = 0; //the pid of sender
    int intercept = 0;

    //target pid is not valid
    if(pid <= 0) { goto out; }
    //the sig may be 0,it suppose that
    //just check process,don't kill process really
    if(sig <= 0) { goto out; }

    //is special signal info?
    if(is_si_special(info)) {
        goto out;
    }

    //is the signal from kernel?
    if(SI_FROMKERNEL(info)) {
        goto out;
    }

    //is self-hold enabled?
    if(!is_defense_enable()) {
        goto out;
    }

    //is the target us?
    if(!is_self_process2(pid)) {
        goto out;
    }

    //is the signal from myself
    spid = info->si_pid;
    if(is_self_process2(spid)) {
        goto out;
    }

    //we just recive signal sent by sigqueue
    intercept = !SI_FROMQUEUE(info);
    if(intercept) { goto out; }

    //我们需要的信号不阻断
    intercept = !is_need_signal(sig);
    if(intercept) { goto out; }

out:
	return intercept;
}

static int hold_task_kill(struct task_struct* p,struct siginfo* info,int sig,u32 secid)
{
    int rc = 0;
    int gotmod = 0;
    int intercept = 0;
    pid_t pid = PID(p); //the pid of target

    gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = -EPERM;
    intercept = need_intercept(pid,sig,info);
    if(!intercept) { goto out; }

    LOG_DEBUG("hold task kill:pid:%d,signal: %d\n",pid,sig);

out:
    if(!intercept) { rc = org_handler(p,info,sig,secid); }
    kvd_self_module_put();

    return rc;
}

static void disable_kernel_preempt(void)
{
    preempt_disable();
    barrier();
}

static void enable_kernel_preempt(void)
{
    barrier();
    preempt_enable();
}

int init_defense_task(void)
{
    int rc = -EFAULT;
    task_kill_handler_t old_handler = NULL;

    rc = init_pid_ht();
    if(rc) { return rc; }

    /*此处一定要小心:
    *内核其他模块有可能会修改security_ops的指针
    *此处禁止内核抢占操作
    */
    disable_kernel_preempt();

    if(!security_ops) { goto out; }
    (void)xchg(&old_handler,security_ops->task_kill);
    if(!old_handler) { goto out; }

    //save original task_kill handler
    org_handler = cmpxchg(&security_ops->task_kill,
                        old_handler,hold_task_kill);
    if(org_handler != old_handler) { goto out; }
    rc = 0;
    
out:
    enable_kernel_preempt();
    if(rc) { uninit_pid_ht(); }

    return rc;
}

//bhold-->表是是否执行进程保护操作,如果不执行，
//则仅仅将相应进程加到受保护列表中,后续自保开关来时再进行保护
//这个是因为用户态在启动时不关是否开启自保都会先将要保护的pid通过策略下来
//此处实际就是只加pid,所以此种情况不需要判断bhold值
int hold_one_proc(struct task_struct* task,bool bhold)
{
    return upgrade_hold_task(task);
}

int unhold_one_proc(struct task_struct* task)
{
    return del_hold_task(task);
}

void uninit_defense_task(void)
{
    /*此处一定要小心:
    *内核其他模块有可能会修改security_ops的指针
    *此处禁止内核抢占操作
    */
    disable_kernel_preempt();
    //restore it
    (void)cmpxchg(&security_ops->task_kill,
                hold_task_kill,org_handler);
    enable_kernel_preempt();
    uninit_pid_ht();
}

void unhold_all_procs(void)
{
    size_t count = vsec_htable_size(&_pid_ht);
    DEFENSE_LOG_INFO("unhold %lu procs\n",count);
}

void hold_all_procs(void)
{
    size_t count = vsec_htable_size(&_pid_ht);
    DEFENSE_LOG_INFO("defense hold %lu procs\n",count);
}

#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
    #define PROFILE_EVENT_REMOVED_NOTIFY 1
#else
    #ifdef RHEL_RELEASE_CODE
        #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,2)
            #define PROFILE_EVENT_REMOVED_NOTIFY 1
        #endif
    #endif
#endif

#if !defined(CONFIG_PROFILING) || defined(PROFILE_EVENT_REMOVED_NOTIFY)
static int is_task_runnability(struct task_struct* tsk)
{
	unsigned int state = tsk->exit_state &
						(EXIT_ZOMBIE | EXIT_DEAD);

	return (!state);
}

static int clean_pid_filter(void* key,size_t key_len,
                        void* data,void* ctx)
{
    int tsk_ok = 0;
    long pid = (long)key;
	struct task_struct* tsk = NULL;

    rcu_read_lock();
    tsk = kvd_get_task_struct_locked(pid);
    if(tsk) { 
        tsk_ok = is_task_runnability(tsk);
    }
    rcu_read_unlock();

    return !tsk_ok;
}

void cleanup_exited_tasks(void)
{
    int count = vsec_htable_clean_items(&_pid_ht,NULL,
                            clean_pid_filter);
    if(count > 0) {
        DEFENSE_LOG_INFO("cleanup defense task: %d\n",count);
    }
}
#endif



