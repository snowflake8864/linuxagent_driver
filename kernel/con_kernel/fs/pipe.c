/*
 *pipe.c: 2021-12-27 created by qudreams
 *处理在hook syscall模式下因管道文件打开时
 * hook sys_open/openat无法返回引起内核模块无法正常卸载的问题
 */
#include <linux/types.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h> //for force_sig
#endif
#include "core/kvd_core.h"
#include "khookframe.h"
#include "syscall_def.h"
#include "clientexit/client_exit.h"
#include "utils/hash_table.h"
#include "config.h"

static int _pipe_inited = 0;
//这个htable中存放的是以current
static vsec_htable_t _pipe_tasks; 

static bool is_pipe(int dfd,
                    const char __user* pathname,
                    int flags)
{
    int rc = 0;
    struct path path;
    struct kstat stat;
    bool bpipe = false;
    unsigned lookup_flags = LOOKUP_FOLLOW;

    if(flags & O_NOFOLLOW) {
        lookup_flags &= ~LOOKUP_FOLLOW;
    }

    rc = kvd_user_path_at(dfd,pathname,lookup_flags,&path);
	if (rc) { return bpipe; }

	rc = kvd_vfs_getattr(&path,&stat);
    if(rc) { goto out; }

    bpipe = S_ISFIFO(stat.mode);

out:
    kvd_path_put(&path);

    return bpipe;
}

static void upgrade_pipe_tasks(kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    long tid = current->pid;
    rc = vsec_htable_upgrade(&_pipe_tasks,(void*)tid,
                            sizeof(tid),(void*)tid);
    if(rc == 0) {
        ctx->data = (void*)(tid); 
    }
}

static void del_pipe_task(kvd_hook_ctx_t* ctx)
{
    if(ctx->data) {
        long tid = (long)(ctx->data);
        vsec_htable_del(&_pipe_tasks,
                (void*)tid,sizeof(tid));
        ctx->data = NULL;
    }
}

static void do_pipe_hook_pre_openat(int dfd,
                    const char __user* pathname,
                    int flags,kvd_hook_ctx_t* ctx)
{
    mode_t pipe_mode = 0;
    //这里就是要保存线程tid,不是进程pid
    mode_t fmode = ((flags+1) & O_ACCMODE) | FMODE_LSEEK |
				            FMODE_PREAD | FMODE_PWRITE;
    pipe_mode = fmode & (FMODE_READ | FMODE_WRITE);

    //管道只支持下面三种权方式的打开，否则直接会返回出错
    if((pipe_mode != O_RDONLY) && 
        (pipe_mode != O_WRONLY) && 
        (pipe_mode != O_RDWR)) 
    {
        return;
    }

    if(is_pipe(dfd,pathname,flags)) {
       upgrade_pipe_tasks(ctx);
    }
}

static void do_pipe_hook_post_open(kvd_hook_ctx_t* ctx)
{
    del_pipe_task(ctx);
}

static void pipe_hook_pre_open(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int dfd = AT_FDCWD;

    KVD_REG_CAST_TO_ARGS(3,regs,
        const char __user*,pathname,
        int,flags,mode_t,mode);
    
    ctx->data = NULL;
    do_pipe_hook_pre_openat(dfd,pathname,flags,ctx);
}

static void pipe_hook_pre_openat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    KVD_REG_CAST_TO_ARGS(4,regs,
        int,dfd,
        const char __user*,pathname,
        int,flags,mode_t,mode);

    ctx->data = NULL;
    do_pipe_hook_pre_openat(dfd,pathname,flags,ctx);
}

static void pipe_hook_post_open(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    do_pipe_hook_post_open(ctx);
}

static void pipe_hook_post_openat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    do_pipe_hook_post_open(ctx);
}

//非阻塞模式下的sys_accept才需要考虑
static void do_pipe_hook_pre_accept(int fd,kvd_hook_ctx_t* ctx)
{
    int err;
    struct socket* sock = NULL;

    sock = sockfd_lookup(fd,&err);
	if (sock) {
        if(!(sock->file->f_flags & O_NONBLOCK)) {
            upgrade_pipe_tasks(ctx);
        }
        sockfd_put(sock);
    }
}

static void do_pipe_hook_post_accept(kvd_hook_ctx_t* ctx)
{
    del_pipe_task(ctx);
}

static void pipe_hook_pre_accept(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    KVD_REG_CAST_TO_ARGS(3,regs,int, fd, 
        struct sockaddr __user*, uservaddr, 
        int __user *,addrlen);
    do_pipe_hook_pre_accept(fd,ctx);
}

static void pipe_hook_post_accept(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    do_pipe_hook_post_accept(ctx);
}

static void pipe_hook_pre_accept4(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    KVD_REG_CAST_TO_ARGS(4,regs,int, fd, 
        struct sockaddr __user*, uservaddr, 
        int __user *,addrlen,int, flags);

    do_pipe_hook_pre_accept(fd,ctx);
}

static void pipe_hook_post_accept4(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    do_pipe_hook_post_accept(ctx);
}

/*
 *Note:
 *在deepin 15.11上发现：
 *deepin-anything-monitor这个破软件在底层的内核模块中(vfs_monitor)会在sys_ioctl
 *系统调用中同步等待，导致sys_ioctl系统调用无法返回引起内核模块无法卸载
 */
static void pipe_hook_pre_ioctl(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    KVD_REG_CAST_TO_ARGS(3, regs, u_int, fd, u_int, cmd, u_long, arg);
    if (fd >= 0) {
        upgrade_pipe_tasks(ctx);
    }
}

static void pipe_hook_post_ioctl(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    del_pipe_task(ctx);
}

static void do_pipe_hook_pre_connect(int fd,kvd_hook_ctx_t* ctx)
{
    int err;
    struct socket* sock = NULL;

    sock = sockfd_lookup(fd,&err);
    if(sock) {
        if(!(sock->file->f_flags & O_NONBLOCK)) {
            upgrade_pipe_tasks(ctx);
        }
        sockfd_put(sock);
    }

}

//sys_connect阻塞模式下有可能很长时间不返回，并且在unix套接字模式下也有可能长时间不返回
static void pipe_hook_pre_connect(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{   
    KVD_REG_CAST_TO_ARGS(3, regs,
        int, fd, struct sockaddr __user*,uservaddr,
        int, addrlen);
    do_pipe_hook_pre_connect(fd,ctx);
 
}

static void pipe_hook_post_connect(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    del_pipe_task(ctx);
}


#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[21] = {
    AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
    AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
    AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
    AL(4), AL(5), AL(4)
 };
static void pipe_hook_pre_socketcall(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    unsigned long a[6];
    unsigned long a0;
    unsigned int len;

    KVD_REG_CAST_TO_ARGS(2,regs,
        int,call,unsigned long __user *,args); 

    if (call < 1 || call > SYS_SOCKET_MAX) {
        return ;
    }

    len = nargs[call];
    if (len > sizeof(a)) {return ;}
    if (copy_from_user(a,args,len)) {
        return ;
    }

    a0 = a[0];

    switch (call) {
    case SYS_ACCEPT:
            do_pipe_hook_pre_accept(a0,ctx);
            break;
    case SYS_CONNECT:
            do_pipe_hook_pre_connect(a0,ctx);
            break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
    case SYS_ACCEPT4:
            do_pipe_hook_pre_accept(a0,ctx);
            break;
#endif 
    default:
            break;
    }
}

static void pipe_hook_post_socketcall(kvd_regs_t* regs,kvd_hook_ctx_t* ctx) 
{
    del_pipe_task(ctx);
}

static struct kvd_hook_ops pipe_hook_ops[] = {
        KVD_INIT_HOOK_OPS(pipe_hook_pre_open,
                pipe_hook_post_open,
                SYS_OPEN_INDEX,KVD_OPS_PRI_LAST),
        KVD_INIT_HOOK_OPS(pipe_hook_pre_openat,
                pipe_hook_post_openat,
                SYS_OPENAT_INDEX,KVD_OPS_PRI_LAST),
        KVD_INIT_HOOK_OPS(pipe_hook_pre_ioctl, 
                pipe_hook_post_ioctl,
                SYS_IOCTL_INDEX,KVD_OPS_PRI_LAST),
        KVD_INIT_HOOK_OPS(pipe_hook_pre_socketcall,
                pipe_hook_post_socketcall,
                SYS_SOCKETCALL_INDEX,KVD_OPS_PRI_LAST),
        KVD_INIT_HOOK_OPS(pipe_hook_pre_accept,
                pipe_hook_post_accept,
                SYS_ACCEPT_INDEX,KVD_OPS_PRI_LAST),
        KVD_INIT_HOOK_OPS(pipe_hook_pre_accept4,
                pipe_hook_post_accept4,
                SYS_ACCEPT4_INDEX,KVD_OPS_PRI_LAST),
        KVD_INIT_HOOK_OPS(pipe_hook_pre_connect, 
                pipe_hook_post_connect,
                SYS_CONNECT_INDEX,KVD_OPS_PRI_LAST),
        };


static bool is_valid_task_state(struct task_struct* task,int signo)
{
    u_long task_state = kvd_task_state(task);
    return ((signo == SIGCONT) || 
            ((signo == SIGSTOP) && 
            (task_state & TASK_INTERRUPTIBLE) && 
            !signal_pending(task)));
}

static bool sig_pipe_task(long pid,int signo)
{
    bool ok = false;
    struct task_struct* task = NULL;
    LOG_INFO("====================\n");
    //SIGCONT特殊处理不要调用force_sig发送
    //因为该信号在低版本的内核上
    //调用force_sig/send_sig时会被内核自动屏蔽掉
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    if(signo == SIGCONT) {
        int err = kill_proc(pid,signo,1);
        ok = ((err == 0) || (err == -ESRCH));
        return ok;
    }
#endif

    smp_mb(); //禁止编译优化
    rcu_read_lock();
    task = kvd_get_task_struct_locked(pid);
    if(task && is_valid_task_state(task,signo))
    {
        ok = (0 == send_sig(signo,task,1));
    }
    rcu_read_unlock();

    return ok;
}

struct pipe_task_ht_ctx {
    u_int size;
    u_int n;
    int* tids;
};

static int realloc_ctx(struct pipe_task_ht_ctx* ht_ctx)
{
    int* tids = NULL;
    u_int size = (ht_ctx->size + 8);

    tids = kzalloc(size * sizeof(int),GFP_ATOMIC);
    if(!tids) { return -ENOMEM; }

    if(ht_ctx->tids && ht_ctx->n) {
        memcpy(tids,ht_ctx->tids,
            sizeof(int) * ht_ctx->n);
        kfree(ht_ctx->tids);
    }

    ht_ctx->tids = tids;
    ht_ctx->size = size;

    return 0;
}

/*
 *唤醒进程:
 *先给对应进程发送SIGSTOP信号再给进程发送SIGCONT信号
 *这样保证进程在收到SIGSTOP信号从系统调用open/openat中返回
 *然后收到SIGCONT后继续运行并重启系统调用(由glibc自动做的，进程无感)
 */
static int wake_pipe_task(void* key,size_t key_len,
                    void* data,void* ctx)
{
    int err = 0;
    bool ok = false;
    long pid = (long)key;
    struct pipe_task_ht_ctx* ht_ctx = ctx;

    if(ht_ctx->size <= ht_ctx->n) {
        //即使内存分配失败我们也继续，
        //尽可能执行进程唤醒操作
        err = realloc_ctx(ht_ctx);
    }
    
    //唤醒进程时先发送SIGSTOP信号
    ok = sig_pipe_task(pid,SIGSTOP);
    if(ok && (err == 0)) {
        ht_ctx->tids[ht_ctx->n++] = pid;
    }

    return 1;
}

static void continue_pipe_tasks(struct pipe_task_ht_ctx* ctx)
{
    u_int i = 0;
    for(;i < ctx->n;i++) {
        //让进程继续运行发送SIGCONT信号
        (void)sig_pipe_task(ctx->tids[i],SIGCONT);
    }
}

/*
 *先发送SIGSTOP唤醒进程
 *再发送SIGCONT让进程继续
 *两者分开：
 *因为在低版本的内核上发完SIGSTOP信号
 *立刻发送SIGCONT时可能会丢失信号
 */
static int pipe_client_exit(struct notifier_block* nb,
                        unsigned long val,void* data)
{
    int err = 0;
    pid_t ts_pid = -1;
    struct pipe_task_ht_ctx ctx;
    struct task_struct* task = data;
    
    //可能为空
    if(task) { ts_pid = PID(task); }

    //将初始大小搞的大一些，以减少分配次数
    memset(&ctx,0,sizeof(ctx));
    ctx.size = vsec_htable_size(&_pipe_tasks);
    err = realloc_ctx(&ctx);
    if(err) { ctx.size = 0; }

    //先要保存下来，因为进程一旦被唤醒在(open/openat)系统调用返回时
    //会将进程pid从_pipe_tasks中移除
    vsec_htable_clean_items(&_pipe_tasks,&ctx,
                            wake_pipe_task);
    
    //发送continue信号
    continue_pipe_tasks(&ctx);
    if(ctx.tids) { kfree(ctx.tids); }

    LOG_INFO("pipe receive client[%d] exit notify,"
        "total waked-tasks: %d\n",ts_pid,ctx.n);
    
    return NOTIFY_DONE;
}

static struct notifier_block pipe_client_notifer = {
    .notifier_call = pipe_client_exit,
};

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
{}

void pipe_hook_init(void)
{
    int rc = 0;

    rc = vsec_htable_init(&_pipe_tasks,
                        "pipe_tasks",NULL,32,
                        ht_cmp_fn,
                        ht_hash_fn,
                        ht_free_fn);
    if(rc) { return; }

    rc = kvd_register_hook_ops(pipe_hook_ops,
                ARRAY_SIZE(pipe_hook_ops));
    if(rc) {
        vsec_htable_cleanup(&_pipe_tasks);
        return; 
    }

    register_client_exit_notify(&pipe_client_notifer);

    (void)xchg(&_pipe_inited,1);
}

void pipe_hook_uninit(void)
{
    if(!xchg(&_pipe_inited,0)) { return; }

    unregister_client_exit_notify(&pipe_client_notifer);
    kvd_unregister_hook_ops(pipe_hook_ops,
                ARRAY_SIZE(pipe_hook_ops));

    vsec_htable_cleanup(&_pipe_tasks);
    vsec_htable_uninit(&_pipe_tasks);
}
