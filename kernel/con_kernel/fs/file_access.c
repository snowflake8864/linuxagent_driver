#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/vfs.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "utils/utils.h"
#include "core/kvd_memcache.h"
#include "core/kvd_core.h"
#include "utils/fs_magic.h"
#include "fs_inner.h"
#include "syscall_def.h"
//#include "fsmount/fs_mount.h"

/********************************************************************************
 *Note!!!!:
 *此处我们通过强改Linux系统调用表的方式来HOOK　syscalls,这种操作十分危险
 *因为在执行我们自己的syscall时，我们自己的模块的引用计数并不会被操作系统内核增加
 *所以会出现：
 *即使我们自己的syscall在调用时，也能将我们自己的模块卸载掉
 *一旦出现上述情况，极可能导致内核崩溃问题
 *所以我们在修改系统调用表之前会先将THIS_MODULE的引用计数增加，防止模块被卸载
 *并且在每次执行我们自己的syscall时，都先获取模块引用计数，调用完成后再释放
 *应用层进程退出之前会向我们发送UNINIT指令，此处我们会复原系统调用表，
 *然后释放THIS_MODULE的引用计数,进而才能进行模块卸载操作
 */
////////////////////////////////////////////////////////////////////////////////
//syscall ioctl

KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_ioctl,SYS_IOCTL_INDEX,
    unsigned int, fd,unsigned int, cmd, unsigned long, arg);

////////////////////////////////////////////////////////////////////////////////
//sys_kill与sys_ptrace本来不是文件，但为了方便也放在这里吧，不再新建文件了
//sys_kill

KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_kill,SYS_KILL_INDEX,
        pid_t, pid, int, sig);

KVD_FTRACE_HOOK_SYSCALL_DEFINE4(sys_ptrace, SYS_PTRACE_INDEX,
    long, request, long, pid, unsigned long, addr, unsigned long, data);

////////////////////////////////////////////////////////////////////////////////////////////////////

//ioctl operation
static int do_hook_ioctl_syscalls(void)
{
    int rc = 0;

    rc = KVD_REGISTER_SC_FTRACE_HOOK(ioctl,SYS_IOCTL_INDEX);

    return rc;
}

//kill and ptrace operations
static int do_hook_kill_ptrace_syscalls(void)
{
    int rc = 0;
    rc = KVD_REGISTER_SC_FTRACE_HOOK(kill,SYS_KILL_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(ptrace,SYS_PTRACE_INDEX);
out:
    return rc;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////

extern int do_hook_open_syscalls(void);
extern int do_hook_close_syscalls(void);
extern int do_hook_truncate_syscalls(void);
extern int do_hook_chmod_syscalls(void);
extern int do_hook_chown_syscalls(void);

extern int do_hook_link_syscalls(void);
extern int do_hook_unlink_syscalls(void);
extern int do_hook_rename_syscalls(void);
extern int do_hook_dir_syscalls(void);

extern int do_hook_mount_syscalls(void);
extern int do_hook_utimes_syscalls(void);
extern void do_hook_sock_syscalls(void);

extern int do_hook_mmap_syscalls(void);
extern int do_hook_getents_syscalls(void);
extern int do_hook_delete_module_syscalls(void);

void pipe_hook_init(void);
void pipe_hook_uninit(void);
static int do_hook_file_syscalls(void)
{
    int rc = 0;
    //不再care返回值了，因为有些情况下是注定会失败的
    //比如arm64平台上hook sys_open一定会失败
	do_hook_ioctl_syscalls();
    do_hook_unlink_syscalls();

    do_hook_dir_syscalls();
    do_hook_truncate_syscalls();
    do_hook_rename_syscalls();
    do_hook_chmod_syscalls();

    do_hook_chown_syscalls();
    do_hook_open_syscalls();
    do_hook_close_syscalls();
    do_hook_link_syscalls();

    do_hook_mount_syscalls();
    do_hook_kill_ptrace_syscalls();
    do_hook_sock_syscalls();
    do_hook_utimes_syscalls();

    do_hook_mmap_syscalls();
    do_hook_getents_syscalls();
    do_hook_delete_module_syscalls();

    pipe_hook_init();
    return rc;
}


int init_file_access(void)
{
    do_hook_file_syscalls();
    /* vsec_fs_mount_init放在此处是由于:
     * 1. 用到了_hook_lsm_on, 需在其值确定之后;
     * 2. com_notify_init需待vsec_fs_mount_init初始化后向其注册;
     * */
    return 0;
}

void uninit_file_access(void)
{
    pipe_hook_uninit();
}
