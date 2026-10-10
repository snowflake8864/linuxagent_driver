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
#include <linux/uaccess.h>
#include "gnHead.h"
#include "core/kvd_core.h"
#include "utils/fs_magic.h"
#include "fs_inner.h"
#include "fs_core.h"
#include "syscall_def.h"



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

/*
 *syscall : openat
 *Note:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *open操作有一个非常麻烦的问题: 针对命名管道(fifo),
 *当进程以O_WRONLY open fifo时，如果没有进程以O_RDONLY打开相应fifo文件
 *会导致open操作一直无法返回会陷入了open操作当中，从而导致我们的引用计数无法正常减到0
 *导致模块无法卸载，这个目前还没有什么好办法
 */

KVD_FTRACE_HOOK_SYSCALL_DEFINE4(sys_openat, SYS_OPENAT_INDEX,
                int, dfd, const char __user *, pathname,
                int, flags, umode_t, mode);

////////////////////////////////////////////////////////////////////////////////
/*
    syscall : open
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_open,SYS_OPEN_INDEX, 
                const char __user *,pathname,
                int, flags, umode_t, mode);


//////////////////////////////////////////////////////////////////////////////////////////////////////

KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_chmod,SYS_CHMOD_INDEX,
        const char __user *, filename, umode_t, mode);

KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_fchmod,SYS_FCHMOD_INDEX,
        unsigned int, fd, umode_t, mode);
KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_fchmodat,SYS_FCHMODAT_INDEX,
        int, dfd, const char __user *, filename, umode_t, mode);

////////////////////////////////////////////////////////////////////////////////
/*
syscall : chown
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_chown, SYS_CHOWN_INDEX,
    const char __user *, filename, uid_t, user, gid_t, group);

////////////////////////////////////////////////////////////////////////////////
/*
syscall : fchown
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_fchown, SYS_FCHOWN_INDEX,
    unsigned int, fd, uid_t, user, gid_t, group);
//fchownat
KVD_FTRACE_HOOK_SYSCALL_DEFINE5(sys_fchownat,SYS_FCHOWNAT_INDEX,
    int, dfd, const char __user *, filename, uid_t, user, gid_t, group, int, flag);
////////////////////////////////////////////////////////////////////////////////
/*
syscall : lchown
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_lchown, SYS_LCHOWN_INDEX,
    const char __user *, filename, uid_t, user, gid_t, group);
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
/*
 *   syscall : close
 */
KVD_FTRACE_HOOK_SYSCALL_DEFINE1(sys_close,SYS_CLOSE_INDEX,unsigned int, fd);
////////////////////////////////////////////////////////////////////////////////
/*
syscall : truncate
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_truncate, SYS_TRUNCATE_INDEX,
    const char __user *, pathname, unsigned long, length);
//syscall_ftruncate
KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_ftruncate, SYS_FTRUNCATE_INDEX,
    unsigned int ,fd, unsigned long, length);
//////////////////////////////////////////////////////////////////////
KVD_FTRACE_HOOK_SYSCALL_DEFINE4(sys_utimensat,SYS_UTIMENSAT_INDEX,
            int,dfd,const char __user*,pathname,
            struct timespec __user*,utimes,int,flags);

///////////////////////////////////////////////////////////////////////////////
//syscall: futimesat

KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_futimesat,SYS_FUTIMESAT_INDEX,int, dfd,
        const char __user*, pathname,
		struct timeval __user*, utimes);
/////////////////////////////////////////////////////////////////////////////////
//syscall: utimes
KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_utimes,SYS_UTIMES_INDEX,
        const char __user*, pathname,
		struct timeval __user*, utimes);


//syscall: mmap
KVD_FTRACE_HOOK_SYSCALL_DEFINE6(sys_mmap,SYS_MMAP_INDEX,
    unsigned long,addr, unsigned long,len, unsigned long,prot, 
    unsigned long, flags,unsigned long, fd, unsigned long,off);

//syscall: mmap2
KVD_FTRACE_HOOK_SYSCALL_DEFINE6(sys_mmap2,SYS_MMAP2_INDEX,
    unsigned long,addr, unsigned long,len, unsigned long,prot, 
    unsigned long, flags,unsigned long, fd, unsigned long,off);

////////////////////////////////////////////////////////////////////////////////
/*
syscall : getdents,getdents64
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_getdents, SYS_GETDENTS_INDEX,
    unsigned int,fd,
    struct linux_dirent __user*,dirent,
    unsigned int,count);

KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_getdents64,SYS_GETDENTS64_INDEX,
       unsigned int,fd,
       struct linux_dirent64 __user*,dirent,
       unsigned int,count);
//////////////////////////////////////////////////////////////////////
// open operations
int do_hook_open_syscalls(void)
{
    int rc = 0;

    //hook sys_openat firstly
    rc = KVD_REGISTER_SC_FTRACE_HOOK(openat,SYS_OPENAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(open,SYS_OPEN_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}


//close operations
int do_hook_close_syscalls(void)
{
    int rc = 0;

    rc = KVD_REGISTER_SC_FTRACE_HOOK(close,SYS_CLOSE_INDEX);

    return rc;
}

//truncate operations
int do_hook_truncate_syscalls(void)
{
    int rc = 0;

    rc = KVD_REGISTER_SC_FTRACE_HOOK(truncate,SYS_TRUNCATE_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(ftruncate,SYS_FTRUNCATE_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}

//chmod operations
int do_hook_chmod_syscalls(void)
{
    int rc = 0;

    //先hook sys_fchmodat,再hook sys_fchmod,sys_chmod,在arm64平台上hook sys_chmod一定会失败的
    rc = KVD_REGISTER_SC_FTRACE_HOOK(fchmodat,SYS_FCHMODAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(fchmod,SYS_FCHMOD_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(chmod,SYS_CHMOD_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}

//chown operations
int do_hook_chown_syscalls(void)
{
    int rc = 0;

    //先hook sys_fchownat,再hook sys_fchown,sys_chown,在arm64平台上hook sys_chown一定会失败的
    rc = KVD_REGISTER_SC_FTRACE_HOOK(fchownat,SYS_FCHOWNAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(fchown,SYS_FCHOWN_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(lchown,SYS_LCHOWN_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(chown,SYS_CHOWN_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}

//utimes operations
int do_hook_utimes_syscalls(void)
{
    int rc = 0;

    //hook utimensat firstly
    rc = KVD_REGISTER_SC_FTRACE_HOOK(utimensat,SYS_UTIMENSAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(futimesat,SYS_FUTIMESAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(utimes,SYS_UTIMES_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}


//mmap operations
int do_hook_mmap_syscalls(void)
{
    int rc = 0;

    //sys_mmap2在x86_64上肯定是没有的，在其他平台可能有
    //目前发现在i686平台上采用的是该系统调用对dlopen作支持
    KVD_REGISTER_SC_FTRACE_HOOK(mmap2,SYS_MMAP2_INDEX);
    rc = KVD_REGISTER_SC_FTRACE_HOOK(mmap,SYS_MMAP_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}

//getents/getents64 operations
int do_hook_getents_syscalls(void)
{
    int rc = 0;

    rc = KVD_REGISTER_SC_FTRACE_HOOK(getdents,SYS_GETDENTS_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(getdents64,SYS_GETDENTS64_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}

