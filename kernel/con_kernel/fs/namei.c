#include <linux/types.h>
#include <linux/list.h>
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
#include "core/kvd_core.h"
#include <linux/binfmts.h>
#include "fs_inner.h"
#include "syscall_def.h"


//syscall:linkat
KVD_FTRACE_HOOK_SYSCALL_DEFINE5(sys_linkat, SYS_LINKAT_INDEX,
                int, olddfd, const char __user *, oldname,
			    int, newdfd, const char __user *, newname,int, flags);
////////////////////////////////////////////////////////////////////////////////
//syscall: link
KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_link,SYS_LINK_INDEX, 
                const char __user *, oldname,
			    const char __user *, newname);


////////////////////////////////////////////////////////////////////////////////
/*
syscall : unlinkat
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_unlinkat, SYS_UNLINKAT_INDEX,
    int, dfd, const char __user *, pathname, int, flag);

////////////////////////////////////////////////////////////////////////////////
/*
syscall : unlink
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE1(sys_unlink,SYS_UNLINK_INDEX, 
                    const char __user *, pathname);
///////////////////////////////////////////////////////////////////////////////
/*
 *sycall: mkdirat
 */
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
 KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_mkdirat,SYS_MKDIRAT_INDEX,
    int, dfd,const char __user *, pathname,umode_t, mode);
 #else
 KVD_FTRACE_HOOK_SYSCALL_DEFINE3(sys_mkdirat,SYS_MKDIRAT_INDEX,
        int, dfd,const char __user *, pathname,int, mode);
 #endif

 ///////////////////////////////////////////////////////////////////////////////
 /*
  *sycall: mkdir
  */
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
  KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_mkdir,SYS_MKDIRAT_INDEX, 
                const char __user *, pathname,umode_t, mode);
  #else
  KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_mkdir,SYS_MKDIRAT_INDEX, 
                const char __user *, pathname,int, mode);
  #endif

////////////////////////////////////////////////////////////////////////////////
/*
syscall : renameat2
*/

//flags-->RENAME_EXCHANGE,RENAME_NOREPLACE,RENAME_WHITEOUT
KVD_FTRACE_HOOK_SYSCALL_DEFINE5(sys_renameat2,SYS_RENAMEAT2_INDEX,
                int, olddfd, const char __user *, oldname, 
                int, newdfd, const char __user *, newname,unsigned int, flags);
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
/*
syscall : renameat
*/
KVD_FTRACE_HOOK_SYSCALL_DEFINE4(sys_renameat,SYS_RENAMEAT_INDEX,
                int, olddfd, const char __user *, oldname,
                int, newdfd, const char __user *, newname);

////////////////////////////////////////////////////////////////////////////////
/*
syscall : rename
*/

KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_rename,SYS_RENAME_INDEX, 
    const char __user *, oldname, const char __user *, newname);

//////////////////////////////////////////////////////////////////////////////////////////////////////////

//link operations
int do_hook_link_syscalls(void)
{
    int rc = 0;

    //先hook sys_linkat,再hook sys_link,在arm64平台上hook sys_link一定会失败的
    rc = KVD_REGISTER_SC_FTRACE_HOOK(linkat,SYS_LINKAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(link,SYS_LINK_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}

//unlink operations
int do_hook_unlink_syscalls(void)
{
    int rc = 0;

    //先hook sys_unlinkat,再hook sys_unlink,在arm64平台上hook sys_unlink一定会失败的
    rc = KVD_REGISTER_SC_FTRACE_HOOK(unlinkat,SYS_UNLINKAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(unlink,SYS_UNLINK_INDEX);
    if(rc) { goto out; }
 
out:
    return rc;
}

//rename operations
int do_hook_rename_syscalls(void)
{
    int rc = 0;

    //不用关心renameat2是否会失败，因为在小于3.15版本的内核上一定会失败，但不影响
    KVD_REGISTER_SC_FTRACE_HOOK(renameat2,SYS_RENAMEAT2_INDEX);

    //先hook sys_renameat,再hook sys_rename,在arm64平台上hook sys_rename一定会失败的
    rc = KVD_REGISTER_SC_FTRACE_HOOK(renameat,SYS_RENAMEAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(rename,SYS_RENAME_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}


//directory operations
int do_hook_dir_syscalls(void)
{
    int rc = 0;

    //先hook sys_mkdirat,再hook sys_mkdir,在arm64平台上hook sys_mkdir一定会失败的
    rc = KVD_REGISTER_SC_FTRACE_HOOK(mkdirat,SYS_MKDIRAT_INDEX);
    if(rc) { goto out; }

    rc = KVD_REGISTER_SC_FTRACE_HOOK(mkdir,SYS_MKDIR_INDEX);
    if(rc) { goto out; }

out:
    return rc;
}
