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
#include "core/kvd_core.h"
#include "utils/fs_magic.h"
#include "utils/utils.h"
#include "fs_inner.h"
#include "fs_core.h"
#include "syscall_def.h"
#include "gnHead.h"

//////////////////////////////////////////////////////////////////////////////
//syscall: mount
KVD_FTRACE_HOOK_SYSCALL_DEFINE5(sys_mount,SYS_MOUNT_INDEX,
                char __user *, dev_name, char __user *, dir_name,
                char __user *, type, unsigned long, flags,
                void __user *, data);
///////////////////////////////////////////////////////////////////////////////////////////////////
//syscall: umount
KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_umount,SYS_UMOUNT_INDEX,
                char __user *, name, int, flags);
KVD_FTRACE_HOOK_SYSCALL_DEFINE1(sys_oldumount,SYS_OLDUMOUNT_INDEX,
                char __user *, name);
/////////////////////////////////////////////////////////////////////////////////


//mount operation
int do_hook_mount_syscalls(void)
{
    int rc = 0;
    rc = KVD_REGISTER_SC_FTRACE_HOOK(mount,SYS_MOUNT_INDEX);
    if(rc) { goto out; }

    KVD_REGISTER_SC_FTRACE_HOOK(umount,SYS_UMOUNT_INDEX);
    KVD_REGISTER_SC_FTRACE_HOOK(oldumount,SYS_OLDUMOUNT_INDEX);

out:
    return rc;
}
