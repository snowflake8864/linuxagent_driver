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

//syscall: delete_module
KVD_FTRACE_HOOK_SYSCALL_DEFINE2(sys_delete_module,SYS_DELETE_MODULE_INDEX,
                                    const char __user *, name_user,
                                    unsigned int, flags);
/////////////////////////////////////////////////////////////////////////////////


//mount operation
int do_hook_delete_module_syscalls(void)
{
    int rc = 0;
    rc = KVD_REGISTER_SC_FTRACE_HOOK(delete_module,SYS_DELETE_MODULE_INDEX);

    return rc;
}
