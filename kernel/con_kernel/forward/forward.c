#include <linux/module.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include "gnHead.h"
#include "forward.h"

extern struct proc_dir_entry *proc_osec;
struct proc_dir_entry *proc_forward;
int forward_init(void)
{
    int retv = 0;
    if((proc_forward = proc_mkdir("forward", proc_osec)) == NULL)
    {   
        LOG_INFO("forward: creating proc_fs directory failed.\n");
        retv = -1;
        goto err1;
    }   

    if ((retv =session_cache_init(proc_forward)) == -1) {
        LOG_INFO("forward: creating proc_fs directory failed.\n");
        goto err2;
    }
    //forward_rtable_init(proc_forward);
    return retv;
err2:
    remove_proc_entry("forward", proc_osec);
err1:
    return retv;
}
void forward_exit(void)
{
    //forward_rtable_exit();
    session_cache_exit(proc_forward);
    remove_proc_entry("forward", proc_osec);
}
