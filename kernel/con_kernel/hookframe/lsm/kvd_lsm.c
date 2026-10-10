#include <linux/version.h>
#include "kvd_lsm.h"
#include "khookframe.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#include "hook_lsm_empty.c"
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4,2,0)
#include "hook_lsm_ops.c"
#else
#include "hook_lsm_list.c"
#endif


int kvd_init_lsm_hook(void)
{
    LOG_INFO("init kvd lsm hook\n");
    do_lsm_hook_init();
    return 0;
}

void kvd_uninit_lsm_hook(void)
{
    LOG_INFO("uninit kvd lsm hook\n");
    do_lsm_hook_uninit();
}
