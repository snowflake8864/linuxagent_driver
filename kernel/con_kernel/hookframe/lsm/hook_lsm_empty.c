
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/security.h>


#warning "don't support lsm hook"


int kvd_lsm_hooks_init(struct security_operations* new_lsm_ops)
{
    return -ENOTSUPP;
}

int kvd_add_lsm_hooks(struct security_operations *hooks,int count,
                    struct security_operations** porg)
{
    return -ENOTSUPP;
}

int kvd_del_lsm_hooks(struct security_operations* hooks, int count)
{
    return -ENOTSUPP;
}

static void do_lsm_hook_init(void)
{}

static void do_lsm_hook_uninit(void)
{}
