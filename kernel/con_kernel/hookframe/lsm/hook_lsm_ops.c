/*
 *hook_lsm_ops.c: 2020-05-03 created by qudreams
 *support lsm-hook operations before linux kernel 4.2.0
 */

#include <linux/types.h>
#include <linux/version.h>
#include <linux/security.h>
#include "hook/hook_ksyms.h"

static unsigned long hook_lsm_ok = 0;
static struct security_operations* lsm_org_ops = NULL;
static struct security_operations** pp_lsm_ops = NULL;

extern int hook_search_ksym(const char *sym_name, unsigned long *sym_addr);
//general Linux
//这里使用二级指针是为了hook_replace_pointer方便
static struct security_operations** find_security_ops(void)
{
    struct security_operations** psec_ops = ERR_PTR(-EFAULT);

    psec_ops = (struct security_operations**)kallsyms_lookup_name("security_ops");
    if(!psec_ops) {
        int rc = hook_search_ksym("security_ops",
                        (unsigned long*)&psec_ops);
        if(rc) { psec_ops = ERR_PTR(rc); }
    }

    if(IS_ERR(psec_ops)) {
        LOG_ERROR("not find security_ops\n");
    } else {
        LOG_INFO("find security_ops at: 0x%lx\n",(long)psec_ops);
    }

    return psec_ops;
}

extern int hook_replace_pointer(void **pp_addr, void *pointer);


int kvd_add_lsm_hooks(struct security_operations* new_lsm_ops,int count,
                    struct security_operations** porg)
{
    int rc = -EAGAIN;
    
    (void)count;

    if(test_and_set_bit(0,&hook_lsm_ok)) {
        LOG_ERROR("add_lsm_hooks failed:"
            " some one has register\n");
        return rc;
    }

    LOG_INFO("lsm_org_ops at 0x%lx\n",(long)lsm_org_ops);

    rc = -EFAULT;
    (void)xchg(porg,lsm_org_ops);
    rc = hook_replace_pointer((void **)pp_lsm_ops,new_lsm_ops);
    if (rc) {
        (void)xchg(porg,NULL);
        clear_bit(0,&hook_lsm_ok);
        LOG_ERROR("hook_replace_pointer error: rc: %d\n",rc);
    } else {
        LOG_INFO("new security_ops at  0x%lx\n",(long)*pp_lsm_ops);
    }
    
    return rc;
}

int kvd_del_lsm_hooks(struct security_operations* new_lsm_ops, int count)
{
    int ok = 0;
    int rc = -EFAULT;

    (void)count;
    (void)new_lsm_ops;
    
    ok = test_bit(0,&hook_lsm_ok);
    if (ok && lsm_org_ops) {
        hook_replace_pointer((void **)pp_lsm_ops, lsm_org_ops);
    }

    if(ok) {
        rc = 0;
        clear_bit(0,&hook_lsm_ok); 
    }

    return rc;
}

int kvd_lsm_hooks_init(struct security_operations* new_lsm_ops)
{
    int rc = -EFAULT;

    if(!lsm_org_ops) { return rc; }

    rc = 0;
    memcpy(new_lsm_ops,lsm_org_ops,
            sizeof(*lsm_org_ops));
    return 0;
}

static void do_lsm_hook_init(void)
{
    struct security_operations** psec_ops = ERR_PTR(-EFAULT);

    psec_ops = find_security_ops();
    if(IS_ERR(psec_ops)) {
        return;
    }

    lsm_org_ops = *psec_ops;
    pp_lsm_ops = psec_ops;
}

static void do_lsm_hook_uninit(void)
{}
