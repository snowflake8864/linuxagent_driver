#ifndef __KVD_LSM_H
#define __KVD_LSM_H

#include <linux/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
    struct security_operations;
    int kvd_lsm_hooks_init(struct security_operations* new_lsm_ops);
    int kvd_add_lsm_hooks(struct security_operations* new_lsm_ops,int count,
                        struct security_operations** porg);
    int kvd_del_lsm_hooks(struct security_operations* new_lsm_ops, int count);

#else
    struct security_hook_list;
    struct security_hook_heads;

    extern struct security_hook_heads* __kvd_lsm_hook_heads;

    #define KVD_LSM_HOOK_INIT(HOOK_LIST,HEAD,HOOK_FN)       \
        {                                                   \
            struct security_hook_list *plist = &HOOK_LIST;  \
            if(__kvd_lsm_hook_heads) {                      \
                plist->head = &__kvd_lsm_hook_heads->HEAD;  \
                plist->hook.HEAD = HOOK_FN;                 \
            }                                               \
        }

    int kvd_lsm_hooks_init(struct security_hook_list* hook_list);
    int kvd_add_lsm_hooks(struct security_hook_list* new_lsm_ops,int count,
                            struct security_hook_list** porg);
    int kvd_del_lsm_hooks(struct security_hook_list* new_lsm_ops, int count);
#endif

int kvd_init_lsm_hook(void);
void kvd_uninit_lsm_hook(void);

#endif
