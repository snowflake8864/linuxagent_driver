#include <linux/types.h>
#include <linux/version.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>

#include "hook/hook_ksyms.h"
#include "khookframe.h"
#include "hook/wp.h"
#include "kvd_lsm.h"

struct security_hook_heads* __kvd_lsm_hook_heads = NULL;

int kvd_lsm_hooks_init(struct security_hook_list* new_lsm_ops)
{
    (void)new_lsm_ops;
    return 0;
}

int kvd_add_lsm_hooks(struct security_hook_list *hooks,int count,
                    struct security_hook_list** porg)
{
    int i;
	int rc = -ENOTSUPP;
	unsigned long old_v;
    (void)porg;

    if(!__kvd_lsm_hook_heads) {
        return rc;
    }

	rc = disable_wp(&old_v);
	if (rc) { return rc; }

	for (i = 0; i < count; i++) {
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
        list_add_tail_rcu(&hooks[i].list, hooks[i].head);
    #else
        hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);
    #endif
	}
	restore_wp(old_v);

	return rc;
}


int kvd_del_lsm_hooks(struct security_hook_list* hooks, int count)
{
    int i;
	int rc = -ENOTSUPP;
    unsigned long old_v;

    if(!__kvd_lsm_hook_heads) {
        return rc;
    }

    rc = disable_wp(&old_v);
    if(rc) { return rc; }

    for (i = 0; i < count; i++) {
	#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
		list_del_rcu(&hooks[i].list);
	#else
		hlist_del_rcu(&hooks[i].list);
	#endif
    }

    restore_wp(old_v);

    /* mips上使用必崩, 暂时移除
     * loongarch
     * 麒麟990
     * */
#if !defined(__mips__) && !defined(__loongarch__) \
        && !defined(CONFIG_HUAWEI_ARMPC_PLATFORM) \
        && !defined(__sw_64__)
    synchronize_rcu();
#endif

    return rc;
}

extern int hook_search_ksym(const char *sym_name, unsigned long *sym_addr);
//我们在此处不做错误控制，因为在很多场合是不需要lsm hook的
//所以此处初始化成功就使用，不成功在后面使用时就判断
static void do_lsm_hook_init(void)
{
    struct security_hook_heads* pheads = NULL;
	pheads = (void *)kallsyms_lookup_name("security_hook_heads");
	if (!pheads) {
        hook_search_ksym("security_hook_heads",
                (unsigned long*)&pheads);
	}

    if(!pheads) {
		LOG_ERROR("failed to find security_hook_heads\n");
    } else {
        __kvd_lsm_hook_heads = pheads;
        LOG_INFO("find security_hook_heads at: 0x%lx\n",(long)pheads);
    }
}

static void do_lsm_hook_uninit(void)
{}
