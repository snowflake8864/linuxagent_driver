#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/freezer.h>
#endif
#include "core/kvd_core.h"
#include "gnHead.h"

struct task_struct *_vd_kth = NULL;

//dns查询通知
static BLOCKING_NOTIFIER_HEAD(_kth_chain);
static atomic_t _kth_chain_count = ATOMIC_INIT(0);

int register_kthread_notifier(struct notifier_block* notifier)
{
    int rc = -EINVAL;
    
    if(!notifier || !notifier->notifier_call) {
        return rc;
    }

    rc = blocking_notifier_chain_register(&_kth_chain,notifier);
    if(rc == 0) { atomic_inc(&_kth_chain_count); }

    return rc;
}

void unregister_kthread_notifier(struct notifier_block* notifier)
{
    int ret = 0;
    
    ret = blocking_notifier_chain_unregister(&_kth_chain,notifier);
    if(ret == 0) { atomic_dec(&_kth_chain_count); }
}

static void kthread_fired(unsigned long ecn,void* data)
{
    if(0 < atomic_read(&_kth_chain_count)) {
        blocking_notifier_call_chain(&_kth_chain,ecn,data);
    }
}

static int kthread_routine(void *data)
{
	while (!kthread_should_stop())
	{
		kthread_fired(0,NULL);
        //support system hibernate
        try_to_freeze(); 
		msleep(1000);
	}

	return 0;
}

void vsec_kthread_init(void)
{
	_vd_kth = kthread_run(kthread_routine, NULL, "osec_kth");
	if (IS_ERR(_vd_kth)) {
		LOG_ERROR("create osec kthread fail,"
			"err: %ld\n",PTR_ERR(_vd_kth));
	}
}

void vsec_kthread_exit(void)
{
	if (!KVD_IS_ERR_OR_NULL(_vd_kth)) {
        kthread_stop(_vd_kth);
        _vd_kth = NULL;
    }
}
