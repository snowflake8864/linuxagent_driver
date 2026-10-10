#ifndef KOSEC_KTHREAD_H
#define KOSEC_KTHREAD_H

int  vsec_kthread_init(void);
void vsec_kthread_exit(void);

int register_kthread_notifier(struct notifier_block* notifier);
void unregister_kthread_notifier(struct notifier_block* notifier);

#endif
