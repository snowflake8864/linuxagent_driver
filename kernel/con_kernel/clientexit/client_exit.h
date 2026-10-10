/*
 *client_exit.h: 2019-06-27 created by qudreams
 *处理客户端用户态进程退出通知
 */

#ifndef CLIENT_EXIT_H
#define CLIENT_EXIT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/notifier.h>

int register_client_exit_notify(struct notifier_block* notifier);
void unregister_client_exit_notify(struct notifier_block* notifier);

void vsec_client_exit_init(void);
void vsec_client_exit_uninit(void);

#endif
