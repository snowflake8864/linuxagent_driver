/*
 *hook_ops.h: 2019-06-07 created by qudreams
 *khf is a short name of kernel module tian qing
 *用于注册hook系统调用后的操作接口,类似security_ops的操作
 *我们在此处将每个系统调用称为一个阶段，每个阶段最多能支持16个回调点
 */

#ifndef HOOK_OPS_H
#define HOOK_OPS_H

#include <linux/types.h>
#include <linux/kernel.h> /* for INT_MIN, INT_MAX */
#include <linux/socket.h>


struct kvd_regs_s;
//这两个函数只在hook功能模块中调用,所以以不以khf开头
int init_hook_ops(void);
int uninit_hook_ops(void);

void kvd_set_hook_args(struct kvd_regs_s* regs,
                u_int i,u_int n,u_long* args);


const char* kvd_hook_syscall_name(u_int syscall_idx);


#endif
