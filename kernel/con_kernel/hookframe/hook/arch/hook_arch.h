#ifndef KOSEC_HOOK_ARCH_H
#define KOSEC_HOOK_ARCH_H

#include <linux/list.h>
#include <linux/errno.h>
#include <linux/types.h>
#include "hook/wp.h"

struct hook_arch_operations{
    const char* name;
    int (*fn_init)(void);
    void (*fn_uninit)(void);
    int (*fn_disable_wp)(unsigned long*);
    void (*fn_restore_wp)(unsigned long);
    //由应用层预先设置符号地址，某些情况下地址在内核是拿不到的，
    //这个函数要在真正hook前调用
    int (*fn_set_ksym_addr)(const char*,unsigned long); 
    //对内核地址进行重新修正，因为有些地址存在偏移
    void (*fn_refix_ksym_addr)(void);
};

int init_hook_arch(void);
void uninit_hook_arch(void);
int preset_ksym_addr(const char* name,unsigned long addr);
int disable_wp(unsigned long* pflags);
void restore_wp(unsigned long flags);
void refix_ksym_addr(void);

#endif
