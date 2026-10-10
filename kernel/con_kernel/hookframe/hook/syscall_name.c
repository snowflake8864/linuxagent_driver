#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/list.h>
#include "khookframe.h"

#define SET_SYSCALL_NAME(idx,name)  \
    if (idx > 0)                    \
        __syscall_names[idx] = name   

static const char* __syscall_names[KVD_NR_SYSCALLS] = { NULL};


void __set_syscall_name(int syscall_idx,const char* name) 
{
    SET_SYSCALL_NAME(syscall_idx,name);
}

const char* get_syscall_name(int index)
{
    const char* name = "unknown syscall";
    if(index < 0 || KVD_NR_SYSCALLS <= index) {
        return name;
    }

    name = __syscall_names[index];
    if(!name) { name = "unknown syscall"; }

    return name;
}

void init_syscall_names(void)
{
    LOG_INFO("NR_syscalls: %d\n",
            KVD_NR_SYSCALLS);
}

void uninit_syscall_names(void)
{}
