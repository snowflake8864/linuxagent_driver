#ifndef __KVD_HOOK_H_
#define __KVD_HOOK_H_

#include <linux/types.h>

int kvd_hook_init(const char* sysmaps[],
                size_t size);
void kvd_hook_exit(void);
volatile void** kvd_find_syscall_table(void);

#endif

