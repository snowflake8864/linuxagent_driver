#ifndef HOOK_H_
#define HOOK_H_

#include <asm/atomic.h>

extern int _hook_lsm_on; 

int vsec_hook_init(void);
void vsec_hook_exit(void);
void reset_old_syscall_hook(void);

#endif

