
#ifndef HOOK_KSYMS_H
#define HOOK_KSYMS_H

#include <asm/atomic.h>
#include "khookframe.h"

void init_syms_opt(const char* sysmaps[],
                size_t size);
int clear_syms_opt(void);

#endif
