#ifndef KVD_KALLSYMS_H
#define KVD_KALLSYMS_H

#include <linux/types.h>
int kvd_load_kallsyms(const char* kallsyms,
		int (*cb)(const char* data,size_t len));

#endif
