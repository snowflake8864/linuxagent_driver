#include <linux/types.h>
#include <linux/version.h>
#include "kvd_memcache.h"

struct kmem_cache *kvd_mem_cache_create(const char* name, size_t size, size_t align)
{
    struct kmem_cache* pcache = NULL;
    #if 0
    char prefixed_name[256] = {0};
    // Add osec_ prefix to the name
    snprintf(prefixed_name, sizeof(prefixed_name), "osec_%s", name);

    //the flags must be 0,or else will occur system-dump on Neokylin 6.5
    //but I don't know why
    #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
        pcache = kmem_cache_create(prefixed_name, size, align, 0, NULL);
    #else
        pcache = kmem_cache_create(prefixed_name, size, align, 0, NULL, NULL);
    #endif
#else
    #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
        pcache = kmem_cache_create(name, size, align, 0, NULL);
    #else
        pcache = kmem_cache_create(name, size, align, 0, NULL, NULL);
    #endif

#endif
    return pcache;
}
