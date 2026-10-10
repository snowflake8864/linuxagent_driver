/*
 *kvd_memcache.h: 2019-06-07 created by qudreams
 *a wrapper for kernel slab cache
 *khf is a short name for kernel hook frame
 */
#ifndef KVD_MEM_CACHE_H
#define KVD_MEM_CACHE_H

#include <linux/slab.h>

struct kmem_cache *kvd_mem_cache_create(const char* name,size_t size, size_t align);
#define kvd_mem_cache_destroy kmem_cache_destroy
#define kvd_mem_cache_zalloc kmem_cache_zalloc
#define kvd_mem_cache_free   kmem_cache_free

#endif
