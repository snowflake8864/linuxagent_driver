#ifndef __FORWARD_SESSION_H__
#define __FORWARD_SESSION_H__
#include <linux/types.h>
#include <net/ipv6.h>
#include "hcache/h_cache.h"

#define SESSION_CACHE_HASH_SIZE    (1 << 8)
#define SESSION_CACHE_MAX_LEN      (SESSION_CACHE_HASH_SIZE * 8)
#define SESSION_CACHE_TIMEOUT      (30)
#define SESSION_OUTPUT_INTERVAL    (300)

#define SESSION_IPV6

typedef struct {
#ifdef SESSION_IPV6
	union {
		struct in6_addr ip6;
		struct {
			uint32_t pad[3];
			uint32_t ip4;
		};
        uint8_t as_u8[16];
        uint16_t as_u16[8];
        uint32_t as_u32[4];
        uint64_t as_u64[2];
	};  
#else
	uint32_t ip4;
#endif
} ip46_address_t;


struct session_cache
{   
    struct h_cache h_cache;
    
    ip46_address_t  sip;
    ip46_address_t  dip;
#ifdef SESSION_IPV6
    ip46_address_t  forward_sip;
#endif
    ip46_address_t  forward_dip;
	//ip46_address_t  rip;
    uint16_t  sport;
    uint16_t  dport;
    uint16_t  forward_sport;
    uint16_t  forward_dport;
    uint16_t  rport;
    struct rtable *rt;
    //unsigned long rt_addr;
    //uint8_t   l4_proto;
    //spinlock_t   lock;
};



int session_cache_init(struct proc_dir_entry *proc_parent);
void session_cache_exit(struct proc_dir_entry *proc_parent);
#endif
