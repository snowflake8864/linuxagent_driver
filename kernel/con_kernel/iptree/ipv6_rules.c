#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/ipv6.h>

#include "core/kvd_memcache.h"
#include "ipv6_rules.h"
#include "utils/utils.h"
#include "gnHead.h"
#include "hcache/h_cache.h"
#include "utils/var_proc.h"
#include "defense/defense_inner.h"

#define IPV6_BLOCK_CACHE_HASH_SIZE    (1 << 7)
#define IPV6_BLOCK_CACHE_MAX_LEN      (IPV6_BLOCK_CACHE_HASH_SIZE * 8)
#define IPV6_BLOCK_CACHE_TIMEOUT      (0)
#define IPV6_BLOCK_OUTPUT_INTERVAL    (300)


typedef struct {
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
} _ip46_address_t;


struct block_cache
{   
    struct h_scalar h_scalar;
    _ip46_address_t  sip;
};

static u32 _g_hash_initval  = 0;
struct block_cache_table
{
    struct h_table h_table;
    struct kmem_cache *mem_cache;
} block_cache_tbl;
struct h_bucket block_cache_base[IPV6_BLOCK_CACHE_HASH_SIZE];

struct block_cache_key
{
    _ip46_address_t  sip;
};
/* Find route for the newly created packet. */

static u32 block_cache_hash_fn(void *key) {
    struct block_cache_key *k = (struct block_cache_key *)key;
    uint32_t a = k->sip.as_u32[2] ^ k->sip.as_u32[3];
    return jhash_3words(a, k->sip.as_u32[0] , k->sip.as_u32[1] , _g_hash_initval);
}



static int block_cache_comp_key_fn(struct h_scalar *he, void *key)
{
    struct block_cache *fc = container_of(he, struct block_cache, h_scalar);
    struct block_cache_key *k = (struct block_cache_key *)key;

    return (fc->sip.as_u64[0] ^ k->sip.as_u64[0] || fc->sip.as_u64[1] ^ k->sip.as_u64[1]);
}


static void block_cache_release_fn(struct h_scalar *he)
{
    struct block_cache *tc = container_of(he, struct block_cache, h_scalar);
    //LOG_INFO("free session, %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u\n",\
    IPQUADS(tc->sip), ntohs(tc->sport), IPQUADS(tc->dip), ntohs(tc->dport));
    kmem_cache_free(block_cache_tbl.mem_cache, tc);
}

static char *block_cache_build_line_fn(struct h_scalar *he, gfp_t flags)
{   
    struct block_cache *tc = container_of(he, struct block_cache, h_scalar);
    char *line, *dp;
 	
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }
   
    if((line = (char *)kmalloc(150, flags)) == NULL)
        return NULL;
    /* Only XXX bytes max needed. */
    dp = line;
    
   
    /* Connection tuple description. */

    //LOG_INFO("in netdos_tcp_in_v6 process:%s, %pI6:%u-->%pI6:%u Protocol: %d\n", \
    CURRENT_COMM, &ip6h->saddr, ntohs(tcph->source),&ip6h->daddr, ntohs(tcph->dest), ip6h->nexthdr);  
    sprintf(dp, "block ip:%pI6\n",
            &tc->sip.ip6);

    dp += strlen(dp);
    return line;
}
static struct h_scalar_operations block_cache_ops =
{
    .hash        = block_cache_hash_fn,
    .comp_key    = block_cache_comp_key_fn,
    .release     = block_cache_release_fn,
    .build_line  = block_cache_build_line_fn,
};

#include <net/arp.h>
static struct h_scalar *block_cache_create_fn(struct h_table *ht, void *key)
{   
    struct block_cache_key *k = (struct block_cache_key *)key;
    struct block_cache *tc;
    if((tc = (struct block_cache *)kvd_mem_cache_zalloc(block_cache_tbl.mem_cache, GFP_ATOMIC)) == NULL)
        return NULL;
    memcpy(&tc->sip, &k->sip, sizeof(_ip46_address_t));

    LOG_INFO("create==========%pI6\n",
            &tc->sip.ip6); 
    return &tc->h_scalar;
}


static int ipv6_block_cache_try_get(struct in6_addr *sip)
{
    struct h_scalar *he;
    struct block_cache *tc;
    struct block_cache_key k;
	
    memcpy(&k.sip.ip6, sip, sizeof(_ip46_address_t));
    return h_scalar_try_get(&block_cache_tbl.h_table, &k,  block_cache_create_fn, NULL);
}
static void __block_cache_lookup_action(struct h_scalar *he, void *key, void *result)
{
    struct block_cache_key *k = (struct block_cache_key *)key;
    struct block_cache *tc = container_of(he, struct block_cache, h_scalar);
}


int ipv6_block_cache_lookup(struct in6_addr *sip)
{
    struct block_cache *tc;
    struct block_cache_key k;
    memcpy(&k.sip.ip6, sip, sizeof(_ip46_address_t));
    return h_scalar_try_lookup(&block_cache_tbl.h_table, &k, NULL, __block_cache_lookup_action) == 0;
}

static int ipv6_block_cache_free(struct in6_addr *sip)
{
    struct block_cache *tc;
    struct block_cache_key k;
    memcpy(&k.sip.ip6, sip, sizeof(_ip46_address_t));
    return h_scalar_try_free_key(&block_cache_tbl.h_table, &k);
}




int ip6str_parse_kernel(const char *ip6str, struct in6_addr *addr) 
{
    int ip6str_len = strlen(ip6str);
    if (ip6str_len > 40) {
        return -1;
    }
    if (likely(in6_pton(ip6str, strlen(ip6str), (void *)addr, -1, NULL) == 1)) {  
        return 0;
    }
    return -1;
}

static int ipv6_rules_cmd_parse(char *cmd)
{
     _ip46_address_t ipaddr;
    trim_spaces(cmd);
	if(strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0)
	{
        h_scalar_table_clear(&block_cache_tbl.h_table);
        LOG_INFO("clear:%s\n",cmd);
		return 0;
	} else {
        ip6str_parse_kernel(cmd, &ipaddr.ip6); 
		LOG_INFO("==========%pI6\n",
				&ipaddr.ip6); 
        return ipv6_block_cache_try_get(&ipaddr.ip6);
    }

    return 0;
}

static void __block_saddr_rt_build_action(struct h_scalar *he, void *p)
{
    struct block_cache *tc = container_of(he, struct block_cache, h_scalar);
    char *buf = (char *)p;
    char n = strlen(buf);
    snprintf(buf + n, 4095 - n, "%pI6\n",\
				&tc->sip.ip6); 
}

/*
 * Operations for setting or displaying block gateway.
 */
static int __block_saddr_rt_build(char *buf, size_t buf_sz, void *info)
{
	
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

    memset(buf, 0, buf_sz);
    h_scalar_table_iterate_safe2(&block_cache_tbl.h_table, (void *)buf, __block_saddr_rt_build_action);
	return 0;
}
static int __block_saddr_rt_parse(const char *buf, void *info)
{
#if 0
	if(!is_ipv4_addr(buf))
		return -EINVAL;
	forward_gateway = ipv4_stohl(buf);
#endif
    ipv6_rules_cmd_parse(buf);
	return 0;
}
static struct var_proc_info block_saddr_rt_vinfo =
{
	.parse = __block_saddr_rt_parse,
	.build = __block_saddr_rt_build,
};


int ipv6_block_cache_init(struct proc_dir_entry *proc_parent)
{
    int ret, retv = -1; 
     //g_hash_initval = (u32)CURRENT_TIME_SEC.tv_sec;
     _g_hash_initval = (u32)jiffies;

    if((block_cache_tbl.mem_cache = kvd_mem_cache_create("ipv6_block_cache",
        sizeof(struct block_cache), 0)) == NULL)
    {   
        retv = -ENOMEM;
        goto err_kmem_create;
    }   
    block_cache_tbl.h_table.timeo = 0;

    if((retv = h_scalar_table_create(&block_cache_tbl.h_table, block_cache_base,
        IPV6_BLOCK_CACHE_HASH_SIZE, IPV6_BLOCK_CACHE_MAX_LEN,  &block_cache_ops,
        GFP_KERNEL, "ipv6_block_cache_tbl", proc_parent)) < 0)
    {   
        goto err_block_create;
    }   
    
    VAR_PROC_FS_CREATE(block_cache_tbl.h_table.max_len, IPV6_BLOCK_CACHE_HASH_SIZE / 16, IPV6_BLOCK_CACHE_HASH_SIZE * 16, "ipv6_block_cache_max", proc_parent);
    //VAR_PROC_FS_CREATE(block_cache_tbl.h_table.timeo, 1, 7200, "ipv6_block_cache_timeo", proc_parent);
	var_proc_create("block_saddr_rt_v6", proc_parent, &block_saddr_rt_vinfo);	
    LOG_INFO("session_cache_init success...\n");
    return retv;
err_block_create:
    VAR_PROC_FS_REMOVE("ipv6_block_cache_max", proc_parent);
    kmem_cache_destroy(block_cache_tbl.mem_cache);
err_kmem_create:
    return retv;
}

void ipv6_block_cache_exit(struct proc_dir_entry *proc_parent)
{
    
	var_proc_remove("block_saddr_rt_v6", proc_parent);
    VAR_PROC_FS_REMOVE("ipv6_block_cache_max", proc_parent);
    h_scalar_table_release(&block_cache_tbl.h_table);
    kvd_mem_cache_destroy(block_cache_tbl.mem_cache);
}


