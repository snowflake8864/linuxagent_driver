#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include "ipv4_rules.h"
#include "utils/utils.h"
#include "gnHead.h"
#include "defense/defense_inner.h"
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
#define GET_IPV4_RULES_DATA(inode) pde_data(inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define GET_IPV4_RULES_DATA(inode) PDE_DATA(inode)
#else
#define GET_IPV4_RULES_DATA(inode) PDE(inode)->data
#endif
#endif

#define IPV4_L1_SHIFT  12
#define IPV4_L2_SHIFT  12
#define IPV4_L3_SHIFT  (32 - IPV4_L1_SHIFT - IPV4_L2_SHIFT)

#define IPV4_L1_SIZE   (1U << IPV4_L1_SHIFT)
#define IPV4_L2_SIZE   (1U << IPV4_L2_SHIFT)
#define IPV4_L3_SIZE   (1U << IPV4_L3_SHIFT)

#define IPV4_L1_MASK   (IPV4_L1_SIZE - 1)
#define IPV4_L2_MASK   (IPV4_L2_SIZE - 1)
#define IPV4_L3_MASK   (IPV4_L3_SIZE - 1)

/**
 * The least significant bit of leaf indicates
 *  that if a segment is wholly mapped, or if
 *  a single address is assigned.
 */
#define IPV4_SEGMENT_ISSET  (1UL)

/**
 * Mask value for extra data.
 * [
 *  High bits (rather than the lowest 2 bits) of
 *  leaf data can be used for storing extra data
 *  (description or routing information) of the
 *  segment or address.
 * ]
 */
#define IPV4_SEGMENT_FLAGS_MASK   (3UL)
#define IPV4_SEGMENT_POINTER_MASK (~IPV4_SEGMENT_FLAGS_MASK)

/**
 * Some simple functions for calculating
 *  network segment addresses.
 */
static inline __u32 __l1_start(void)
{
	return 0;
}
static inline __u32 __l1_end(void)
{
	return 0xffffffff;
}
static inline __u32 __l2_start(int i)
{
	return (__u32)i << (IPV4_L2_SHIFT + IPV4_L3_SHIFT);
}
static inline __u32 __l2_end(int i)
{
	return  ((__u32)i << (IPV4_L2_SHIFT + IPV4_L3_SHIFT)) |
			(((__u32)1 << (IPV4_L2_SHIFT + IPV4_L3_SHIFT)) - 1);
}
static inline __u32 __l3_start(int i, int j)
{
	return  ((__u32)i << (IPV4_L2_SHIFT + IPV4_L3_SHIFT)) |
			((__u32)j << IPV4_L3_SHIFT);
}
static inline __u32 __l3_end(int i, int j)
{
	return  ((__u32)i << (IPV4_L2_SHIFT + IPV4_L3_SHIFT)) |
			((__u32)j << IPV4_L3_SHIFT) |
			(((__u32)1 << IPV4_L3_SHIFT) - 1);
}
static inline __u32 __address(int i, int j, int k)
{
	return  ((__u32)i << (IPV4_L2_SHIFT + IPV4_L3_SHIFT)) |
			((__u32)j << IPV4_L3_SHIFT) |
			(__u32)k;
}

static inline void ipv4_rules_free_l3(__rtype_t *l3_tbl)
{
	
	if(!l3_tbl)
		return;
	kfree(l3_tbl);
}
static void ipv4_rules_free_l2(__rtype_t **l2_tbl)
{
	int i;
	if(!l2_tbl)
		return;

	for(i = 0; i < IPV4_L2_SIZE; i++)
	{
		if((unsigned long)l2_tbl[i] & IPV4_SEGMENT_ISSET)
			continue;
		else if(l2_tbl[i])
			ipv4_rules_free_l3(l2_tbl[i]);
	}
	kfree(l2_tbl);
}
static void ipv4_rules_free_l1(__rtype_t ***l1_tbl)
{
	int i;
	if(!l1_tbl)
		return;
	
	for(i = 0; i < IPV4_L1_SIZE; i++)
	{
		if((unsigned long)l1_tbl[i] & IPV4_SEGMENT_ISSET)
			continue;
		else if(l1_tbl[i])
			ipv4_rules_free_l2(l1_tbl[i]);
	}
	kfree(l1_tbl);
}
static inline __rtype_t   *ipv4_rules_alloc_l3(void)
{
	__rtype_t *l3_tbl;
	if((l3_tbl = (__rtype_t *)kmalloc(sizeof(__rtype_t) * IPV4_L3_SIZE, GFP_KERNEL)) == NULL)
		return NULL;
	memset(l3_tbl, 0x0, sizeof(__rtype_t) * IPV4_L3_SIZE);
	return l3_tbl;
}
static inline __rtype_t  **ipv4_rules_alloc_l2(void)
{
	__rtype_t **l2_tbl;
	if((l2_tbl = (__rtype_t **)kmalloc(sizeof(__rtype_t *) * IPV4_L2_SIZE, GFP_KERNEL)) == NULL)
		return NULL;
	memset(l2_tbl, 0x0, sizeof(__rtype_t *) * IPV4_L2_SIZE);
	return l2_tbl;
}
static inline __rtype_t ***ipv4_rules_alloc_l1(void)
{
	__rtype_t ***l1_tbl;
	if((l1_tbl = (__rtype_t ***)kmalloc(sizeof(__rtype_t **) * IPV4_L1_SIZE, GFP_KERNEL)) == NULL)
		return NULL;
	memset(l1_tbl, 0x0, sizeof(__rtype_t **) * IPV4_L1_SIZE);
	return l1_tbl;
}

static int ipv4_rules_add_single_rcu(__rtype_t ****l1_tblp, __u32 ip, size_t n, unsigned long data)
{
	__rtype_t ***l1_tbl = *l1_tblp;
	__rtype_t **l2_tbl, *l3_tbl;
	__u32 l1_index = ip >> (IPV4_L2_SHIFT + IPV4_L3_SHIFT);//20
	__u32 l2_index = (ip >> IPV4_L3_SHIFT) & IPV4_L2_MASK;
	__u32 l3_index = ip & IPV4_L3_MASK;
	
	/* Check L1 pointer */
	if((unsigned long)l1_tbl & IPV4_SEGMENT_ISSET)
		return 0;
	else if(!l1_tbl)
	{
		if((l1_tbl = ipv4_rules_alloc_l1()) == NULL)
			return -1;
		 rcu_assign_pointer(*l1_tblp, l1_tbl);
	}

	/* Check L2 pointer */
	if((unsigned long)(l2_tbl = l1_tbl[l1_index]) & IPV4_SEGMENT_ISSET)
		return 0;
	else if(!l2_tbl)
	{
		if((l2_tbl = ipv4_rules_alloc_l2()) == NULL)
			return -1;
		rcu_assign_pointer(l1_tbl[l1_index], l2_tbl);
	}

	/* Check L3 pointer */
	if((unsigned long)(l3_tbl = l2_tbl[l2_index]) & IPV4_SEGMENT_ISSET)
		return 0;
	else if(!l3_tbl)
	{
		if((l3_tbl = ipv4_rules_alloc_l3()) == NULL)
			return -1;
		rcu_assign_pointer(l2_tbl[l2_index], l3_tbl);
	}

	/* Add each single address */
	for( ; n; l3_index++, n--)
	{
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		if(!(l3_tbl[l3_index & IPV4_L3_MASK] & IPV4_SEGMENT_ISSET))
			l3_tbl[l3_index & IPV4_L3_MASK] = (__rtype_t)(data | IPV4_SEGMENT_ISSET);
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
	}

	return 0;
}

static int ipv4_rules_add_l3_rcu(__rtype_t ****l1_tblp, __u32 ip, size_t n, unsigned long data)
{
	__rtype_t ***l1_tbl = *l1_tblp;
	__rtype_t **l2_tbl;
	__u32 l1_index = ip >> (IPV4_L2_SHIFT + IPV4_L3_SHIFT);
	__u32 l2_index = (ip >> IPV4_L3_SHIFT) & IPV4_L2_MASK;

	/* Check L1 pointer */
	if((unsigned long)l1_tbl & IPV4_SEGMENT_ISSET)
		return 0;
	else if(!l1_tbl)
	{
		if((l1_tbl = ipv4_rules_alloc_l1()) == NULL)
			return -1;
		 rcu_assign_pointer(*l1_tblp, l1_tbl);
	}

	/* Check L2 pointer */
	if((unsigned long)(l2_tbl = l1_tbl[l1_index]) & IPV4_SEGMENT_ISSET)
		return 0;
	else if(!l2_tbl)
	{

		if((l2_tbl = ipv4_rules_alloc_l2()) == NULL)
			return -1;
		rcu_assign_pointer(l1_tbl[l1_index], l2_tbl);
	}
	
	/* Add each L3 block */
	for( ; n; l2_index++, n--)
	{
		__u32 __l2_index = l2_index & IPV4_L2_MASK;
		__rtype_t *l3_tbl = l2_tbl[__l2_index];

		/* Assign pointer first */
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		if(!((unsigned long)l2_tbl[__l2_index] & IPV4_SEGMENT_ISSET))
			rcu_assign_pointer(l2_tbl[__l2_index], (__rtype_t *)(data | IPV4_SEGMENT_ISSET));
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

		/* If the pointer indicates a detailed L3 table, free it after RCU read finished. */
		if(!((unsigned long)l3_tbl & IPV4_SEGMENT_ISSET) && l3_tbl)
		{
			synchronize_rcu();
			ipv4_rules_free_l3(l3_tbl);
		}
	}
	return 0;
}

static int ipv4_rules_add_l2_rcu(__rtype_t ****l1_tblp, __u32 ip, size_t n, unsigned long data)
{
	__rtype_t ***l1_tbl = *l1_tblp;
	__u32 l1_index = ip >> (IPV4_L2_SHIFT + IPV4_L3_SHIFT);
	
	/* Check L1 pointer */
	if((unsigned long)l1_tbl & IPV4_SEGMENT_ISSET)
		return 0;
	else if(!l1_tbl)
	{
		if((l1_tbl = ipv4_rules_alloc_l1()) == NULL)
			return -1;
		 rcu_assign_pointer(*l1_tblp, l1_tbl);
	}
	
	/* Add each L2 block */
	for( ; n; l1_index++, n--)
	{
		__u32 __l1_index = l1_index & IPV4_L1_MASK;
		__rtype_t **l2_tbl = l1_tbl[__l1_index];

		/* Assign pointer first */
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		if(!((unsigned long)l1_tbl[__l1_index] & IPV4_SEGMENT_ISSET))
			rcu_assign_pointer(l1_tbl[__l1_index], (__rtype_t **)(data | IPV4_SEGMENT_ISSET));
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

		/* If the pointer indicates a detailed L2 table, free it after RCU read finish */
		if(!((unsigned long)l2_tbl & IPV4_SEGMENT_ISSET) && l2_tbl)
		{
			synchronize_rcu();
			ipv4_rules_free_l2(l2_tbl);
		}
	}
	return 0;
}

/* Add one L1 block for the whole IPv4 address space */
static int ipv4_rules_add_l1_rcu(__rtype_t ****l1_tblp, unsigned long data)
{
	__rtype_t ***l1_tbl = *l1_tblp;
	
	/* Check L1 pointer */
	if((unsigned long)l1_tbl & IPV4_SEGMENT_ISSET)
		return 0;

	/* Assign the pointer first, and later release the old one */
	/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
	if(!((unsigned long)*l1_tblp & IPV4_SEGMENT_ISSET))
		rcu_assign_pointer(*l1_tblp, (__rtype_t ***)(data | IPV4_SEGMENT_ISSET));
	/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

	if(!((unsigned long)l1_tbl & IPV4_SEGMENT_ISSET) && l1_tbl)
	{
		synchronize_rcu();
		ipv4_rules_free_l1(l1_tbl);
	}
	return 0;
}

int ipv4_rules_add_netmask(struct ipv4_rules *rules, __u32 net, __u32 net_mask, unsigned long data)
{
	__u32 net_size = (~net_mask) + 1;
	size_t n;
	
	net &= net_mask;

	if(net_mask == 0)
	{
		/* Add level 1 segment (for the whole address space) */
		ipv4_rules_add_l1_rcu(&rules->map_table, data);
	}
	else if((n = net_size / (1 << (IPV4_L2_SHIFT + IPV4_L3_SHIFT))) > 0)
	{
		/* Add level 2 segments */
		ipv4_rules_add_l2_rcu(&rules->map_table, net, n, data);
	}
	else if((n = net_size / (1 << IPV4_L3_SHIFT)) > 0)
	{
		/* Add level 3 segments */
		ipv4_rules_add_l3_rcu(&rules->map_table, net, n, data);
	}
	else
	{
		/* Add single addresses */
		n = net_size;
		ipv4_rules_add_single_rcu(&rules->map_table, net, n, data);
	}

	return 0;
}

int ipv4_rules_add_net(struct ipv4_rules *rules, __u32 net, int net_bits, unsigned long data)
{
	__u32 net_mask;

	if(net_bits == 0)
		net_mask = 0x00000000;
	else
		net_mask = ~(((__u32)1 << (32 - net_bits)) - 1);
	//printf("%d: %08x, %08x\n", net_bits, net_mask, net_size);

	return ipv4_rules_add_netmask(rules, net, net_mask, data);
}

int ipv4_rules_add_range(struct ipv4_rules *rules, __u32 low, __u32 high, unsigned long data)
{
	__u32 i, j, lxh;

	if(low > high)
	{
		i = low;
		low = high;
		high = i;
	}
	for(lxh = i = low ^ high; i & 1; i >>= 1);
	if(i == 0 && (low | lxh) == high)
	{
		int ret;
		if((ret = ipv4_rules_add_netmask(rules, low, ~(high - low), data)) < 0)
			return ret;
	}
	else
	{
		for(i = lxh, j = 0; i >> 1; j++) i >>= 1;
		i <<= j;
		i = ~(i - 1) & high;
		ipv4_rules_add_range(rules, low, i - 1, data);
		ipv4_rules_add_range(rules, i, high, data);
	}
	return 0;
}

bool ipv4_rules_check(struct ipv4_rules *rules, __u32 ip, unsigned long *edata)
{
	__rtype_t ***l1_tbl;
	__rtype_t  **l2_tbl;
	__rtype_t   *l3_tbl;
	__rtype_t    l3_val;
	__u32 l1_index, l2_index, l3_index;
	bool retv = false;
	unsigned long __edata = 0;
	
	rcu_read_lock();

	l1_tbl = rcu_dereference(rules->map_table);

	/* Check the L1 pointer: IPV4_SEGMENT_ISSET means always matched, NULL for never */
	if((unsigned long)l1_tbl & IPV4_SEGMENT_ISSET)
	{
		retv = true;
		__edata = (unsigned long)l1_tbl & IPV4_SEGMENT_POINTER_MASK;
		goto to_exit;
	}
	else if(l1_tbl)
	{
		l1_index = ip >> (IPV4_L2_SHIFT + IPV4_L3_SHIFT);
		if((unsigned long)(l2_tbl = rcu_dereference(l1_tbl[l1_index])) & IPV4_SEGMENT_ISSET)
		{
			retv = true;
			__edata = (unsigned long)l2_tbl & IPV4_SEGMENT_POINTER_MASK;
			goto to_exit;
		}
		else if(l2_tbl)
		{
			l2_index = (ip >> IPV4_L3_SHIFT) & IPV4_L2_MASK;
			if((unsigned long)(l3_tbl = rcu_dereference(l2_tbl[l2_index])) & IPV4_SEGMENT_ISSET)
			{
				retv = true;
				__edata = (unsigned long)l3_tbl & IPV4_SEGMENT_POINTER_MASK;
				goto to_exit;
			}
			else if(l3_tbl)
			{
				l3_index = ip & IPV4_L3_MASK;
				if((l3_val = l3_tbl[l3_index]) & IPV4_SEGMENT_ISSET)
				{
					__edata = (unsigned long)l3_val & IPV4_SEGMENT_POINTER_MASK;
					retv = true;
					goto to_exit;
				}
				else
				{
					retv = false;
					goto to_exit;
				}
			}
			else
			{
				retv = false;
				goto to_exit;
			}
		}
		else
		{
			retv = false;
			goto to_exit;
		}
	}
	else
	{
		retv = false;
		goto to_exit;
	}

	/* It won't actually get here */
	rcu_read_lock();
	return false;

to_exit:
	rcu_read_unlock();

	if(edata)
		*edata = __edata;
	return retv;
}

static inline void ipv4_rules_clean_rcu(struct ipv4_rules *rules)
{
	__rtype_t ***l1_tbl = rules->map_table;

	rcu_assign_pointer(rules->map_table, NULL);

	if(!((unsigned long)l1_tbl & IPV4_SEGMENT_ISSET) && l1_tbl)
	{
		synchronize_rcu();
		ipv4_rules_free_l1(l1_tbl);
	}
}

/* --------------------------------------------------------- */

/**
 * Structure for printing rule table.
 */
struct buffer_s
{
	char   line[100];
	size_t len;
	struct buffer_s *next;
};

static inline size_t ipv4_range_show(
		struct ipv4_rules *rules,
		struct buffer_s ***curpp, __u32 start, __u32 end,
		unsigned long edata )
{
	struct buffer_s **curp = *curpp;
	char s1[20], s2[20];
	//char line[50];
	size_t len;
	char *dp;

	if((*curp = (struct buffer_s *)kmalloc(sizeof(struct buffer_s), GFP_KERNEL)) == NULL)
		return 0;
	(*curp)->next = NULL;

	dp = (*curp)->line;

	if(end == start)
		sprintf(dp, "%s", ipv4_hltos(start, s1));
	else
		sprintf(dp, "%s-%s", ipv4_hltos(start, s1), ipv4_hltos(end, s2));
	dp += strlen(dp);

	if(rules->fn_show_edata)
	{
		*(dp++) = ' ';
		rules->fn_show_edata(edata, dp);
		dp += strlen(dp);
	}

	sprintf(dp, "\n");

	len = (*curp)->len = strlen((*curp)->line);
	*curpp = &(*curp)->next;

	return len;
}

/**
 * ipv4_rules_show_mem: Allocate a buffer for outputing IP ranges.
 */
static char *ipv4_rules_show_mem(struct ipv4_rules *rules, size_t *lenp)
{
	__rtype_t ***l1_tbl = rules->map_table;
	__rtype_t  **l2_tbl;
	__rtype_t   *l3_tbl;
	__rtype_t    l3_val;
	int i, j, k;
	__u32 start = 0, end = 0;
	bool is_start = false;  /* Use this to mark if the range has started */
	unsigned long edata_s = 0, __edata = 0;
	struct buffer_s *head = NULL, **curp = &head, *cur, *cur_next;
	char *data;
	size_t len = 0, wpos;

#define __operation_at_not_set__()	\
	do {							\
		if(is_start) {				\
			len += ipv4_range_show(rules, &curp, start, end, edata_s);	\
			is_start = false;		\
		}							\
	} while(0)

#define __operation_at_edata_diff__(cur_ip)	\
	do {							\
		len += ipv4_range_show(rules, &curp, start, end, edata_s);	\
		start = cur_ip;				\
		edata_s = __edata;			\
		is_start = true;			\
	} while(0)

	/* L1 block exist? */
	if((unsigned long)l1_tbl & IPV4_SEGMENT_ISSET)
	{
		__edata = (unsigned long)l1_tbl & IPV4_SEGMENT_POINTER_MASK;
		len += ipv4_range_show(rules, &curp, __l1_start(), __l1_end(), __edata);
		//up_read(&rules->rwsem);
		goto to_exit;
	}
	else if(!l1_tbl)
	{
		//up_read(&rules->rwsem);
		goto to_exit;
	}
	
	/* Traverse each L2 entries */
	for(i = 0; i < IPV4_L1_SIZE; i++)
	{
		if((unsigned long)(l2_tbl = l1_tbl[i]) & IPV4_SEGMENT_ISSET)
		{
			__edata = (unsigned long)l2_tbl & IPV4_SEGMENT_POINTER_MASK;
			if(!is_start)
			{
				start = __l2_start(i);
				edata_s = __edata;
				is_start = true;
			}
			else if(__edata != edata_s)
				__operation_at_edata_diff__(__l2_start(i));
			end = __l2_end(i);
		}
		else if(!l2_tbl)
			__operation_at_not_set__();
		else
		{
			for(j = 0; j < IPV4_L2_SIZE; j++)
			{
				if((unsigned long)(l3_tbl = l2_tbl[j]) & IPV4_SEGMENT_ISSET)
				{
					__edata = (unsigned long)l3_tbl & IPV4_SEGMENT_POINTER_MASK;
					if(!is_start)
					{
						start = __l3_start(i, j);
						edata_s = __edata;
						is_start = true;
					}
					else if(__edata != edata_s)
						__operation_at_edata_diff__(__l3_start(i, j));
					end = __l3_end(i, j);
				}
				else if(!l3_tbl)
					__operation_at_not_set__();
				else
				{
					for(k = 0; k < IPV4_L3_SIZE; k++)
					{
						if((l3_val = l3_tbl[k]) & IPV4_SEGMENT_ISSET)
						{
							__edata = (unsigned long)l3_val & IPV4_SEGMENT_POINTER_MASK;
							if(!is_start)
							{
								start = __address(i, j, k);
								edata_s = __edata;
								is_start = true;
							}
							else if(__edata != edata_s)
								__operation_at_edata_diff__(__address(i, j, k));
							end = __address(i, j, k);
						}
						else
							__operation_at_not_set__();
					} /* for(k = 0; k < IPV4_L3_SIZE; k++) */
				}
			} /* for(j = 0; j < IPV4_L2_SIZE; j++) */
		}
	} /* for(i = 0; i < IPV4_L1_SIZE; i++) */

	/* Display the last segment as well */
	__operation_at_not_set__();

to_exit:

	if(len == 0)
	{
		*lenp = len;
		return NULL;
	}
	if((data = (char *)kmalloc(len, GFP_KERNEL)) == NULL)
	{
		for(cur = head; cur; cur = cur_next)
		{
			cur_next = cur->next;
			kfree(cur);
		}
		*lenp = len;
		return NULL;
	}
	for(cur = head, wpos = 0; cur; cur = cur_next)
	{
		cur_next = cur->next;
		if(!(wpos < len))
			break;
		memcpy(data + wpos, cur->line, cur->len);
		wpos += cur->len;
		kfree(cur);
	}
	*lenp = len;
	return data;
}

/* --------- /proc interface part --------- */

struct ipv4_rules_proc
{
#define IPF_PROC_WBUF_SZ  512
	char    wbuf[IPF_PROC_WBUF_SZ + 20];
	size_t  wbuf_sz;
	size_t  wpos;
	/* Length of the output string */
	char   *rbuf;
	size_t  rbuf_len;
	size_t  rpos;
};

static int ipv4_rules_cmd_parse(struct ipv4_rules *rules, char *cmd)
{
	char *a1 = NULL, *a2 = NULL;
	char *sep;
	char sc;
	int n = 32;
	char *extra_str = NULL;
	// -------------------------------
	unsigned long data = 0;
	// -------------------------------
    //printk("cmd:%s\n",cmd);
    //LOG_INFO("cmd:%s\n",cmd);
	if(strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0)
	{
		/* Case 1: 'clear' command. */
		/* ------------------------------------ */
		down_write(&rules->rwsem);
		ipv4_rules_clean_rcu(rules);
		if(rules->fn_clear)
			rules->fn_clear(rules);
		up_write(&rules->rwsem);
		/* ------------------------------------ */
		return 0;
	}
	else if(strncmp(cmd, "t ", 2) == 0)
	{
		/* Case 2: 't' command (test method). */
		a1 = cmd + 2;
		if(!is_ipv4_addr(a1))
		{
			printk(KERN_WARNING "Invalid IP address '%s'.\n", a1);
			return -EINVAL;
		}
		if(ipv4_rules_check(rules, ipv4_stohl(a1), NULL))
			return 0;
		else
			return -EINVAL;
	}

	/* Check if there's extra information. */
	if((sep = strchr(cmd, ' ')))
	{
		extra_str = sep + 1;
		*sep = '\0';
	}

	/* Check IP description part: network segment or range? */
	if((sep = strchr(cmd, '/'))) { }
	else if((sep = strchr(cmd, '-'))) { }
	else if((sep = strchr(cmd, ':'))) { }
	if(sep)
	{
		/* Describes a segment or range. */
		sc = *sep;
		*sep = '\0';

		a1 = cmd;
		a2 = sep + 1;

		if(*a2 == '\0')
		{
			printk(KERN_WARNING "Nothing after '%c'.\n", sc);
			return -EINVAL;
		}
	}
	else
	{
		/* Describes a single IP, or is a 'clear' command. */
		sc = '\0';
		a1 = cmd;
	}
	
	/* Generate data for extra information. */
	if(extra_str && rules->fn_get_edata)
	{
		data = rules->fn_get_edata(extra_str);
		if(unlikely(data & IPV4_SEGMENT_FLAGS_MASK))
		{
			printk(KERN_ERR "Lowest 2 bits of extra data should be zero, but '0x%lx' obtained.\n", data);
			BUG();
			return -EFAULT;
		}
	}

	switch(sc)
	{
	case '/':
		/* 10.10.20.0/24 */
		/* ------------------------------------ */
		down_write(&rules->rwsem);
		if(is_ipv4_addr(a2))
			ipv4_rules_add_netmask(rules, ipv4_stohl(a1), ipv4_stohl(a2), data);
		else
		{
			sscanf(a2, "%d", &n);
			ipv4_rules_add_net(rules, ipv4_stohl(a1), n, data);
		}
		up_write(&rules->rwsem);
		/* ------------------------------------ */
		break;
	case ':':
	case '-':
		/* 10.10.20.0-10.20.0.255 */
		/* ------------------------------------ */
		down_write(&rules->rwsem);
		ipv4_rules_add_range(rules, ipv4_stohl(a1), ipv4_stohl(a2), data);
		up_write(&rules->rwsem);
		/* ------------------------------------ */
		break;
	default:
		if(is_ipv4_addr(a1))
		{
			/* Single IP address. */
			/* ------------------------------------ */
			down_write(&rules->rwsem);
			ipv4_rules_add_net(rules, ipv4_stohl(a1), 32, data);
			up_write(&rules->rwsem);
			/* ------------------------------------ */
		}
		else
		{
			printk(KERN_WARNING "Invalid IP address '%s'.\n", a1);
			return -EINVAL;
		}
		break;
	}
	return 0;
}

static int ipv4_rules_proc_open(struct inode *inode, struct file *file)
{
	//struct ipv4_rules *rules = (struct ipv4_rules *)PDE(inode)->data;
	struct ipv4_rules_proc *proc;
    	
	if((proc = (struct ipv4_rules_proc *)kmalloc(sizeof(struct ipv4_rules_proc), GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memset(proc, 0x0, sizeof(struct ipv4_rules_proc));
	file->private_data = proc;
	proc->wbuf_sz = IPF_PROC_WBUF_SZ;
	proc->wpos = 0;
    LOG_INFO("success open ipv4 rules\n");
	return 0;
}

static int ipv4_rules_proc_release(struct inode *inode, struct file *file)
{
	struct ipv4_rules *rules = (struct ipv4_rules *)OSEC_PDE_DATA(inode);
	struct ipv4_rules_proc *proc = (struct ipv4_rules_proc *)file->private_data;

	/* Parse the last unfinished line on close */
	if(proc->wpos > 0 && proc->wpos < proc->wbuf_sz)
	{
		proc->wbuf[proc->wpos] = '\0';
		ipv4_rules_cmd_parse(rules, proc->wbuf);
	}
	/* Release the read buffer on close */
	if(proc->rbuf)
		kfree(proc->rbuf);
	kfree(proc);
	file->private_data = NULL;
	return 0;
}

static ssize_t ipv4_rules_proc_read(struct file *file, char __user *data, size_t count, loff_t *f_pos)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct ipv4_rules *rules = (struct ipv4_rules *)OSEC_PDE_DATA(inode);
	struct ipv4_rules_proc *proc = (struct ipv4_rules_proc *)file->private_data;
	size_t len;
	
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

	if(proc->rbuf == NULL)
	{
		/* ------------------------------------ */
		down_read(&rules->rwsem);
		proc->rbuf = ipv4_rules_show_mem(rules, &proc->rbuf_len);
		up_read(&rules->rwsem);
		/* ------------------------------------ */
		proc->rpos = 0;
	}
	if((len = proc->rbuf_len - proc->rpos) == 0)
		return 0;
	if(count < len)
		len = count;
	
	if(copy_to_user(data, proc->rbuf + proc->rpos, len))
		return -EFAULT;
	proc->rpos += len;

	return len;
}

static ssize_t ipv4_rules_proc_write(struct file *file, const char __user *data, size_t count, loff_t *f_pos)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct ipv4_rules *rules = (struct ipv4_rules *)OSEC_PDE_DATA(inode);
    if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) !=0) {
		return -EINVAL;
    }


	struct ipv4_rules_proc *proc = (struct ipv4_rules_proc *)file->private_data;
	size_t len;
	size_t __count = count;
	char *ln_start, *ln_end;
	int ret;
	while(count > 0)
	{
		len = proc->wbuf_sz - proc->wpos;
		if(count < len)
			len = count;
		if(len == 0)
			return -EINVAL;
		
		if(copy_from_user(proc->wbuf + proc->wpos, data, len))
			return -EFAULT;
		proc->wpos += len;
		
		/* Pick out each possible line */
		for(ln_start = proc->wbuf;
			ln_start < proc->wbuf + proc->wpos &&
			( ln_end = (char *)memchr(ln_start, '\n', (size_t)(proc->wbuf + proc->wpos - ln_start)) );
			ln_start = ln_end + 1)
		{
			*ln_end = '\0';
			/* Parse and do operations on current line*/
			if(ln_end - ln_start > 0)
			{
				if((ret = ipv4_rules_cmd_parse(rules, ln_start)) < 0)
				{
					proc->wpos = 0;
					return ret;
				}
			}
		}
		/* Move the incomplete line data ahead */
		if(ln_start > proc->wbuf)
		{
			if(ln_start < proc->wbuf + proc->wpos)
			{
				size_t remained = (size_t)(proc->wbuf + proc->wpos - ln_start);
				memmove(proc->wbuf, ln_start, remained);
				proc->wpos = remained;
			}
			else
				proc->wpos = 0;
		}
		
		data += len;
		count -= len;
	}

	return __count - count;
}

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static const struct proc_ops ipv4_rules_proc_fops =
{
	//.owner   = THIS_MODULE,
	.proc_read    = ipv4_rules_proc_read,
	.proc_write   = ipv4_rules_proc_write,
	.proc_open    = ipv4_rules_proc_open,
	.proc_release = ipv4_rules_proc_release,
    .proc_lseek   = default_llseek,
};

#else
static const struct file_operations ipv4_rules_proc_fops =
{
	.owner   = THIS_MODULE,
	.read    = ipv4_rules_proc_read,
	.write   = ipv4_rules_proc_write,
	.open    = ipv4_rules_proc_open,
	.release = ipv4_rules_proc_release,
    .llseek   = default_llseek,
};
#endif

int ipv4_rules_init(struct ipv4_rules *rules, const char *proc_name, struct proc_dir_entry *proc_parent)
{
	rules->map_table = NULL;
	init_rwsem(&rules->rwsem);
	if(proc_name)
	{
		rules->proc_name = proc_name;
		rules->proc_parent = proc_parent;
		proc_create_data(proc_name, 0644, proc_parent, &ipv4_rules_proc_fops, rules);
	}
	else
	{
		rules->proc_name = NULL;
		rules->proc_parent = NULL;
	}
	return 0;
}

void ipv4_rules_purge(struct ipv4_rules *rules)
{
	if(rules->proc_name)
		remove_proc_entry(rules->proc_name, rules->proc_parent);
	down_write(&rules->rwsem);
	ipv4_rules_clean_rcu(rules);
	up_write(&rules->rwsem);
}

int ipv4_rules_add_single(struct ipv4_rules *rules, __u32 ip)
{
    down_write(&rules->rwsem);
	ipv4_rules_add_single_rcu(&rules->map_table, ip, 1, 0);
	up_write(&rules->rwsem);
    return 0;
}
EXPORT_SYMBOL(ipv4_rules_add_netmask);
EXPORT_SYMBOL(ipv4_rules_add_net);
EXPORT_SYMBOL(ipv4_rules_add_range);
EXPORT_SYMBOL(ipv4_rules_add_single);
EXPORT_SYMBOL(ipv4_rules_check);
EXPORT_SYMBOL(ipv4_rules_init);
EXPORT_SYMBOL(ipv4_rules_purge);


