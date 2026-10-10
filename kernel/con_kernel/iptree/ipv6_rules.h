#ifndef __IPV6_RULES_H
#define __IPV6_RULES_H

#include <linux/types.h>

int ipv6_block_cache_init(struct proc_dir_entry *proc_parent);
void ipv6_block_cache_exit(struct proc_dir_entry *proc_parent);
int ipv6_block_cache_lookup(struct in6_addr *sip);
#endif /* __IPV4_RULES_H */
