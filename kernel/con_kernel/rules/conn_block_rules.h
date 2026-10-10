#ifndef __CONN_BLOCK_RULES_H
#define __CONN_BLOCK_RULES_H


int conn_block_init(struct proc_dir_entry *proc_parent);
void conn_block_exit(struct proc_dir_entry *proc_parent);
bool conn_block_check(__u32 ip);
bool conn_block_check_v6(struct in6_addr *ip);
int add_conn_block_rules(__u32 ip);

#endif /* __CONN_BLOCK_H */

