#ifndef __MD5HASH_MD5_RULES_TBL_H__
#define __MD5HASH_MD5_RULES_TBL_H__

int find_md5_action(const u8 *md5); 
int md5_rules_init(struct proc_dir_entry *proc_parent); 
void md5_rules_exit(struct proc_dir_entry *proc_parent); 

#endif
