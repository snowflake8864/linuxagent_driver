#ifndef __DPI_TRUE_PROCESS_TBL_H__
#define __DPI_TRUE_PROCESS_TBL_H__

int find_true_process(const u8 *md5, const u8 rule_id, const u8 rule_type);
int true_process_init(struct proc_dir_entry *proc_parent); 
void true_process_exit(struct proc_dir_entry *proc_parent); 

#endif
