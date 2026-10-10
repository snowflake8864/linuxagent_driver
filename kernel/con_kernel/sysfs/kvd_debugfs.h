#ifndef KOSEC_DEBUGFS_H
#define KOSEC_DEBUGFS_H

#include <linux/types.h>

int vsec_debugfs_init(void);
void vsec_debugfs_uninit(void);

struct dentry;
struct file_operations;
struct dentry* vsec_debugfs_create_file(const char* name,mode_t mode,
			    void *data,const struct file_operations *fops);
#define vsec_debugfs_remove  debugfs_remove


struct list_head;
struct list_head *vsec_seq_list_start(struct list_head *head, loff_t pos);
struct list_head *vsec_seq_list_start_head(struct list_head *head, loff_t pos);
struct list_head *vsec_seq_list_next(void *v, struct list_head *head, loff_t *ppos);

#endif
