#include <linux/module.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/list.h>
#include "core/kvd_core.h"
#include "gnHead.h"
#include "kvd_debugfs.h"

static struct dentry *vsec_debugfs_rootdir;

struct dentry* vsec_debugfs_create_file(const char* name,mode_t mode,
					    void *data,const struct file_operations *fops)
{
    return debugfs_create_file(name,mode,
				vsec_debugfs_rootdir,data,fops);
}

void vsec_debugfs_uninit(void)
{
	LOG_INFO("removing kvd debugfs dirs\n");
    if(vsec_debugfs_rootdir)
	    debugfs_remove(vsec_debugfs_rootdir);
}

int vsec_debugfs_init(void)
{
    int rc = 0;
    struct dentry* dir = NULL;

	dir = debugfs_create_dir(KOSEC_SYSFS_NAME,NULL);
    if(KVD_IS_ERR_OR_NULL(dir)) { 
        rc = dir ? PTR_ERR(dir) : -EFAULT; 
    } else {
		vsec_debugfs_rootdir = dir;
	}

    return rc;
}

struct list_head *vsec_seq_list_start(struct list_head *head, loff_t pos)
{
	struct list_head *lh;

	list_for_each(lh, head)
		if (pos-- == 0)
			return lh;

	return NULL;
}

struct list_head *vsec_seq_list_start_head(struct list_head *head, loff_t pos)
{
	if (!pos)
		return head;

	return vsec_seq_list_start(head, pos - 1);
}

struct list_head *vsec_seq_list_next(void *v, struct list_head *head, loff_t *ppos)
{
	struct list_head *lh;

	lh = ((struct list_head *)v)->next;
	++*ppos;
	return lh == head ? NULL : lh;
}

