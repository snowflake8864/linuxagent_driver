#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/slab.h>  //kmalloc,kfree

#include "utils.h"
#include "var_proc.h"
#include "defense/defense_inner.h"

int __var_scalar_build(char *buf, size_t buf_sz, void *info)
{
	struct var_desc *vdesc = (struct var_desc *)info;
 	
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }
 
	if(buf_sz < 12)
		return -EINVAL;
	
	switch(vdesc->size)
	{
	case 1:
		sprintf(buf, "%d\n", (int)(*(s8 *)vdesc->varp));
		break;
	case 2:
		sprintf(buf, "%d\n", (int)(*(s16 *)vdesc->varp));
		break;
	case 4:
		sprintf(buf, "%ld\n", (long)(*(s32 *)vdesc->varp));
		break;
#ifdef CONFIG_64BIT
	case 8:
		sprintf(buf, "%ld\n", (long)(*(s64 *)vdesc->varp));
		break;
#endif
	default:
		return -EINVAL;
	}
	
	return 0;
}

int __var_scalar_parse(const char *line, void *info)
{
	struct var_desc *vdesc = (struct var_desc *)info;
	long val = 0;
	
	if(sscanf(line, "%ld", &val) != 1)
		return -EINVAL;
	
	if((val < vdesc->min) || (val > vdesc->max))
		return -EINVAL;
	
	switch(vdesc->size)
	{
	case 1:
		*(s8 *)vdesc->varp = (s8)val;;
		break;
	case 2:
		*(s16 *)vdesc->varp = (s16)val;;
		break;
	case 4:
		*(s32 *)vdesc->varp = (s32)val;;
		break;
#ifdef CONFIG_64BIT
	case 8:
		*(s64 *)vdesc->varp = (s64)val;;
		break;
#endif
	default:
		return -EINVAL;
	}

	return 0;
}

static int var_proc_open(struct inode *inode, struct file *file)
{
	struct var_proc_info *vinfo = (struct var_proc_info *)OSEC_PDE_DATA(inode);
	if (!try_module_get(vinfo->owner))
		return -ENODEV;
	file->private_data = false;
	return 0;
}

static int var_proc_release(struct inode *inode, struct file *file)
{
	struct var_proc_info *vinfo = (struct var_proc_info *)OSEC_PDE_DATA(inode);
	module_put(vinfo->owner);
	return 0;
}

static ssize_t var_proc_read(struct file *file, char __user *data, size_t count, loff_t *f_pos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	struct var_proc_info *vinfo = (struct var_proc_info *)OSEC_PDE_DATA(inode);
	char *buf;
	size_t buf_sz = 4095;
	size_t len;
	int ret;
	int retv = count;

	if(vinfo->build == NULL)
		return -ENOTTY;

	if(file->private_data)
		return 0;
	
	if((buf = (char *)kmalloc(buf_sz + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	
	if((ret = vinfo->build(buf, buf_sz, vinfo->data)) < 0)
	{
		retv = ret;
		goto out;
	}
	len = strlen(buf);
	if(count < len)
		len = count;
	if(copy_to_user(data, buf, len))
	{
		retv = -EFAULT;
		goto out;
	}
	file->private_data = (void *)true;
	
	retv = len;
out:
	kfree(buf);
	return retv;
}

static ssize_t var_proc_write(struct file *file, const char __user *data, size_t count, loff_t *f_pos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	struct var_proc_info *vinfo = (struct var_proc_info *)OSEC_PDE_DATA(inode);
	char *buf;
	int retv = count;
	int ret;

	if(vinfo->parse == NULL)
		return -ENOTTY;

	if((buf = (char *)kmalloc(count + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	
	if(copy_from_user(buf, data, count))
	{
		retv = -EFAULT;
		goto out;
	}
	buf[count] = '\0';
	
	if(!file->private_data)
	{
		if((ret = vinfo->parse(buf, vinfo->data)) < 0)
		{
			retv = ret;
			goto out;
		}
	}

out:
	kfree(buf);
	return retv;
}

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static const struct proc_ops var_proc_fops =
{
//	.owner   = THIS_MODULE,
	.proc_open    = var_proc_open,
	.proc_release = var_proc_release,
	.proc_read    = var_proc_read,
	.proc_write   = var_proc_write,
    .proc_lseek   = default_llseek,
};
#else
static const struct file_operations var_proc_fops =
{
	.owner   = THIS_MODULE,
	.open    = var_proc_open,
	.release = var_proc_release,
	.read    = var_proc_read,
	.write   = var_proc_write,
    .llseek   = default_llseek,
};
#endif



struct proc_dir_entry *__var_proc_create(
		const char *name, struct proc_dir_entry *parent,
		struct var_proc_info *vinfo,
		struct module *owner)
{
	int mode = 0;

	if(vinfo->build)
		mode |= 0444;
	if(vinfo->parse)
		mode |= 0200;
	vinfo->owner = owner;

	return proc_create_data((name), mode, (parent), &var_proc_fops, vinfo);
}
EXPORT_SYMBOL(__var_proc_create);
EXPORT_SYMBOL(__var_scalar_parse);
EXPORT_SYMBOL(__var_scalar_build);
