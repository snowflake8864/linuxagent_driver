#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/capability.h>
#include "core/kvd_core.h"
#include "khookframe.h"
#include "kvd_sysfs.h"


extern bool can_sysfs_store(void);

/////////////////////////////////////////////////////////////////////////////
static ssize_t vsec_sysfs_show(struct kobject *kobj,
					struct attribute *attr,char *buf)
{
	struct vsec_sysfs_entry* entry = NULL;
	entry = container_of(attr,struct vsec_sysfs_entry,attr);	
	
	if(!entry->show) {
		return -EIO;
	}
	
	return entry->show(kobj,attr,buf);
}

static ssize_t vsec_sysfs_store(struct kobject* kobj, struct attribute *attr,
	      					const char * buf, size_t len)
{
	struct vsec_sysfs_entry* entry = NULL;
	entry = container_of(attr,struct vsec_sysfs_entry,attr);	
	
	if(!entry->store) {
		return -EIO;
	}

	//只有具备root权限的用户才能写
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	
    //run_mode用于设备运行时模式，我们对该文件的写入不做验证
    //不然的话，我们无法手动开启白盒测试模式
    if(strcmp(attr->name,"run_mode") &&
        (!can_sysfs_store()))
    {
        return -EACCES;
    }

	return entry->store(kobj,attr,buf,len);
}
 
static struct sysfs_ops vsec_sysfs_ops = {
	.show = vsec_sysfs_show,
	.store = vsec_sysfs_store,
};
 
static void obj_release(struct kobject *kobj)
{
	LOG_INFO("release %s kobject!\n",
			kobj->name);
	kfree(kobj);
}
 
struct kobj_type sysfs_ktype = {
	.release = obj_release,
	.sysfs_ops = &vsec_sysfs_ops,
};

static struct kobject* vsec_kobj = NULL;
 
struct kobject* vsec_sysfs_sub_init_add(const char* name,
                    struct kobj_type* ktype)
{
	int rc = -EINVAL;
	struct kobject* kobj = NULL;

	if(!name) {
		kobj = ERR_PTR(rc);
		return kobj;
	}

	if (!ktype)
		ktype = &sysfs_ktype;

	if(!ktype->sysfs_ops) {
		ktype->sysfs_ops = &vsec_sysfs_ops;
	}

	if(!ktype->release) {
		ktype->release = obj_release;
	}

	rc = -ENOMEM;
	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if(!kobj) {
		kobj = ERR_PTR(rc);
		return kobj;
	}

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		kobject_init(kobj,ktype);
		rc = kobject_add(kobj,vsec_kobj,name);
	#else
		kobject_set_name(kobj,name);
		kobject_init(kobj);
		kobj->parent = vsec_kobj;
		kobj->ktype = ktype;
		rc = kobject_add(kobj);
	#endif

	if(rc && kobj) {
		kobject_put(kobj);
		kobj = ERR_PTR(rc);
	}

	return kobj;
}

void vsec_sysfs_sub_del(struct kobject* kobj)
{
	if(kobj) {
		if(kobj->parent) {
			kobject_put(kobj->parent);
			kobj->parent = NULL;
		}

		kobject_del(kobj);
		kobject_put(kobj);
	}
}

int vsec_sysfs_create_group_binfile(struct kobject *kobj,
			struct attribute_group *grp,
			struct bin_attribute **bin_attrs)
{
	int retval = 0;
	int idx = 0;

	if (!kobj || (!grp && !bin_attrs)) {
		retval = -EINVAL;
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
	if (grp && grp->bin_attrs == bin_attrs)
		bin_attrs = NULL;
#endif

	if (grp) {
		retval = sysfs_create_group(kobj, grp);
		if (retval)
			goto out;
	}

	while (bin_attrs && bin_attrs[idx]) {
		retval = sysfs_create_bin_file(kobj, bin_attrs[idx]);
		if (retval)
			goto bin_attr_out;
		idx++;
	}

	return retval;

bin_attr_out:
	while (idx > 0) {
		idx--;
		sysfs_remove_bin_file(kobj, bin_attrs[idx]);
	}
	sysfs_remove_group(kobj, grp);
out:
	return retval;
}

void vsec_sysfs_remove_group_binfile(struct kobject *kobj,
			struct attribute_group *grp,
			struct bin_attribute **bin_attrs)
{
	int idx = 0;

	if (!kobj)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
	if (grp && bin_attrs && grp->bin_attrs == bin_attrs)
		bin_attrs = NULL;
#endif

	if (grp)
		sysfs_remove_group(kobj, grp);

	while (bin_attrs && bin_attrs[idx]) {
		sysfs_remove_bin_file(kobj, bin_attrs[idx]);
		idx++;
	}
}


int vsec_sysfs_init(const char* name,
            struct attribute_group* def_attr_group)
{
    int rc = 0;
    struct kobject* kobj = NULL;

    if(!name || !def_attr_group) {
        rc = -EINVAL;
        goto out;
    }

	kobj = kzalloc(sizeof(struct kobject),GFP_KERNEL);
	if(kobj == NULL)
	{
		LOG_ERROR("out of memory\n");
		rc = -ENOMEM;
        goto out;
	}

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
		kobject_init(kobj,&sysfs_ktype);
		rc = kobject_add(kobj,NULL,name);
	#else
		kobject_set_name(kobj,name);
		kobject_init(kobj);
		kobj->ktype = &sysfs_ktype;
		rc = kobject_add(kobj);
	#endif

	if(rc != 0)
	{
		LOG_ERROR("kobject add failed,rc: %d\n",rc);
		goto kobj_exit;
	}

    rc = sysfs_create_group(kobj,def_attr_group);
    if (rc) {
        LOG_ERROR("create default attribute group failed, rc: %d\n", rc);
        goto kobj_exit;
    }

    vsec_kobj = kobj;
    return rc;

kobj_exit:
	kobject_put(kobj);
out:
	return rc;
}
 
void vsec_sysfs_uninit(void)
{
	kobject_del(vsec_kobj);
	kobject_put(vsec_kobj);
    vsec_kobj = NULL;
}

