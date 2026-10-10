#include <linux/types.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/err.h>
#include <linux/kobject.h>
#include "sysfs/kvd_sysfs.h"
#include "core/gnkernel.h"
#include "core/kvd_core.h"
#include "defense_sysfs.h"
#include "defense_inner.h"
#include "gnHead.h"

static ssize_t defense_switch_show(struct kobject* kobj,
                    struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
    ret = sprintf(buf,"%d",
        is_defense_enable());
    return ret;
}

static ssize_t defense_switch_store(struct kobject* kobj, 
                        struct attribute *attr,
	      				const char * buf, size_t len)
{
	char c;
    int bon = 0;

	if(!buf || !len) {
		return -EINVAL;
	}

	if(len > 1) {
		return -E2BIG;
	}

	c = buf[0];
	if(c != '0' && c != '1') {
		return -EINVAL;
	}

	bon = (c == '0' ? 0 : 1);
    if(bon) {
        turn_on_defense();
    } else {
        turn_off_defense();
    }
	
	return len;
}

static struct vsec_sysfs_entry switch_entry = 
	    __ATTR(switch,S_IRUGO | S_IWUSR,defense_switch_show,defense_switch_store);


static ssize_t defense_white_exes_show(struct kobject* kobj,
                    struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
	
	ret = get_defense_white_exes(buf,
				PAGE_SIZE - 1);
    return ret;
}

static struct vsec_sysfs_entry white_exes_entry = 
	    __ATTR(white_exes,S_IRUGO,defense_white_exes_show,NULL);


static ssize_t defense_protect_paths_show(struct kobject* kobj,
                    struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
	
	ret = get_defense_protect_paths(buf,
				PAGE_SIZE - 1);
    return ret;
}

static struct vsec_sysfs_entry protect_paths_entry = 
	    __ATTR(protect_paths,S_IRUGO,defense_protect_paths_show,NULL);


static ssize_t defense_hold_pids_show(struct kobject* kobj,
                    struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
	
	ret = get_all_hold_procs(buf,
				PAGE_SIZE - 1);
    return ret;
}

static struct vsec_sysfs_entry hold_pids_entry = 
	    __ATTR(hold_pids,S_IRUGO,defense_hold_pids_show,NULL);

static ssize_t defense_debug_show(struct kobject* kobj,
                    struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
    ret = sprintf(buf,"%d",
        test_bit(0,&defense_debug));
    return ret;
}

static ssize_t defense_debug_store(struct kobject* kobj, 
                        struct attribute *attr,
	      				const char * buf, size_t len)
{
	char c;
    int bon = 0;

	if(!buf || !len) {
		return -EINVAL;
	}

	if(len > 1) {
		return -E2BIG;
	}

	c = buf[0];
	if(c != '0' && c != '1') {
		return -EINVAL;
	}

	bon = (c == '0' ? 0 : 1);
    defense_do_debug(bon);
	
	return len;
}

static struct vsec_sysfs_entry defense_debug_entry = 
	    __ATTR(debug,S_IRUGO | S_IWUSR,defense_debug_show,defense_debug_store);


static struct attribute* defense_def_attrs[] = {
	&switch_entry.attr,
	&white_exes_entry.attr,
	&protect_paths_entry.attr,
    &hold_pids_entry.attr,
    &defense_debug_entry.attr,
	NULL,
};

static void defense_obj_release(struct kobject *kobj)
{
	DEFENSE_LOG_INFO("release %s kobject!\n",
                kobj->name);
	kfree(kobj);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)
ATTRIBUTE_GROUPS(defense_def);
#endif

struct kobj_type defense_sysfs_ktype = {
	.release = defense_obj_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)
    .default_groups = defense_def_groups,
#else
	.default_attrs = defense_def_attrs,
#endif
};

static struct kobject* defense_kobj = NULL;

int defense_sysfs_init(void)
{
    int rc = 0;
    struct kobject* kobj = NULL;
    kobj = vsec_sysfs_sub_init_add("defense",
            &defense_sysfs_ktype);
    
    if(IS_ERR(kobj)) {
        rc = PTR_ERR(kobj);
        return rc;
    }

    defense_kobj = kobj;
    DEFENSE_LOG_INFO("init defense sysfs ok\n");
    return rc;
}

void defense_sysfs_uninit(void)
{
    if(!defense_kobj) { return; }
    vsec_sysfs_sub_del(defense_kobj);
    DEFENSE_LOG_INFO("uninit defense sysfs\n");
}
