#include "sysfs/kvd_sysfs.h"
#include "core/kvd_version.h"
#include "khookframe.h"

static ssize_t vd_version_show(struct kobject *kobj,struct attribute *attr,char *buf)
{
	ssize_t ret;
    const char* mod_ver = kvd_get_version();
	ret = sprintf(buf,"name: %s\n%s\n",
                THIS_MODULE->name,mod_ver);
	return ret;
}
 
struct kvd_sysfs_entry vd_version = 
	__ATTR(version,S_IRUGO,vd_version_show,NULL);

extern unsigned long debug_flag; 
static ssize_t vd_debug_show(struct kobject* kobj,struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
    ret = sprintf(buf,"%lu",debug_flag);
    return ret;
}

static ssize_t vd_debug_store(struct kobject* kobj, struct attribute *attr,
	      					const char * buf, size_t len)
{
	char c;
	unsigned long val = 0;

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

	val = c - '0';
	(void)xchg(&debug_flag,val);
	LOG_DEBUG("set debug_flag: %lu\n",val);
	
	return len;
}

struct kvd_sysfs_entry vd_debug = 
	__ATTR(debug,S_IRUGO | S_IWUSR,vd_debug_show,vd_debug_store);

static ssize_t vd_switch_store(struct kobject* kobj, struct attribute *attr,
	      					const char * buf, size_t len)
{
	char c;
	unsigned long val = 0;

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

	val = c - '0';
	if(val) {
		kvd_hook_syscalls();
	} else {
		kvd_cleanup_syscalls();
	}
	LOG_DEBUG("set debug_flag: %lu\n",val);
	
	return len;
}

struct kvd_sysfs_entry vd_switch = 
	__ATTR(switch,S_IWUSR,NULL,vd_switch_store);

static struct attribute* sysfs_def_attr[] = {
	&vd_debug.attr,
	&vd_version.attr,
	&vd_switch.attr,
	NULL,
};

static struct attribute_group def_attr_group = {
	.attrs = sysfs_def_attr
};


void test_sysfs_init(void)
{
    kvd_sysfs_init(KMOD_NAME,&def_attr_group);
}

void test_sysfs_uninit(void)
{
    kvd_sysfs_uninit();
}
