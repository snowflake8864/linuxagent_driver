#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/capability.h>
#include "netlink/netlink.h"
#include "cdev/cdev.h"
#include "khookframe.h"
#include "core/kvd_version.h"
#include "core/gnkernel.h"
#include "kvd_sysfs.h"
#include "kvd_debugfs.h"
#include "gnHead.h"

extern const char* get_kmod_pathname(unsigned* plen);
static ssize_t vd_version_show(struct kobject *kobj,struct attribute *attr,char *buf)
{
	ssize_t ret;
	unsigned len = 0;
	unsigned remain_len = 0;
    const char* mod_ver = kvd_get_version();
	const char* kmod_path = get_kmod_pathname(&len);

	ret = sprintf(buf,"name: %s\n%s"
				"srcversion: %s\n",
                THIS_MODULE->name,mod_ver,
				THIS_MODULE->srcversion);
	if(ret <= 0 || !kmod_path) { return ret; }

	remain_len = PAGE_SIZE  - ret;
	if(len < (remain_len - sizeof("path: \n")))
	{
		ret += sprintf(buf + ret,
				"path: %s\n",kmod_path);
	}

	return ret;
}
 
struct vsec_sysfs_entry vd_version = 
	__ATTR(version,S_IRUGO,vd_version_show,NULL);


static ssize_t vd_proto_show(struct kobject *kobj,struct attribute *attr,char *buf)
{
	ssize_t ret;
	char tmp[256] = {0};
    int group = get_netlink_group();
    const char* cdev_name = vsec_cdev_name();
	
	//字符设备名可能为空,因为只有密标功能才用
	//但密标功能模块可能根本就没有在编译时开启
	if(cdev_name) {
		snprintf(tmp,sizeof(tmp) - 1,
			"cdev:%s\n",cdev_name);
	}

	ret = sprintf(buf,"netlink:%d\n%s",
				group,tmp);
	return ret;
}
 
struct vsec_sysfs_entry vd_proto = 
	__ATTR(proto,S_IRUGO,vd_proto_show,NULL);

extern const char* __hook_mode;
extern bool vsec_is_kws_lsm_enabled(void);
static ssize_t vd_hook_mode_show(struct kobject *kobj,
                        struct attribute *attr,char *buf)
{
	ssize_t ret;

	ret = sprintf(buf,"%s\n",
                __hook_mode);
	return ret;
}
 
struct vsec_sysfs_entry vd_hook_mode = 
	__ATTR(hook_mode,S_IRUGO,vd_hook_mode_show,NULL);

extern int set_run_mode(const char* mode,size_t len);
static ssize_t vd_run_mode_set(struct kobject* kobj,
						struct attribute *attr,
						const char * buf, size_t len)
{
	int rc = 0;
	if(!buf || !len) {
		return -EINVAL;
	}

	rc = set_run_mode(buf,len);
	if(rc) { return rc; }

	return len;
}

static struct vsec_sysfs_entry vd_run_mode = 
		__ATTR(run_mode,S_IWUSR,NULL,vd_run_mode_set);


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

struct vsec_sysfs_entry vd_debug = 
	__ATTR(debug,S_IRUGO | S_IWUSR,vd_debug_show,vd_debug_store);

extern u_int warn_dump_stack;
static ssize_t warn_dump_stack_show(struct kobject* kobj,struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
    ret = sprintf(buf,"%u",warn_dump_stack);
    return ret;
}


static ssize_t warn_dump_stack_store(struct kobject* kobj, struct attribute *attr,
	      					const char * buf, size_t len)
{
	char c;
	u_int val = 0;

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
	(void)xchg(&warn_dump_stack,val);
	
	return len;
}

struct vsec_sysfs_entry dump_stack_entry = 
	__ATTR(warn_dump_stack,S_IRUGO | S_IWUSR,
            warn_dump_stack_show,
            warn_dump_stack_store);
extern const char* vsec_mmc_name(void);

static ssize_t vd_mmc_show(struct kobject *kobj,struct attribute *attr,char *buf)
{
	ssize_t ret = 0;
	const char* mmc_name = NULL;

	mmc_name = vsec_mmc_name();
	if(mmc_name) {
		ret = sprintf(buf,
				"%s",mmc_name);
	}

	return ret;
}
 
struct vsec_sysfs_entry vd_mmc_entry = 
	__ATTR(mmc,S_IRUGO,vd_mmc_show,NULL);

extern int vsec_mmc_get_stats(struct vsec_pack_stats* st_in,
							struct vsec_pack_stats* st_out);

extern int vsec_cdev_get_stats(struct vsec_pack_stats* st_in,
							struct vsec_pack_stats* st_out);
extern int vsec_netlink_get_stats(struct vsec_pack_stats* st_in,
							struct vsec_pack_stats* st_out);

static ssize_t vd_stats_show(struct kobject *kobj,struct attribute *attr,char *buf)
{
	int rc = 0;
	ssize_t n = 0;
	struct vsec_pack_stats st_in;
	struct vsec_pack_stats st_out;

	n += sprintf(buf,"Proto\tInTotals\tInDrops\tOutTotals\tOutDrops\n");

	rc = vsec_mmc_get_stats(&st_in,&st_out);
	if(rc == 0) {
		n += sprintf(buf + n,
				"mmc:\t%ld\t%ld\t%ld\t%ld\n",
				st_in.packets,st_in.drops,
				st_out.packets,st_out.drops);
	}

	rc = vsec_cdev_get_stats(&st_in,&st_out);
	if(rc == 0) {
		n += sprintf(buf + n,
				"cdev:\t%ld\t%ld\t%ld\t%ld\n",
				st_in.packets,st_in.drops,
				st_out.packets,st_out.drops);
	}

	rc = vsec_netlink_get_stats(&st_in,&st_out);
	if(rc == 0) {
		n += sprintf(buf + n,
				"netlink:\t%ld\t%ld\t%ld\t%ld\n",
				st_in.packets,st_in.drops,
				st_out.packets,st_out.drops);
	}

	return n;
}
 
struct vsec_sysfs_entry vd_stats_entry = 
	__ATTR(stats,S_IRUGO,vd_stats_show,NULL);

static ssize_t use_syshook_show(struct kobject *kobj,struct attribute *attr,char *buf)
{
    ssize_t ret = 0;

    ret = sprintf(buf,"%d", kvd_syscall_hook_forced());

    return ret;
}

struct vsec_sysfs_entry use_syshook_entry = 
	__ATTR(force_syscall_hook,S_IRUGO,use_syshook_show,NULL);
		
static struct attribute* sysfs_def_attr[] = {
	&vd_proto.attr,
	&vd_debug.attr,
	&vd_version.attr,
	&vd_hook_mode.attr,
	&vd_run_mode.attr,
	&dump_stack_entry.attr,
	&vd_mmc_entry.attr,
	&vd_stats_entry.attr,
	&use_syshook_entry.attr,
	NULL,
};

static struct attribute_group def_attr_group = {
	.attrs = sysfs_def_attr
};

extern bool is_white_box_test(void);
bool can_sysfs_store(void)
{
    //白盒测试模式下或者是我们自己的进程
    //我们允许对自保sysfs文件写入
    return (is_white_box_test() ||
        is_self_process());
}

/////////////////////////////////////////////////////////////////////////////

int vsec_sysfs_core_init(void)
{
    int rc = 0;

    rc = vsec_sysfs_init(KOSEC_SYSFS_NAME,
                    &def_attr_group);
	if(rc) { return rc; }
#if defined(CONFIG_DEBUG_FS)
	rc = vsec_debugfs_init();
	if(rc) { vsec_sysfs_uninit(); }
#endif

	return rc;
}
 
void vsec_sysfs_core_uninit(void)
{
	vsec_debugfs_uninit();
	vsec_sysfs_uninit();
	LOG_INFO("uninit sysfs\n");
}

