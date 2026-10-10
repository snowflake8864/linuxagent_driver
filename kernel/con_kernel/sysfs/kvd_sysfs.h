/*
 * sysfs.h: 2019-08-25 created by qudreams
 * export /sys file-system interface
 */

#ifndef __vsec_SYSFS_H
#define __vsec_SYSFS_H

#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/version.h>

/* NOTE: __BIN_ATTR is a macro, defined in linux/sysfs.h
 * Mybe you have seen that #include <linux/sysfs.h> has been there above
 * So, if __BIN_ATTR still undefined, it's because the linux kernel version
 * too low. We define it here.
 */
#if !defined(__BIN_ATTR) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
/* macros to create static binary attributes easier */
#define __BIN_ATTR(_name, _mode, _read, _write, _size) {                \
        .attr = { .name = __stringify(_name), .mode = _mode },          \
        .read   = _read,                                                \
        .write  = _write,                                               \
        .size   = _size,                                                \
}
#endif

#if defined(RHEL_RELEASE_CODE) && defined(RHEL_RELEASE_VERSION)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,10)

/*
 * Nightmare! RHEL enhanced linux 2.6.x with features
 * which just appear in newer versions
 */
#define RHEL_BIN_ATTR_COMPAT_2635

#endif
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)) || \
     defined RHEL_BIN_ATTR_COMPAT_2635

#define bin_attr_read_prototype(function_name) \
ssize_t function_name(struct file * file, struct kobject * kobj, \
                      struct bin_attribute * bin_attr, char * buf, \
                      loff_t offset, size_t count)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)

#define bin_attr_read_prototype(function_name) \
ssize_t function_name(struct kobject * kobj, struct bin_attribute * bin_attr, \
                      char * buf, loff_t offset, size_t count)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)

#define bin_attr_read_prototype(function_name) \
ssize_t function_name(struct kobject * kobj, char * buf, \
                      loff_t offset, size_t count)
#else
#error "linux kernel 2.6.18 is the lowest supported version!!"
#endif

struct vsec_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct kobject*,struct attribute*,char*);
	ssize_t (*store)(struct kobject*, struct attribute*,
	      			const char*,size_t);
};

int vsec_sysfs_init(const char* name,
    struct attribute_group* def_attr_group);
void vsec_sysfs_uninit(void);

struct kobject* vsec_sysfs_sub_init_add(const char* name,
                    struct kobj_type* ktype);
void vsec_sysfs_sub_del(struct kobject* kobj);

int vsec_sysfs_create_group_binfile(struct kobject *kobj,
		struct attribute_group *grp,
		struct bin_attribute **bin_attrs);
void vsec_sysfs_remove_group_binfile(struct kobject *kobj,
		struct attribute_group *grp,
		struct bin_attribute **bin_attrs);

#endif //
