#ifndef __VAR_PROC_H
#define __VAR_PROC_H

#include <linux/module.h>
#include <linux/proc_fs.h>

struct var_proc_info
{
	int (*parse)(const char *, void *);
	int (*build)(char *, size_t, void *);
	void *data;
	struct module *owner;
};

struct var_desc
{
	void *varp;
	int   size;
	long  min;
	long  max;
};

struct proc_dir_entry *__var_proc_create(
		const char *name, struct proc_dir_entry *parent,
		struct var_proc_info *vinfo,
		struct module *owner);

static inline struct proc_dir_entry *var_proc_create(
		const char *name, struct proc_dir_entry *parent,
		struct var_proc_info *vinfo)
{
	return __var_proc_create(name, parent, vinfo, THIS_MODULE);
}

static inline void var_proc_remove(const char *name, struct proc_dir_entry *parent)
{
	remove_proc_entry(name, parent);
}

int __var_scalar_parse(const char *line, void *info);
int __var_scalar_build(char *buf, size_t buf_sz, void *info);

#define VAR_PROC_FS_CREATE(var, min, max, name, parent)	\
	do {												\
		static struct var_desc __var_desc =				\
			{ &(var), sizeof(var), (min), (max), };		\
		static struct var_proc_info __var_info = {		\
				__var_scalar_parse,						\
				__var_scalar_build,						\
				&__var_desc, };							\
		var_proc_create((name), (parent),				\
				&__var_info);							\
	} while(0)

#define VAR_PROC_FS_REMOVE(name, parent)				\
	do {												\
		var_proc_remove((name), (parent));				\
	} while(0)

#endif /* __VAR_PROC_H */
