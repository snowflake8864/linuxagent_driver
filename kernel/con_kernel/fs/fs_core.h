/*
 *fs_core.h: 2019-06-21 created by qudreams
 *export public function for file
 */
#ifndef FS_CORE_H
#define FS_CORE_H

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

struct file;
struct kstat;
struct path;
uint64_t get_fs_magic(struct path* path);
int is_valid_fs(struct path* path);
int is_valid_path(struct path* path);
int is_file_write(struct file* filp);
int get_stat_by_file(struct file* filp,struct kstat* stat);
int get_stat_by_path(struct path* path,struct kstat* stat);
int get_lookup_flags(int flag,int* lookup_flags);
//flags-->is not look_up flags,it's the flags like open flags:0,or O_NOFOLLOW
int get_vfs_stat(int dfd,const char __user *name,unsigned flags,struct kstat *stat);
char* get_kernel_pathname_stat(int dfd,const char __user* pathname,
            unsigned lookup_flags,struct kstat *stat);

struct mount_event_info {
    char dev_name[128];
    char mnt_path[256];
};
int register_mount_event_notify(struct notifier_block *notifier);
void unregister_mount_event_notify(struct notifier_block* notifier);

#endif
