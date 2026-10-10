/*
 *path_security.h: 2019-06-24 created by qudreams
 *Copyright to qianxin enterprise security group
 *
 *path_security.h 主要定义用于自保检查的函数
 *Note:
 *调用本头文件中的函数时自保肯定已经开启了，否则应当先检查自保是否开启
 *然后再调用本头文件中定义的函数，本头文件中定义的函数不再检查自保是否开启
 */
#ifndef PATH_SECURITY_H
#define PATH_SECURITY_H

#include <linux/fs.h>

int may_open_path(int dfd,const char __user* pathname,int flags);
int may_open_path_ex(int dfd,const char __user* pathname,int flags);
int may_unlink_path(const char* pathname,int is_dir);
int may_rmdir(const char* pathname);
int may_mkdir(int dfd,const char __user* pathname);
int may_truncate_path(const char* pathname);
#if 0
int may_rename_path(const char* koldname,int newdfd,
            const char __user* newname,int is_dir);
#else            
int may_rename_path(const char* koldname,int newdfd,
        const char __user* oldname, const char __user* newname, int is_dir);
#endif
int may_chmod_path(const char* pathname,int is_dir);
int may_chown_path(const char* pathname,int is_dir);
int may_ioctl_path(const char* pathname,int is_dir);
int may_close_path(const char* pathname,int is_dir);
int may_link_path(const char* koldname,int newdfd,
            const char __user* newname,
            int lookup_flags,int is_dir);

#endif
