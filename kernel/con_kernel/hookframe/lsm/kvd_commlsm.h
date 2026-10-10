#ifndef __KVD_COMMLSM_H
#define __KVD_COMMLSM_H
#include <linux/types.h>
#include <linux/version.h>
#include <linux/security.h>

/* 定义兼容类型 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
    typedef struct {
        uid_t val;
    } kuid_t;

    typedef struct {
        gid_t val;
    } kgid_t;
#endif

struct kvd_security_operations {
    struct list_head list;
    const char *name;

    int (*ptrace_access_check)(struct task_struct *child,
            unsigned int mode);

    int (*bprm_check_security)(struct linux_binprm *bprm);

    int (*sb_kern_mount)(struct super_block *sb);
    int (*sb_mount)(const char *dev_name, const struct path *path,
            const char *type, unsigned long flags, void *data);

#ifdef CONFIG_SECURITY_PATH
    int (*path_unlink)(const struct path *dir, struct dentry *dentry);
    int (*path_mkdir)(const struct path *dir, struct dentry *dentry,
            umode_t mode);
    int (*path_rmdir)(const struct path *dir, struct dentry *dentry);
    int (*path_mknod)(const struct path *dir, struct dentry *dentry,
            umode_t mode, unsigned int dev);
    int (*path_truncate)(const struct path *path);
    int (*path_symlink)(const struct path *dir, struct dentry *dentry,
            const char *old_name);
    int (*path_link)(struct dentry *old_dentry,
            const struct path *new_dir, struct dentry *new_dentry);
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
    int (*path_rename)(const struct path *old_dir, struct dentry *old_dentry,
            const struct path *new_dir, struct dentry *new_dentry, unsigned int flags);
  #else
    int (*path_rename)(const struct path *old_dir, struct dentry *old_dentry,
            const struct path *new_dir, struct dentry *new_dentry);
  #endif
    int (*path_chmod)(const struct path *path, umode_t mode);
    int (*path_chown)(const struct path *path, kuid_t uid, kgid_t gid);
#endif

    void (*inode_free_security)(struct inode *inode);
    int (*inode_create)(struct inode *dir, struct dentry *dentry, umode_t mode);
    int (*inode_link)(struct dentry *old_dentry, struct inode *dir,
            struct dentry *new_dentry);
    int (*inode_mknod)(struct inode *dir, struct dentry *dentry,
            umode_t mode, dev_t dev);
    int (*inode_symlink)(struct inode *dir, struct dentry *dentry,
            const char *old_name);
    int (*inode_unlink)(struct inode *dir, struct dentry *dentry);
    int (*inode_mkdir)(struct inode *dir, struct dentry *dentry,
            umode_t mode);
    int (*inode_rmdir)(struct inode *dir, struct dentry *dentry);
    int (*inode_rename)(struct inode *old_dir, struct dentry *old_dentry,
            struct inode *new_dir, struct dentry *new_dentry);
    int (*inode_setattr)(struct dentry *dentry, struct iattr *attr);
    void (*file_free_security)(struct file *file);
    int (*file_ioctl)(struct file *file, unsigned int cmd,
            unsigned long arg);
    int (*mmap_file)(struct file *file, unsigned long reqprot,
            unsigned long prot, unsigned long flags);
    int (*file_open)(struct file *file);

    void (*task_free)(struct task_struct *task);
    int (*task_kill)(struct task_struct *p, struct siginfo *info,
            int sig);

#ifdef CONFIG_SECURITY_NETWORK
    int (*socket_create)(int family, int type, int protocol, int kern);
    int (*socket_post_create)(struct socket *sock, int family,
            int type, int protocol, int kern);
    int (*socket_accept)(struct socket *sock, struct socket *newsock);
    int (*socket_bind)(struct socket *sock, struct sockaddr *address,
            int addrlen);
    int (*socket_connect)(struct socket *sock, struct sockaddr *address,
            int addrlen);
    int (*socket_sendmsg)(struct socket *sock, int size);
    int (*socket_recvmsg)(struct socket *sock, int size, int flags);
    void (*sk_free_security)(struct sock *sk);
#endif

    //KWS
    void (*wfile_close)(const char *filename, const struct kstat *kst);
};

/* 这两个函数只在模块初始化/退出清理时调用
 * 全局调用一次即可 */
int kvd_init_commlsm_hook(void);
void kvd_uninit_commlsm_hook(void);

/* 注册/注销函数请确保在(kvd_init_commlsm_hook)调用后 */
int kvd_register_commlsm_hook(struct kvd_security_operations *hooks);
void kvd_unregister_commlsm_hook(struct kvd_security_operations *hooks);

/* 使能函数请确保在(kvd_init_commlsm_hook)调用后
 * 1. 开启成功模块引用计数加1, 防止使用中卸载模块
 * 2. 关闭成功模块引用计数减1, 确保模块引用计数正常 */
int kvd_enable_commlsm_hook(void);
void kvd_disable_commlsm_hook(void);

int kvd_commlsm_is_enabled(void);
char * kvd_commlsm_hook_mode(void);

/* 强制开启lsm hook并设置: _hook_lsm_on, __hook_mode */
int kvd_enable_commlsm_forced(void);

enum {
    COMMLSM_TYPE_KWS = 0,
    COMMLSM_TYPE_UOS,
};

enum {
    LSM_STATE_INITED = 0,
    LSM_STATE_ENABLED,
};

#endif
