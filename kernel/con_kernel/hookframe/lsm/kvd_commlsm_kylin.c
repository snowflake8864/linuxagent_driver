/*
 * 适用麒麟系统(CONFIG_SECURITY_KYLIN_EXTEND), KERNEL_VERSION >=
 * */
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/security_ops.h>

static unsigned long kylin_lsm_enabled = 0;

static int kylin_ptrace_access_check(struct task_struct *child,
        unsigned int mode)
{
    int rc = 0;

    call_hook_begin(ptrace_access_check);
    rc = hooks->ptrace_access_check(child, mode);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_bprm_check_security(struct linux_binprm *bprm)
{
    int rc = 0;

    call_hook_begin(bprm_check_security);
    rc = hooks->bprm_check_security(bprm);
    call_int_hook_end(rc);

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int kylin_sb_kern_mount(struct super_block *sb)
#else
static int kylin_sb_kern_mount(struct super_block *sb, int flags, void *data)
#endif
{
    int rc = 0;

    call_hook_begin(sb_kern_mount);
    rc = hooks->sb_kern_mount(sb);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_sb_mount(const char *dev_name,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
        const struct path *path,
#else
        struct path *path,
#endif
        const char *type, unsigned long flags, void *data)
{
    int rc = 0;

    call_hook_begin(sb_mount);
    rc = hooks->sb_mount(dev_name, (const struct path *)path, type, flags, data);
    call_int_hook_end(rc);

    return rc;
}

#ifdef CONFIG_SECURITY_PATH
    static int kylin_path_unlink(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *dir,
    #else
            struct path *dir,
    #endif
            struct dentry *dentry)
    {
        int rc = 0;

        call_hook_begin(path_unlink);
        rc = hooks->path_unlink((const struct path *)dir, dentry);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_path_mkdir(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *dir,
    #else
            struct path *dir,
    #endif
            struct dentry *dentry, umode_t mode)
    {
        int rc = 0;

        call_hook_begin(path_mkdir);
        rc = hooks->path_mkdir((const struct path *)dir,
                dentry, mode);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_path_rmdir(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *dir,
    #else
            struct path *dir,
    #endif
            struct dentry *dentry)
    {
        int rc = 0;

        call_hook_begin(path_rmdir);
        rc = hooks->path_rmdir((const struct path *)dir, dentry);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_path_mknod(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *dir,
    #else
            struct path *dir,
    #endif
            struct dentry *dentry, umode_t mode, unsigned int dev)
    {
        int rc = 0;

        call_hook_begin(path_mknod);
        rc = hooks->path_mknod((const struct path *)dir,
                dentry, mode, dev);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_path_truncate(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *path
    #else
            struct path *path
    #endif
            )
    {
        int rc = 0;

        call_hook_begin(path_truncate);
        rc = hooks->path_truncate((const struct path *)path);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_path_symlink(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *dir,
    #else
            struct path *dir,
    #endif
            struct dentry *dentry, const char *old_name)
    {
        int rc = 0;

        call_hook_begin(path_symlink);
        rc = hooks->path_symlink((const struct path *)dir,
                dentry, old_name);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_path_link(struct dentry *old_dentry,
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *new_dir,
    #else
            struct path *new_dir,
    #endif
            struct dentry *new_dentry)
    {
        int rc = 0;

        call_hook_begin(path_link);
        rc = hooks->path_link(old_dentry,
                (const struct path *)new_dir, new_dentry);
        call_int_hook_end(rc);

        return rc;
    }

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
    static int kylin_path_rename(const struct path *old_dir,
            struct dentry *old_dentry, const struct path *new_dir,
            struct dentry *new_dentry, unsigned int flags)
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
    static int kylin_path_rename(const struct path *old_dir,
            struct dentry *old_dentry, const struct path *new_dir,
            struct dentry *new_dentry)
    #else
    static int kylin_path_rename(struct path *old_dir,
            struct dentry *old_dentry, struct path *new_dir,
            struct dentry *new_dentry)
    #endif
    {
        int rc = 0;

        call_hook_begin(path_rename);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
        rc = hooks->path_rename(old_dir, old_dentry,
                new_dir, new_dentry, flags);
        #else
        rc = hooks->path_rename((const struct path *)old_dir,
                old_dentry, (const struct path *)new_dir,
                new_dentry);
        #endif
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_path_chmod(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *path,
    #else
            struct path *path,
    #endif
            umode_t mode)
    {
        int rc = 0;

        call_hook_begin(path_chmod);
        rc = hooks->path_chmod((const struct path *)path, mode);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_path_chown(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *path,
    #else
            struct path *path,
    #endif
            kuid_t uid, kgid_t gid)
    {
        int rc = 0;

        call_hook_begin(path_chown);
        rc = hooks->path_chown((const struct path *)path, uid, gid);
        call_int_hook_end(rc);

        return rc;
    }
#endif

static void kylin_inode_free_security(struct inode *inode)
{
    call_hook_begin(inode_free_security);
    hooks->inode_free_security(inode);
    call_void_hook_end();
}

static int kylin_inode_create(struct inode *dir,
        struct dentry *dentry, umode_t mode)
{
    int rc = 0;

    call_hook_begin(inode_create);
    rc = hooks->inode_create(dir, dentry, mode);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_inode_link(struct dentry *old_dentry, struct inode *dir,
                        struct dentry *new_dentry)
{
    int rc = 0;
    call_hook_begin(inode_link);
    rc = hooks->inode_link(old_dentry, dir,new_dentry);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_inode_mknod(struct inode *dir, struct dentry *dentry,
                        umode_t mode, dev_t dev)
{
    int rc = 0;
    call_hook_begin(inode_mknod);
    rc = hooks->inode_mknod(dir, dentry, mode, dev);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_inode_symlink(struct inode *dir, struct dentry *dentry,
                        const char *old_name)
{
    int rc = 0;
    call_hook_begin(inode_symlink);
    rc = hooks->inode_symlink(dir, dentry, old_name);
    call_int_hook_end(rc);

    return rc;
}
static int kylin_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    call_hook_begin(inode_unlink);
    rc = hooks->inode_unlink(dir, dentry);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_inode_mkdir(struct inode *dir, struct dentry *dentry,
        umode_t mode)
{
    int rc = 0;

    call_hook_begin(inode_mkdir);
    rc = hooks->inode_mkdir(dir, dentry, mode);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    call_hook_begin(inode_rmdir);
    rc = hooks->inode_rmdir(dir, dentry);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry)
{
    int rc = 0;

    call_hook_begin(inode_rename);
    rc = hooks->inode_rename(old_dir, old_dentry, new_dir, new_dentry);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    int rc = 0;

    call_hook_begin(inode_setattr);
    rc = hooks->inode_setattr(dentry, attr);
    call_int_hook_end(rc);

    return rc;
}

static void kylin_file_free_security(struct file *file)
{
    call_hook_begin(file_free_security);
    hooks->file_free_security(file);
    call_void_hook_end();
}

static int kylin_file_ioctl(struct file *file, unsigned int cmd,
        unsigned long arg)
{
    int rc = 0;

    call_hook_begin(file_ioctl);
    rc = hooks->file_ioctl(file, cmd, arg);
    call_int_hook_end(rc);

    return rc;
}

static int kylin_mmap_file(struct file *file, unsigned long reqprot,
        unsigned long prot, unsigned long flags)
{
    int rc = 0;

    call_hook_begin(mmap_file);
    rc = hooks->mmap_file(file, reqprot, prot, flags);
    call_int_hook_end(rc);

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || \
        defined(KVD_COMMLSM_FILE_OPEN)
static int kylin_file_open(struct file *file)
#else
static int kylin_file_open(struct file *file, const struct cred *cred)
#endif
{
    int rc = 0;

    call_hook_begin(file_open);
    rc = hooks->file_open(file);
    call_int_hook_end(rc);

    return rc;
}

static void kylin_task_free(struct task_struct *task)
{
    call_hook_begin(task_free);
    hooks->task_free(task);
    call_void_hook_end();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) || \
            defined(KVD_COMMLSM_TASK_KILL)
    static inline int kylin_is_info_special(struct kernel_siginfo *info)
    {
        return info <= (struct kernel_siginfo *)SEND_SIG_FORCED;
    }

static int kylin_task_kill(struct task_struct *p, struct kernel_siginfo *_info,
        int sig, const struct cred *cred)
{
    int rc = 0;
    struct siginfo *info = (struct siginfo *)_info;
    struct siginfo dup_info;

    if (!kylin_is_info_special(_info)) {
        info = &dup_info;
        memset(info, 0, sizeof(*info));
        memcpy(info, _info, sizeof(*info));
    }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
static int kylin_task_kill(struct task_struct *p, struct siginfo *info,
        int sig, const struct cred *cred)
{
    int rc = 0;
#else
static int kylin_task_kill(struct task_struct *p, struct siginfo *info,
        int sig, u32 secid)
{
    int rc = 0;
#endif

    call_hook_begin(task_kill);
    rc = hooks->task_kill(p, info, sig);
    call_int_hook_end(rc);

    return rc;
}

#ifdef CONFIG_SECURITY_NETWORK
    static int kylin_socket_create(int family, int type,
            int protocol, int kern)
    {
        int rc = 0;

        call_hook_begin(socket_create);
        rc = hooks->socket_create(family, type, protocol, kern);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_socket_post_create(struct socket *sock, int family,
            int type, int protocol, int kern)
    {
        int rc = 0;

        call_hook_begin(socket_post_create);
        rc = hooks->socket_post_create(sock, family, type, protocol, kern);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_socket_accept(struct socket *sock, struct socket *newsock)
    {
        int rc = 0;

        call_hook_begin(socket_accept);
        rc = hooks->socket_accept(sock, newsock);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_socket_bind(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        call_hook_begin(socket_bind);
        rc = hooks->socket_bind(sock, address, addrlen);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_socket_connect(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        call_hook_begin(socket_connect);
        rc = hooks->socket_connect(sock, address, addrlen);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_socket_sendmsg(struct socket *sock,
            struct msghdr *msg, int size)
    {
        int rc = 0;

        call_hook_begin(socket_sendmsg);
        rc = hooks->socket_sendmsg(sock, size);
        call_int_hook_end(rc);

        return rc;
    }

    static int kylin_socket_recvmsg(struct socket *sock,
            struct msghdr *msg, int size, int flags)
    {
        int rc = 0;

        call_hook_begin(socket_recvmsg);
        rc = hooks->socket_recvmsg(sock, size, flags);
        call_int_hook_end(rc);

        return rc;
    }

    static void kylin_sk_free_security(struct sock *sk)
    {
        call_hook_begin(sk_free_security);
        hooks->sk_free_security(sk);
        call_void_hook_end();
    }
#endif

#define KYLIN_LSM_HOOK_INIT(HEAD, HOOK) \
    .HEAD = HOOK

static struct security_operations _mid_hooks = {
    .name = KOSEC_SYSFS_NAME "_kylin",

    KYLIN_LSM_HOOK_INIT(ptrace_access_check, kylin_ptrace_access_check),
    KYLIN_LSM_HOOK_INIT(bprm_check_security, kylin_bprm_check_security),
    KYLIN_LSM_HOOK_INIT(sb_kern_mount,kylin_sb_kern_mount),
    KYLIN_LSM_HOOK_INIT(sb_mount,     kylin_sb_mount),
#ifdef CONFIG_SECURITY_PATH
    KYLIN_LSM_HOOK_INIT(path_unlink,  kylin_path_unlink),
    KYLIN_LSM_HOOK_INIT(path_mkdir,   kylin_path_mkdir),
    KYLIN_LSM_HOOK_INIT(path_rmdir,   kylin_path_rmdir),
    KYLIN_LSM_HOOK_INIT(path_mknod,   kylin_path_mknod),
    KYLIN_LSM_HOOK_INIT(path_truncate,kylin_path_truncate),
    KYLIN_LSM_HOOK_INIT(path_symlink, kylin_path_symlink),
    KYLIN_LSM_HOOK_INIT(path_link,    kylin_path_link),
    KYLIN_LSM_HOOK_INIT(path_rename,  kylin_path_rename),
    KYLIN_LSM_HOOK_INIT(path_chmod,   kylin_path_chmod),
    KYLIN_LSM_HOOK_INIT(path_chown,   kylin_path_chown),
#endif
    KYLIN_LSM_HOOK_INIT(inode_free_security,kylin_inode_free_security),
    KYLIN_LSM_HOOK_INIT(inode_create,       kylin_inode_create),
    KYLIN_LSM_HOOK_INIT(inode_link,         kylin_inode_link),
    KYLIN_LSM_HOOK_INIT(inode_mknod,        kylin_inode_mknod),
    KYLIN_LSM_HOOK_INIT(inode_symlink,      kylin_inode_symlink),
    KYLIN_LSM_HOOK_INIT(inode_unlink,       kylin_inode_unlink),
    KYLIN_LSM_HOOK_INIT(inode_mkdir,        kylin_inode_mkdir),
    KYLIN_LSM_HOOK_INIT(inode_rmdir,        kylin_inode_rmdir),
    KYLIN_LSM_HOOK_INIT(inode_rename,       kylin_inode_rename),
    KYLIN_LSM_HOOK_INIT(inode_setattr,      kylin_inode_setattr),
    KYLIN_LSM_HOOK_INIT(file_free_security, kylin_file_free_security),
    KYLIN_LSM_HOOK_INIT(file_ioctl,         kylin_file_ioctl),
    KYLIN_LSM_HOOK_INIT(mmap_file,          kylin_mmap_file),
    KYLIN_LSM_HOOK_INIT(file_open,          kylin_file_open),
    KYLIN_LSM_HOOK_INIT(task_free, kylin_task_free),
    KYLIN_LSM_HOOK_INIT(task_kill, kylin_task_kill),
#ifdef CONFIG_SECURITY_NETWORK
    KYLIN_LSM_HOOK_INIT(socket_create,    kylin_socket_create),
    KYLIN_LSM_HOOK_INIT(socket_post_create,kylin_socket_post_create),
    KYLIN_LSM_HOOK_INIT(socket_accept,    kylin_socket_accept),
    KYLIN_LSM_HOOK_INIT(socket_bind,      kylin_socket_bind),
    KYLIN_LSM_HOOK_INIT(socket_connect,   kylin_socket_connect),
    KYLIN_LSM_HOOK_INIT(socket_sendmsg,   kylin_socket_sendmsg),
    KYLIN_LSM_HOOK_INIT(socket_recvmsg,   kylin_socket_recvmsg),
    KYLIN_LSM_HOOK_INIT(sk_free_security, kylin_sk_free_security),
#endif
};

static int kylin_lsm_init_hook(void)
{
    return 0;
}

static void kylin_lsm_uninit_hook(void)
{
    security_del_external_ops(&_mid_hooks);
}

static int kylin_enable_lsm(void)
{
    int rc;

    if (test_and_set_bit(0, &kylin_lsm_enabled)) {
        return -EAGAIN;
    }

    rc = security_add_external_ops(&_mid_hooks);
    if (rc != 0) {
        clear_bit(0, &kylin_lsm_enabled);
    }
    LOG_INFO("osec hook enable kylin: %d\n", rc);

    return rc;
}

static int kylin_disable_lsm(void)
{
    int rc = -EFAULT;

    if (test_and_clear_bit(0, &kylin_lsm_enabled)) {
        //此时注销会导致系统崩溃,移到模块卸载时处理
        //security_del_external_ops(&_mid_hooks);
        rc = 0;
        LOG_INFO("osec hook disable kylin\n");
    }

    return rc;
}

static int kylin_lsm_is_enabled(void)
{
    return test_bit(0, &kylin_lsm_enabled);
}

static char * kylin_lsm_hook_mode(void)
{
    return "kylin-lsm";
}

static int comm_lsm_init_hook(void)
{

    return kylin_lsm_init_hook();
}

static void comm_lsm_uninit_hook(void)
{
    kylin_lsm_uninit_hook();
}

static int comm_lsm_enable(void)
{
    return kylin_enable_lsm();
}

static int comm_lsm_disable(void)
{
    return kylin_disable_lsm();
}

static int comm_lsm_is_enabled(void)
{
    return kylin_lsm_is_enabled();
}

static char * comm_lsm_hook_mode(void)
{
    return kylin_lsm_hook_mode();
}

static int comm_lsm_register_hook(struct kvd_security_operations *hooks)
{
    return comm_lsm_register_do(hooks);
}

static int comm_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    return comm_lsm_unregister_do(hooks);
}
