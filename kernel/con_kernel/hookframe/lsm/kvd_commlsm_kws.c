/*
 * 适用内核卫士KWS: KERNEL_VERSION >= 4.4.0
 * */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#include "kvd_commlsm_kws.h"

static unsigned long kws_lsm_enabled = 0;
static kws_security_register_fn_t kws_security_register_fn = NULL;
static kws_security_unregister_fn_t kws_security_unregister_fn = NULL;

static int kws_find_security_func(void)
{
    void *fn;
    const char fname_reg[] = "kws_security_register";
    const char fname_unreg[] = "kws_security_unregister";

    fn = (void*)kallsyms_lookup_name(fname_reg);
    if (!fn) {
        LOG_INFO("kwslsm_hook: not find %s\n", fname_reg);
        return -ENOTSUPP;
    }
    kws_security_register_fn = fn;

    fn = (void*)kallsyms_lookup_name(fname_unreg);
    if (!fn) {
        LOG_INFO("kwslsm_hook: not find %s\n", fname_unreg);
        return -ENOTSUPP;
    }
    kws_security_unregister_fn = fn;

    set_bit(COMMLSM_TYPE_KWS, &lsm_type_use);
    LOG_INFO("kws_security register: %p, unregister: %p\n",
            kws_security_register_fn, kws_security_unregister_fn);
    return 0;
}

static int kws_ptrace_access_check(struct task_struct *child,
        unsigned int mode)
{
    int rc = 0;

    call_hook_begin(ptrace_access_check);
    rc = hooks->ptrace_access_check(child, mode);
    call_int_hook_end(rc);

    return rc;
}

static int kws_bprm_check_security(struct linux_binprm *bprm)
{
    int rc = 0;

    call_hook_begin(bprm_check_security);
    rc = hooks->bprm_check_security(bprm);
    call_int_hook_end(rc);

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int kws_sb_kern_mount(struct super_block *sb)
#else
static int kws_sb_kern_mount(struct super_block *sb, int flags, void *data)
#endif
{
    int rc = 0;

    call_hook_begin(sb_kern_mount);
    rc = hooks->sb_kern_mount(sb);
    call_int_hook_end(rc);

    return rc;
}

static int kws_sb_mount(const char *dev_name, const struct path *path,
        const char *type, unsigned long flags, void *data)
{
    int rc = 0;

    call_hook_begin(sb_mount);
    rc = hooks->sb_mount(dev_name, path, type, flags, data);
    call_int_hook_end(rc);

    return rc;
}

#ifdef CONFIG_SECURITY_PATH
    static int kws_path_unlink(const struct path *dir, struct dentry *dentry)
    {
        int rc = 0;

        call_hook_begin(path_unlink);
        rc = hooks->path_unlink(dir, dentry);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_path_mkdir(const struct path *dir,
            struct dentry *dentry, umode_t mode)
    {
        int rc = 0;

        call_hook_begin(path_mkdir);
        rc = hooks->path_mkdir(dir, dentry, mode);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_path_rmdir(const struct path *dir, struct dentry *dentry)
    {
        int rc = 0;

        call_hook_begin(path_rmdir);
        rc = hooks->path_rmdir(dir, dentry);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_path_mknod(const struct path *dir, struct dentry *dentry,
            umode_t mode, unsigned int dev)
    {
        int rc = 0;

        call_hook_begin(path_mknod);
        rc = hooks->path_mknod(dir, dentry, mode, dev);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_path_truncate(const struct path *path)
    {
        int rc = 0;

        call_hook_begin(path_truncate);
        rc = hooks->path_truncate(path);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_path_symlink(const struct path *dir,
            struct dentry *dentry, const char *old_name)
    {
        int rc = 0;

        call_hook_begin(path_symlink);
        rc = hooks->path_symlink(dir, dentry, old_name);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_path_link(struct dentry *old_dentry,
            const struct path *new_dir, struct dentry *new_dentry)
    {
        int rc = 0;

        call_hook_begin(path_link);
        rc = hooks->path_link(old_dentry, new_dir, new_dentry);
        call_int_hook_end(rc);

        return rc;
    }

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
    static int kws_path_rename(const struct path *old_dir,
            struct dentry *old_dentry, const struct path *new_dir,
            struct dentry *new_dentry, unsigned int flags)
    #else
    static int kws_path_rename(const struct path *old_dir,
            struct dentry *old_dentry, const struct path *new_dir,
            struct dentry *new_dentry)
    #endif
    {
        int rc = 0;

        call_hook_begin(path_rename);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
        rc = hooks->path_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
        #else
        rc = hooks->path_rename(old_dir, old_dentry, new_dir, new_dentry);
        #endif
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_path_chmod(const struct path *path, umode_t mode)
    {
        int rc = 0;

        call_hook_begin(path_chmod);
        rc = hooks->path_chmod(path, mode);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
    {
        int rc = 0;

        call_hook_begin(path_chown);
        rc = hooks->path_chown(path, uid, gid);
        call_int_hook_end(rc);

        return rc;
    }
#endif

static void kws_inode_free_security(struct inode *inode)
{
    call_hook_begin(inode_free_security);
    hooks->inode_free_security(inode);
    call_void_hook_end();
}

static int kws_inode_create(struct inode *dir,
        struct dentry *dentry, umode_t mode)
{
    int rc = 0;

    call_hook_begin(inode_create);
    rc = hooks->inode_create(dir, dentry, mode);
    call_int_hook_end(rc);

    return rc;
}

static int kws_inode_link(struct dentry *old_dentry,
        struct inode *dir, struct dentry *new_dentry)
{
    int rc = 0;

    call_hook_begin(inode_link);
    rc = hooks->inode_link(old_dentry, dir, new_dentry);
    call_int_hook_end(rc);

    return rc;
}

static int kws_inode_mknod(struct inode *dir, struct dentry *dentry,
                        umode_t mode, dev_t dev)
{
    int rc = 0;

    call_hook_begin(inode_mknod);
    rc = hooks->inode_mknod(dir, dentry, mode, dev);
    call_int_hook_end(rc);

    return rc;
}

static int kws_inode_symlink(struct inode *dir, struct dentry *dentry,
                    const char *old_name)
{
    int rc = 0;

    call_hook_begin(inode_symlink);
    rc = hooks->inode_symlink(dir, dentry, old_name);
    call_int_hook_end(rc);

    return rc;    
}

static int kws_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    call_hook_begin(inode_unlink);
    rc = hooks->inode_unlink(dir, dentry);
    call_int_hook_end(rc);

    return rc;
}

static int kws_inode_mkdir(struct inode *dir, struct dentry *dentry,
        umode_t mode)
{
    int rc = 0;

    call_hook_begin(inode_mkdir);
    rc = hooks->inode_mkdir(dir, dentry, mode);
    call_int_hook_end(rc);

    return rc;
}

static int kws_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    call_hook_begin(inode_rmdir);
    rc = hooks->inode_rmdir(dir, dentry);
    call_int_hook_end(rc);

    return rc;
}

static int kws_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry)
{
    int rc = 0;

    call_hook_begin(inode_rename);
    rc = hooks->inode_rename(old_dir, old_dentry, new_dir, new_dentry);
    call_int_hook_end(rc);

    return rc;
}

static int kws_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    int rc = 0;

    call_hook_begin(inode_setattr);
    rc = hooks->inode_setattr(dentry, attr);
    call_int_hook_end(rc);

    return rc;
}

static void kws_file_free_security(struct file *file)
{
    call_hook_begin(file_free_security);
    hooks->file_free_security(file);
    call_void_hook_end();
}

static int kws_file_ioctl(struct file *file, unsigned int cmd,
        unsigned long arg)
{
    int rc = 0;

    call_hook_begin(file_ioctl);
    rc = hooks->file_ioctl(file, cmd, arg);
    call_int_hook_end(rc);

    return rc;
}

static int kws_mmap_file(struct file *file, unsigned long reqprot,
        unsigned long prot, unsigned long flags)
{
    int rc = 0;

    call_hook_begin(mmap_file);
    rc = hooks->mmap_file(file, reqprot, prot, flags);
    call_int_hook_end(rc);

    return rc;
}

static int kws_file_open(struct file *file)
{
    int rc = 0;

    call_hook_begin(file_open);
    rc = hooks->file_open(file);
    call_int_hook_end(rc);

    return rc;
}

static void kws_task_free(struct task_struct *task)
{
    call_hook_begin(task_free);
    hooks->task_free(task);
    call_void_hook_end();
}

static inline int kws_is_info_special(struct siginfo *info)
{
    return info <= (struct siginfo *)SEND_SIG_FORCED;
}

static int kws_task_kill(struct task_struct *p,
		struct siginfo *_info, int sig)
{
    int rc = 0;
    struct siginfo dup_info;
    struct siginfo *info = (struct siginfo *)_info;

    if (!kws_is_info_special(_info)) {
        info = &dup_info;
        memset(info, 0, sizeof(*info));
        memcpy(info, _info, sizeof(*info));
    }

    call_hook_begin(task_kill);
    rc = hooks->task_kill(p, info, sig);
    call_int_hook_end(rc);

    return rc;
}

#ifdef CONFIG_SECURITY_NETWORK
    static int kws_socket_create(int family, int type,
            int protocol, int kern)
    {
        int rc = 0;

        call_hook_begin(socket_create);
        rc = hooks->socket_create(family, type, protocol, kern);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_socket_post_create(struct socket *sock, int family,
            int type, int protocol, int kern)
    {
        int rc = 0;

        call_hook_begin(socket_post_create);
        rc = hooks->socket_post_create(sock, family, type, protocol, kern);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_socket_accept(struct socket *sock, struct socket *newsock)
    {
        int rc = 0;

        call_hook_begin(socket_accept);
        rc = hooks->socket_accept(sock, newsock);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_socket_bind(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        call_hook_begin(socket_bind);
        rc = hooks->socket_bind(sock, address, addrlen);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_socket_connect(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        call_hook_begin(socket_connect);
        rc = hooks->socket_connect(sock, address, addrlen);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_socket_sendmsg(struct socket *sock,
            struct msghdr *msg, int size)
    {
        int rc = 0;

        call_hook_begin(socket_sendmsg);
        rc = hooks->socket_sendmsg(sock, size);
        call_int_hook_end(rc);

        return rc;
    }

    static int kws_socket_recvmsg(struct socket *sock,
            struct msghdr *msg, int size, int flags)
    {
        int rc = 0;

        call_hook_begin(socket_recvmsg);
        rc = hooks->socket_recvmsg(sock, size, flags);
        call_int_hook_end(rc);

        return rc;
    }

    static void kws_sk_free_security(struct sock *sk)
    {
        call_hook_begin(sk_free_security);
        hooks->sk_free_security(sk);
        call_void_hook_end();
    }
#endif

#define KWS_LSM_HOOK_INIT(HEAD, HOOK) \
    .HEAD = HOOK

static struct kws_security_hook_options __mid_hooks = {
    .name = KOSEC_SYSFS_NAME "_kws",
    .pmod = THIS_MODULE,

    KWS_LSM_HOOK_INIT(ptrace_access_check, kws_ptrace_access_check),
    KWS_LSM_HOOK_INIT(bprm_check_security, kws_bprm_check_security),
    //KWS_LSM_HOOK_INIT(sb_kern_mount,kws_sb_kern_mount),
    KWS_LSM_HOOK_INIT(sb_mount,     kws_sb_mount),
#ifdef CONFIG_SECURITY_PATH
    KWS_LSM_HOOK_INIT(path_unlink,  kws_path_unlink),
    KWS_LSM_HOOK_INIT(path_mkdir,   kws_path_mkdir),
    KWS_LSM_HOOK_INIT(path_rmdir,   kws_path_rmdir),
    KWS_LSM_HOOK_INIT(path_mknod,   kws_path_mknod),
    KWS_LSM_HOOK_INIT(path_truncate,kws_path_truncate),
    KWS_LSM_HOOK_INIT(path_symlink, kws_path_symlink),
    KWS_LSM_HOOK_INIT(path_link,    kws_path_link),
    KWS_LSM_HOOK_INIT(path_rename,  kws_path_rename),
    KWS_LSM_HOOK_INIT(path_chmod,   kws_path_chmod),
    KWS_LSM_HOOK_INIT(path_chown,   kws_path_chown),
#endif
    //KWS_LSM_HOOK_INIT(inode_free_security,kws_inode_free_security),
    KWS_LSM_HOOK_INIT(inode_create,       kws_inode_create),
    KWS_LSM_HOOK_INIT(inode_link,         kws_inode_link),
    KWS_LSM_HOOK_INIT(inode_mknod,        kws_inode_mknod),
    KWS_LSM_HOOK_INIT(inode_symlink,      kws_inode_symlink),
    KWS_LSM_HOOK_INIT(inode_unlink,       kws_inode_unlink),
    KWS_LSM_HOOK_INIT(inode_mkdir,        kws_inode_mkdir),
    KWS_LSM_HOOK_INIT(inode_rmdir,        kws_inode_rmdir),
    KWS_LSM_HOOK_INIT(inode_rename,       kws_inode_rename),
    KWS_LSM_HOOK_INIT(inode_setattr,      kws_inode_setattr),
    //KWS_LSM_HOOK_INIT(file_free_security, kws_file_free_security),
    KWS_LSM_HOOK_INIT(file_ioctl,         kws_file_ioctl),
    KWS_LSM_HOOK_INIT(mmap_file,          kws_mmap_file),
    KWS_LSM_HOOK_INIT(file_open,          kws_file_open),
    KWS_LSM_HOOK_INIT(task_free, kws_task_free),
    KWS_LSM_HOOK_INIT(task_kill, kws_task_kill),
#ifdef CONFIG_SECURITY_NETWORK
    KWS_LSM_HOOK_INIT(socket_create,    kws_socket_create),
    //KWS_LSM_HOOK_INIT(socket_post_create,kws_socket_post_create),
    KWS_LSM_HOOK_INIT(socket_accept,    kws_socket_accept),
    KWS_LSM_HOOK_INIT(socket_bind,      kws_socket_bind),
    KWS_LSM_HOOK_INIT(socket_connect,   kws_socket_connect),
    KWS_LSM_HOOK_INIT(socket_sendmsg,   kws_socket_sendmsg),
    KWS_LSM_HOOK_INIT(socket_recvmsg,   kws_socket_recvmsg),
    KWS_LSM_HOOK_INIT(sk_free_security, kws_sk_free_security),
#endif
};

static int kws_lsm_init_hook(void)
{
    return kws_find_security_func();
}

static void kws_lsm_uninit_hook(void)
{
    kws_security_unregister_fn(&__mid_hooks);
    clear_bit(COMMLSM_TYPE_KWS, &lsm_type_use);
}

static int kws_enable_lsm(void)
{
    int rc;

    if (!kws_security_register_fn ||
            !kws_security_unregister_fn) {
        return -ENOTSUPP;
    }
    if (test_and_set_bit(0, &kws_lsm_enabled)) {
        return -EAGAIN;
    }

    rc = kws_security_register_fn(&__mid_hooks,
            "oseckwssecurity", 0);
    if (rc != 0) {
        clear_bit(0, &kws_lsm_enabled);
    }
    LOG_INFO("osec hook enable kws: %d\n", rc);

    return rc;
}

static int kws_disable_lsm(void)
{
    int rc = -EFAULT;

    if (test_and_clear_bit(0, &kws_lsm_enabled)) {
        //此时注销会导致系统崩溃,移到模块卸载时处理
        //kws_security_unregister_fn(&__mid_hooks);
        rc = 0;
        LOG_INFO("osec hook disable kws\n");
    }

    return rc;
}

static int kws_lsm_is_enabled(void)
{
    return test_bit(0, &kws_lsm_enabled);
}

static char * kws_lsm_hook_mode(void)
{
    return "kws-lsm";
}

static int kws_lsm_register_hook(struct kvd_security_operations *hooks)
{
    return comm_lsm_register_do(hooks);
}

static int kws_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    return comm_lsm_unregister_do(hooks);
}
#else
static int kws_lsm_init_hook(void)
{
    return -ENOTSUPP;
}

static void kws_lsm_uninit_hook(void)
{
}

static int kws_enable_lsm(void)
{
    return -ENOTSUPP;
}

static int kws_disable_lsm(void)
{
    return -ENOTSUPP;
}

static int kws_lsm_is_enabled(void)
{
    return -ENOTSUPP;
}

static char * kws_lsm_hook_mode(void)
{
    return NULL;
}

static int kws_lsm_register_hook(struct kvd_security_operations *hooks)
{
    return -ENOTSUPP;
}

static int kws_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    return -ENOTSUPP;
}
#endif

