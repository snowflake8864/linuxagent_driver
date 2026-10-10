/*
 * UOS LSM HOOK Manager: CONFIG_SECURITY_HOOKMANAGER
 * 目前编译环境已有头文件中,
 * 内核版本4.19.71(只有arm64)无uos_hook_manager头文件
 * 即使定义了HOOKMANAGER宏!!!
 * */
#if (!defined(CONFIG_SECURITY_HOOKMANAGER) ) || \
    (defined(CONFIG_ARM64) && (LINUX_VERSION_CODE == KERNEL_VERSION(4,19,71)))
static int uos_lsm_init_hook(void)
{
    return -ENOTSUPP;
}

static void uos_lsm_uninit_hook(void)
{
}

static int uos_enable_lsm(void)
{
    return -ENOTSUPP;
}

static int uos_disable_lsm(void)
{
    return -ENOTSUPP;
}

static int uos_lsm_is_enabled(void)
{
    return -ENOTSUPP;
}

static char * uos_lsm_hook_mode(void)
{
    return NULL;
}

static int uos_lsm_register_hook(struct kvd_security_operations *hooks)
{
    return -ENOTSUPP;
}

static int uos_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    return -ENOTSUPP;
}
#else
#include <linux/utsname.h>
#include <linux/lsm_uos_hook_manager.h>

static unsigned long uos_lsm_enabled = 0;
struct uos_security_operations {
    enum UOS_HOOK_LIST hook_id;
    struct uos_hook_cb_entry entry;
};

static int uos_ptrace_access_check(struct task_struct *child,
        unsigned int mode)
{
    int rc = 0;

    call_hook_begin(ptrace_access_check);
    rc = hooks->ptrace_access_check(child, mode);
    call_int_hook_end(rc);

    return rc;
}

static int uos_bprm_check_security(struct linux_binprm *bprm)
{
    int rc = 0;

    call_hook_begin(bprm_check_security);
    rc = hooks->bprm_check_security(bprm);
    call_int_hook_end(rc);

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int uos_sb_kern_mount(struct super_block *sb)
#else
static int uos_sb_kern_mount(struct super_block *sb, int flags, void *data)
#endif
{
    int rc = 0;

    call_hook_begin(sb_kern_mount);
    rc = hooks->sb_kern_mount(sb);
    call_int_hook_end(rc);

    return rc;
}

static int uos_sb_mount(const char *dev_name,
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
    static int uos_path_unlink(const struct path *dir, struct dentry *dentry)
    {
        int rc = 0;

        call_hook_begin(path_unlink);
        rc = hooks->path_unlink(dir, dentry);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_path_mkdir(const struct path *dir, struct dentry *dentry,
            umode_t mode)
    {
        int rc = 0;

        call_hook_begin(path_mkdir);
        rc = hooks->path_mkdir(dir, dentry, mode);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_path_rmdir(const struct path *dir, struct dentry *dentry)
    {
        int rc = 0;

        call_hook_begin(path_rmdir);
        rc = hooks->path_rmdir(dir, dentry);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_path_mknod(const struct path *dir, struct dentry *dentry,
            umode_t mode, unsigned int dev)
    {
        int rc = 0;

        call_hook_begin(path_mknod);
        rc = hooks->path_mknod(dir, dentry, mode, dev);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_path_truncate(const struct path *path)
    {
        int rc = 0;

        call_hook_begin(path_truncate);
        rc = hooks->path_truncate(path);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_path_symlink(const struct path *dir, struct dentry *dentry,
            const char *old_name)
    {
        int rc = 0;

        call_hook_begin(path_symlink);
        rc = hooks->path_symlink(dir, dentry, old_name);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_path_link(struct dentry *old_dentry,
            const struct path *new_dir, struct dentry *new_dentry)
    {
        int rc = 0;

        call_hook_begin(path_link);
        rc = hooks->path_link(old_dentry, new_dir, new_dentry);
        call_int_hook_end(rc);

        return rc;
    }

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
    static int uos_path_rename(const struct path *old_dir, struct dentry *old_dentry,
            const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
    #else
    static int uos_path_rename(const struct path *old_dir, struct dentry *old_dentry,
            const struct path *new_dir, struct dentry *new_dentry)
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

    static int uos_path_chmod(const struct path *path, umode_t mode)
    {
        int rc = 0;

        call_hook_begin(path_chmod);
        rc = hooks->path_chmod(path, mode);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
    {
        int rc = 0;

        call_hook_begin(path_chown);
        rc = hooks->path_chown(path, uid, gid);
        call_int_hook_end(rc);

        return rc;
    }
#endif

static void uos_inode_free_security(struct inode *inode)
{
    call_hook_begin(inode_free_security);
    hooks->inode_free_security(inode);
    call_void_hook_end();
}

static int uos_inode_create(struct inode *dir,
        struct dentry *dentry, umode_t mode)
{
    int rc = 0;

    call_hook_begin(inode_create);
    rc = hooks->inode_create(dir, dentry, mode);
    call_int_hook_end(rc);

    return rc;
}

static int uos_inode_link(struct dentry *old_dentry,
        struct inode *dir, struct dentry *new_dentry)
{
    int rc = 0;
    call_hook_begin(inode_link);
    rc = hooks->inode_link(old_dentry, dir, new_dentry);
    call_int_hook_end(rc);

    return rc;
}

static int uos_inode_mknod(struct inode *dir,
        struct dentry *dentry, umode_t mode, dev_t dev)
{
    int rc = 0;
    call_hook_begin(inode_mknod);
    rc = hooks->inode_mknod(dir, dentry, mode, dev);
    call_int_hook_end(rc);

    return rc;
}

static int uos_inode_symlink(struct inode *dir,
        struct dentry *dentry, const char *old_name)
{
    int rc = 0;
    call_hook_begin(inode_symlink);
    rc = hooks->inode_symlink(dir, dentry, old_name);
    call_int_hook_end(rc);

    return rc;
}

static int uos_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    call_hook_begin(inode_unlink);
    rc = hooks->inode_unlink(dir, dentry);
    call_int_hook_end(rc);

    return rc;
}

static int uos_inode_mkdir(struct inode *dir, struct dentry *dentry,
        umode_t mode)
{
    int rc = 0;

    call_hook_begin(inode_mkdir);
    rc = hooks->inode_mkdir(dir, dentry, mode);
    call_int_hook_end(rc);

    return rc;
}

static int uos_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    call_hook_begin(inode_rmdir);
    rc = hooks->inode_rmdir(dir, dentry);
    call_int_hook_end(rc);

    return rc;
}

static int uos_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry)
{
    int rc = 0;

    call_hook_begin(inode_rename);
    rc = hooks->inode_rename(old_dir, old_dentry, new_dir, new_dentry);
    call_int_hook_end(rc);

    return rc;
}

static int uos_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    int rc = 0;

    call_hook_begin(inode_setattr);
    rc = hooks->inode_setattr(dentry, attr);
    call_int_hook_end(rc);

    return rc;
}

static void uos_file_free_security(struct file *file)
{
    call_hook_begin(file_free_security);
    hooks->file_free_security(file);
    call_void_hook_end();
}

static int uos_file_ioctl(struct file *file, unsigned int cmd,
        unsigned long arg)
{
    int rc = 0;

    call_hook_begin(file_ioctl);
    rc = hooks->file_ioctl(file, cmd, arg);
    call_int_hook_end(rc);

    return rc;
}

static int uos_mmap_file(struct file *file, unsigned long reqprot,
        unsigned long prot, unsigned long flags)
{
    int rc = 0;

    call_hook_begin(mmap_file);
    rc = hooks->mmap_file(file, reqprot, prot, flags);
    call_int_hook_end(rc);

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static int uos_file_open(struct file *file)
#else
static int uos_file_open(struct file *file, const struct cred *cred)
#endif
{
    int rc = 0;

    call_hook_begin(file_open);
    rc = hooks->file_open(file);
    call_int_hook_end(rc);

    return rc;
}

static void uos_task_free(struct task_struct *task)
{
    call_hook_begin(task_free);
    hooks->task_free(task);
    call_void_hook_end();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
    static inline int uos_is_info_special(struct kernel_siginfo *info)
    {
        return info <= (struct kernel_siginfo *)SEND_SIG_FORCED;
    }

static int uos_task_kill(struct task_struct *p, struct kernel_siginfo *_info,
        int sig, const struct cred *cred)
{
    int rc = 0;
    struct siginfo *info = (struct siginfo *)_info;
    struct siginfo dup_info;

    if (!uos_is_info_special(_info)) {
        info = &dup_info;
        memset(info, 0, sizeof(*info));
        memcpy(info, _info, sizeof(*info));
    }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
static int uos_task_kill(struct task_struct *p, struct siginfo *info,
        int sig, const struct cred *cred)
{
    int rc = 0;
#else
static int uos_task_kill(struct task_struct *p, struct siginfo *info,
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
    static int uos_socket_create(int family, int type,
            int protocol, int kern)
    {
        int rc = 0;

        call_hook_begin(socket_create);
        rc = hooks->socket_create(family, type, protocol, kern);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_socket_post_create(struct socket *sock, int family,
            int type, int protocol, int kern)
    {
        int rc = 0;

        call_hook_begin(socket_post_create);
        rc = hooks->socket_post_create(sock, family, type, protocol, kern);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_socket_accept(struct socket *sock, struct socket *newsock)
    {
        int rc = 0;

        call_hook_begin(socket_accept);
        rc = hooks->socket_accept(sock, newsock);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_socket_bind(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        call_hook_begin(socket_bind);
        rc = hooks->socket_bind(sock, address, addrlen);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_socket_connect(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        call_hook_begin(socket_connect);
        rc = hooks->socket_connect(sock, address, addrlen);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_socket_sendmsg(struct socket *sock,
            struct msghdr *msg, int size)
    {
        int rc = 0;

        call_hook_begin(socket_sendmsg);
        rc = hooks->socket_sendmsg(sock, size);
        call_int_hook_end(rc);

        return rc;
    }

    static int uos_socket_recvmsg(struct socket *sock,
            struct msghdr *msg, int size, int flags)
    {
        int rc = 0;

        call_hook_begin(socket_recvmsg);
        rc = hooks->socket_recvmsg(sock, size, flags);
        call_int_hook_end(rc);

        return rc;
    }

    static void uos_sk_free_security(struct sock *sk)
    {
        call_hook_begin(sk_free_security);
        hooks->sk_free_security(sk);
        call_void_hook_end();
    }
#endif

#define UOS_LSM_HOOK_INIT(hkid, rtype, func, arglen) \
    { \
        .hook_id = hkid, \
        .entry = { \
            .owner = THIS_MODULE->name, \
            .cb_addr = (unsigned long)func, \
            .ret_type = rtype, \
            .arg_len = arglen, \
        } \
    }

static struct uos_security_operations uos_mid_hooks[] = {
    UOS_LSM_HOOK_INIT(UOS_PTRACE_ACCESS_CHECK, UOS_HOOK_RET_TY_INT,
            uos_ptrace_access_check, 2),
    UOS_LSM_HOOK_INIT(UOS_BPRM_CHECK_SECURITY, UOS_HOOK_RET_TY_INT,
            uos_bprm_check_security, 1),
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        UOS_LSM_HOOK_INIT(UOS_SB_KERN_MOUNT, UOS_HOOK_RET_TY_INT,
                uos_sb_kern_mount, 1),
    #else
        /* 低版本又没有, 需确认该函数在何版本加入支持 */
        //UOS_LSM_HOOK_INIT(UOS_SB_KERN_MOUNT, UOS_HOOK_RET_TY_INT,
        //        uos_sb_kern_mount, 3),
    #endif
    UOS_LSM_HOOK_INIT(UOS_SB_MOUNT, UOS_HOOK_RET_TY_INT,
            uos_sb_mount, 5),
#ifdef CONFIG_SECURITY_PATH
    UOS_LSM_HOOK_INIT(UOS_PATH_UNLINK, UOS_HOOK_RET_TY_INT,
            uos_path_unlink, 2),
    UOS_LSM_HOOK_INIT(UOS_PATH_MKDIR, UOS_HOOK_RET_TY_INT,
            uos_path_mkdir, 3),
    UOS_LSM_HOOK_INIT(UOS_PATH_RMDIR, UOS_HOOK_RET_TY_INT,
            uos_path_rmdir, 2),
    UOS_LSM_HOOK_INIT(UOS_PATH_MKNOD, UOS_HOOK_RET_TY_INT,
            uos_path_mknod, 4),
    UOS_LSM_HOOK_INIT(UOS_PATH_TRUNCATE, UOS_HOOK_RET_TY_INT,
            uos_path_truncate, 1),
    UOS_LSM_HOOK_INIT(UOS_PATH_SYMLINK, UOS_HOOK_RET_TY_INT,
            uos_path_symlink, 3),
    UOS_LSM_HOOK_INIT(UOS_PATH_LINK, UOS_HOOK_RET_TY_INT,
            uos_path_link, 3),
    UOS_LSM_HOOK_INIT(UOS_PATH_RENAME, UOS_HOOK_RET_TY_INT,
            uos_path_rename, 4),
    UOS_LSM_HOOK_INIT(UOS_PATH_CHMOD, UOS_HOOK_RET_TY_INT,
            uos_path_chmod, 2),
    UOS_LSM_HOOK_INIT(UOS_PATH_CHOWN, UOS_HOOK_RET_TY_INT,
            uos_path_chown, 3),
#endif
    UOS_LSM_HOOK_INIT(UOS_INODE_FREE_SECURITY, UOS_HOOK_RET_TY_NONE,
            uos_inode_free_security, 1),
    UOS_LSM_HOOK_INIT(UOS_INODE_CREATE, UOS_HOOK_RET_TY_INT,
            uos_inode_create, 3),
    UOS_LSM_HOOK_INIT(UOS_INODE_LINK, UOS_HOOK_RET_TY_INT,
            uos_inode_link, 3),
    UOS_LSM_HOOK_INIT(UOS_INODE_MKNOD, UOS_HOOK_RET_TY_INT,
            uos_inode_mknod, 4),
    UOS_LSM_HOOK_INIT(UOS_INODE_SYMLINK, UOS_HOOK_RET_TY_INT,
            uos_inode_symlink, 3),
    UOS_LSM_HOOK_INIT(UOS_INODE_UNLINK, UOS_HOOK_RET_TY_INT,
            uos_inode_unlink, 2),
    UOS_LSM_HOOK_INIT(UOS_INODE_MKDIR, UOS_HOOK_RET_TY_INT,
            uos_inode_mkdir, 3),
    UOS_LSM_HOOK_INIT(UOS_INODE_RMDIR, UOS_HOOK_RET_TY_INT,
            uos_inode_rmdir, 2),
    UOS_LSM_HOOK_INIT(UOS_INODE_RENAME, UOS_HOOK_RET_TY_INT,
            uos_inode_rename, 4),
    UOS_LSM_HOOK_INIT(UOS_INODE_SETATTR, UOS_HOOK_RET_TY_INT,
            uos_inode_setattr, 2),
    UOS_LSM_HOOK_INIT(UOS_FILE_FREE_SECURITY, UOS_HOOK_RET_TY_NONE,
            uos_file_free_security, 1),
    UOS_LSM_HOOK_INIT(UOS_FILE_IOCTL, UOS_HOOK_RET_TY_INT,
            uos_file_ioctl, 3),
    UOS_LSM_HOOK_INIT(UOS_MMAP_FILE, UOS_HOOK_RET_TY_INT,
            uos_mmap_file, 4),
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
        UOS_LSM_HOOK_INIT(UOS_FILE_OPEN, UOS_HOOK_RET_TY_INT,
                uos_file_open, 1),
    #else
        UOS_LSM_HOOK_INIT(UOS_FILE_OPEN, UOS_HOOK_RET_TY_INT,
                uos_file_open, 2),
    #endif
    UOS_LSM_HOOK_INIT(UOS_TASK_FREE, UOS_HOOK_RET_TY_NONE,
            uos_task_free, 1),
    UOS_LSM_HOOK_INIT(UOS_TASK_KILL, UOS_HOOK_RET_TY_INT,
            uos_task_kill, 4),
#ifdef CONFIG_SECURITY_NETWORK
    UOS_LSM_HOOK_INIT(UOS_SOCKET_CREATE, UOS_HOOK_RET_TY_INT,
            uos_socket_create, 4),
    UOS_LSM_HOOK_INIT(UOS_SOCKET_POST_CREATE, UOS_HOOK_RET_TY_INT,
            uos_socket_post_create, 5),
    UOS_LSM_HOOK_INIT(UOS_SOCKET_ACCEPT, UOS_HOOK_RET_TY_INT,
            uos_socket_accept, 2),
    UOS_LSM_HOOK_INIT(UOS_SOCKET_BIND, UOS_HOOK_RET_TY_INT,
            uos_socket_bind, 3),
    UOS_LSM_HOOK_INIT(UOS_SOCKET_CONNECT, UOS_HOOK_RET_TY_INT,
            uos_socket_connect, 3),
    UOS_LSM_HOOK_INIT(UOS_SOCKET_SENDMSG, UOS_HOOK_RET_TY_INT,
            uos_socket_sendmsg, 3),
    UOS_LSM_HOOK_INIT(UOS_SOCKET_RECVMSG, UOS_HOOK_RET_TY_INT,
            uos_socket_recvmsg, 4),
    /* 需确认该函数在何版本加入支持 */
    //UOS_LSM_HOOK_INIT(UOS_SK_FREE_SECURITY, UOS_HOOK_RET_TY_NONE,
    //        uos_sk_free_security, 1),
#endif
};

static int uos_hook_init(void)
{
    int i;
    int rc, ret = -EAGAIN;
    struct uos_security_operations *hook;

    for (i = 0; i < ARRAY_SIZE(uos_mid_hooks); i++) {
        hook = &uos_mid_hooks[i];
        rc = uos_hook_register(hook->hook_id, &hook->entry);
        if (rc) {
            LOG_INFO("uos_hook_register failed: "
                    "[%d] id=%d, rc=%d\n", i, hook->hook_id, rc);
        } else {
            //只要有一次成功便认为成功
            ret = 0;
        }
    }

    return ret;
}

static void uos_hook_uninit(void)
{
    int i;
    int rc;
    struct uos_security_operations *hook;

    for (i = 0; i < ARRAY_SIZE(uos_mid_hooks); i++) {
        hook = &uos_mid_hooks[i];
        rc = uos_hook_cancel(hook->hook_id, hook->entry.owner);
        if (rc) {
            LOG_INFO("uos_hook_cancel: [%d] id=%d, rc=%d\n",
                    i, hook->hook_id, rc);
        }
    }
}

extern struct new_utsname * get_init_utsname(void);
static int uos_lsm_init_hook(void)
{
    int enable = 0;
    char buf[64] = {0};

    //通过UTS_VERSION判断UKSI是否可用
    memcpy(buf, get_init_utsname()->version, sizeof(buf)-1);
    if (buf[0] != '#') {
        return -EINVAL;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    //uos20pro1050-update2
    if (strncmp(buf+1, "20.00.52.00", 11) > 0) {
    //目前发现loongarch与mips上uksi在卸载时崩溃!!!
    #if !defined(__mips__) && !defined(__loongarch__)
        enable = 1;
    #else
        enable = 0;
    #endif
    }
#else
    //uos20pro1050-update2
    if (strncmp(buf+1, "5200", 4) > 0) {
    //目前发现loongarch与mips上uksi在卸载时崩溃!!!
    #if !defined(__mips__) && !defined(__loongarch__)
        enable = 1;
    #else
        enable = 0;
    #endif
    }
#endif
    if (enable) {
        set_bit(COMMLSM_TYPE_UOS, &lsm_type_use);
        return 0;
    }
    return -ENOTSUPP;
}

static void uos_lsm_uninit_hook(void)
{
    if (test_and_clear_bit(LSM_STATE_INITED, &uos_lsm_enabled)) {
        //loongarch和mips平台上在用户态退出时使用通知链通知注销
        //会导致系统崩溃,放在模块卸载时注销
        uos_hook_uninit();
    }
    clear_bit(COMMLSM_TYPE_UOS, &lsm_type_use);
}

static int uos_enable_lsm(void)
{
    int rc;
    //已经向系统注册过，不再注册
    if (test_bit(LSM_STATE_INITED, &uos_lsm_enabled)) {
         return -EAGAIN;
    }

    if (test_and_set_bit(LSM_STATE_ENABLED, &uos_lsm_enabled)) {
        return -EAGAIN;
    }

    rc = uos_hook_init();
    if (rc != 0) {
        clear_bit(LSM_STATE_ENABLED, &uos_lsm_enabled);
    } else {
        //标记向系统注册了lsm回调
        set_bit(LSM_STATE_INITED, &uos_lsm_enabled);
    }
    LOG_INFO("osec hook init uos: %d\n", rc);

    return rc;
}

static int uos_disable_lsm(void)
{
    int rc = -EFAULT;

    if (test_and_clear_bit(LSM_STATE_ENABLED, &uos_lsm_enabled)) {
        //此时注销会导致系统崩溃,移到模块卸载时处理
        //uos_hook_uninit();
        rc = 0;
        LOG_INFO("osec hook disable uos\n");
    }

    return rc;
}

static int uos_lsm_is_enabled(void)
{
    return test_bit(LSM_STATE_ENABLED, &uos_lsm_enabled);
}

static char * uos_lsm_hook_mode(void)
{
    return "uos-lsm";
}

static int uos_lsm_register_hook(struct kvd_security_operations *hooks)
{
    return comm_lsm_register_do(hooks);
}

static int uos_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    return comm_lsm_unregister_do(hooks);
}
#endif

