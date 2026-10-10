/*
 * 适用Linux版本: 3.10.0 <= KERNEL_VERSION < 4.2.0
 * */

static unsigned long ops_lsm_enabled = 0;
static struct security_operations *lsm_org_ops = NULL;
static struct security_operations **pp_lsm_ops = NULL;
static struct security_operations _mid_hooks;

extern int hook_search_ksym(const char *sym_name, unsigned long *sym_addr);
//general Linux
//这里使用二级指针是为了hook_replace_pointer方便
static struct security_operations ** ops_find_security_ops(void)
{
    struct security_operations **psec_ops;

    psec_ops = (struct security_operations**)kallsyms_lookup_name("security_ops");
    if (!psec_ops) {
        int rc = hook_search_ksym("security_ops", (unsigned long*)&psec_ops);
        if (rc) { psec_ops = ERR_PTR(rc); }
    }

    if (IS_ERR(psec_ops)) {
        LOG_ERROR("not find security_ops\n");
    } else {
        LOG_INFO("find security_ops at: 0x%lx\n",(long)psec_ops);
    }

    return psec_ops;
}

#define ops_call_int_hook_begain(FUNC, RC, ...) \
    do { \
        unsigned long flags; \
        struct kvd_security_operations *hooks, *nops; \
        int got_mod = kvd_try_self_module_get(); \
        if (!got_mod) { \
            break; \
        } \
        if (lsm_org_ops && lsm_org_ops->FUNC) { \
            RC = lsm_org_ops->FUNC(__VA_ARGS__); \
            if (RC != 0) { \
                kvd_self_module_put(); \
                break; \
            } \
        } \
        read_lock_irqsave(&new_hooks_lock, flags); \
        list_for_each_entry_safe(hooks, nops, &new_hooks, list) { \
            if (!hooks->FUNC) { \
                continue; \
            } \
            read_unlock_irqrestore(&new_hooks_lock, flags);

#define ops_call_int_hook_end(RC) \
            read_lock_irqsave(&new_hooks_lock, flags); \
            if (RC != 0) { \
                break; \
            } \
        } \
        read_unlock_irqrestore(&new_hooks_lock, flags); \
        kvd_self_module_put(); \
    } while (0)

#define ops_call_void_hook_begain(FUNC, ...) \
    do { \
        unsigned long flags; \
        struct kvd_security_operations *hooks, *nops; \
        int got_mod = kvd_try_self_module_get(); \
        if (!got_mod) { \
            break; \
        } \
        if (lsm_org_ops && lsm_org_ops->FUNC) { \
            lsm_org_ops->FUNC(__VA_ARGS__); \
        } \
        read_lock_irqsave(&new_hooks_lock, flags); \
        list_for_each_entry_safe(hooks, nops, &new_hooks, list) { \
            if (!hooks->FUNC) { \
                continue; \
            } \
            read_unlock_irqrestore(&new_hooks_lock, flags);

#define ops_call_void_hook_end() \
            read_lock_irqsave(&new_hooks_lock, flags); \
        } \
        read_unlock_irqrestore(&new_hooks_lock, flags); \
        kvd_self_module_put(); \
    } while (0)

static int ops_ptrace_access_check(struct task_struct *child,
        unsigned int mode)
{
    int rc = 0;

    ops_call_int_hook_begain(ptrace_access_check, rc, child, mode);
    rc = hooks->ptrace_access_check(child, mode);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_bprm_check_security(struct linux_binprm *bprm)
{
    int rc = 0;

    ops_call_int_hook_begain(bprm_check_security, rc, bprm);
    rc = hooks->bprm_check_security(bprm);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
    int rc = 0;

    ops_call_int_hook_begain(sb_kern_mount, rc, sb, flags, data);
    rc = hooks->sb_kern_mount(sb);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_sb_mount(const char *dev_name, struct path *path,
        const char *type, unsigned long flags, void *data)
{
    int rc = 0;

    ops_call_int_hook_begain(sb_mount, rc, dev_name, path, type, flags, data);
    rc = hooks->sb_mount(dev_name, (const struct path *)path, type, flags, data);
    ops_call_int_hook_end(rc);

    return rc;
}

#ifdef CONFIG_SECURITY_PATH
    static int ops_path_unlink(struct path *dir, struct dentry *dentry)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_unlink, rc, dir, dentry);
        rc = hooks->path_unlink((const struct path *)dir, dentry);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_mkdir(struct path *dir,
            struct dentry *dentry, umode_t mode)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_mkdir, rc, dir, dentry, mode);
        rc = hooks->path_mkdir((const struct path *)dir, dentry, mode);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_rmdir(struct path *dir, struct dentry *dentry)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_rmdir, rc, dir, dentry);
        rc = hooks->path_rmdir((const struct path *)dir, dentry);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_mknod(struct path *dir, struct dentry *dentry,
            umode_t mode, unsigned int dev)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_mknod, rc, dir, dentry, mode, dev);
        rc = hooks->path_mknod((const struct path *)dir, dentry, mode, dev);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_truncate(struct path *path)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_truncate, rc, path);
        rc = hooks->path_truncate((const struct path *)path);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_symlink(struct path *dir, struct dentry *dentry,
            const char *old_name)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_symlink, rc, dir, dentry, old_name);
        rc = hooks->path_symlink((const struct path *)dir, dentry, old_name);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_link(struct dentry *old_dentry, struct path *new_dir,
            struct dentry *new_dentry)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_link, rc, old_dentry, new_dir, new_dentry);
        rc = hooks->path_link(old_dentry,
                (const struct path *)new_dir, new_dentry);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_rename(struct path *old_dir, struct dentry *old_dentry,
            struct path *new_dir, struct dentry *new_dentry)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_rename, rc, old_dir, old_dentry, new_dir, new_dentry);
        rc = hooks->path_rename((const struct path *)old_dir, old_dentry,
                (const struct path *)new_dir, new_dentry);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_chmod(struct path *path, umode_t mode)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_chmod, rc, path, mode);
        rc = hooks->path_chmod((const struct path *)path, mode);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_path_chown(struct path *path, kuid_t uid, kgid_t gid)
    {
        int rc = 0;

        ops_call_int_hook_begain(path_chown, rc, path, uid, gid);
        rc = hooks->path_chown((const struct path *)path, uid, gid);
        ops_call_int_hook_end(rc);

        return rc;
    }
#endif

static void ops_inode_free_security(struct inode *inode)
{
    ops_call_void_hook_begain(inode_free_security, inode);
    hooks->inode_free_security(inode);
    ops_call_void_hook_end();
}

static int ops_inode_create(struct inode *dir,
        struct dentry *dentry, umode_t mode)
{
    int rc = 0;

    ops_call_int_hook_begain(inode_create, rc, dir, dentry, mode);
    rc = hooks->inode_create(dir, dentry, mode);
    ops_call_int_hook_end(rc);

    return rc;
}


static int ops_inode_link(struct dentry *old_dentry, struct inode *dir,
                        struct dentry *new_dentry)
{
    int rc = 0;
    ops_call_int_hook_begain(inode_link, rc, old_dentry, dir, new_dentry);
    rc = hooks->inode_link(old_dentry, dir, new_dentry);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_inode_mknod(struct inode *dir, struct dentry *dentry,
                        umode_t mode, dev_t dev) 
{
    int rc = 0;
    ops_call_int_hook_begain(inode_mknod, rc, dir, dentry, mode, dev);
    rc = hooks->inode_mknod(dir, dentry, mode, dev);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_inode_symlink(struct inode *dir, struct dentry *dentry,
                        const char *old_name)
{
    int rc = 0;
    ops_call_int_hook_begain(inode_symlink, rc, dir, dentry, old_name);
    rc = hooks->inode_symlink(dir, dentry, old_name);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    ops_call_int_hook_begain(inode_unlink, rc, dir, dentry);
    rc = hooks->inode_unlink(dir, dentry);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    int rc = 0;

    ops_call_int_hook_begain(inode_mkdir, rc, dir, dentry, mode);
    rc = hooks->inode_mkdir(dir, dentry, mode);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    ops_call_int_hook_begain(inode_rmdir, rc, dir, dentry);
    rc = hooks->inode_rmdir(dir, dentry);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry)
{
    int rc = 0;

    ops_call_int_hook_begain(inode_rename, rc, old_dir, old_dentry, new_dir, new_dentry);
    rc = hooks->inode_rename(old_dir, old_dentry, new_dir, new_dentry);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    int rc = 0;

    ops_call_int_hook_begain(inode_setattr, rc, dentry, attr);
    rc = hooks->inode_setattr(dentry, attr);
    ops_call_int_hook_end(rc);

    return rc;
}

static void ops_file_free_security(struct file *file)
{
    ops_call_void_hook_begain(file_free_security, file);
    hooks->file_free_security(file);
    ops_call_void_hook_end();
}

static int ops_file_ioctl(struct file *file, unsigned int cmd,
        unsigned long arg)
{
    int rc = 0;

    ops_call_int_hook_begain(file_ioctl, rc, file, cmd, arg);
    rc = hooks->file_ioctl(file, cmd, arg);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_mmap_file(struct file *file, unsigned long reqprot,
        unsigned long prot, unsigned long flags)
{
    int rc = 0;

    ops_call_int_hook_begain(mmap_file, rc, file, reqprot, prot, flags);
    rc = hooks->mmap_file(file, reqprot, prot, flags);
    ops_call_int_hook_end(rc);

    return rc;
}

static int ops_file_open(struct file *file, const struct cred *cred)
{
    int rc = 0;

    ops_call_int_hook_begain(file_open, rc, file, cred);
    rc = hooks->file_open(file);
    ops_call_int_hook_end(rc);

    return rc;
}

static void ops_task_free(struct task_struct *task)
{
    ops_call_void_hook_begain(task_free, task);
    hooks->task_free(task);
    ops_call_void_hook_end();
}

static int ops_task_kill(struct task_struct *p, struct siginfo *info,
        int sig, u32 secid)
{
    int rc = 0;

    ops_call_int_hook_begain(task_kill, rc, p, info, sig, secid);
    rc = hooks->task_kill(p, info, sig);
    ops_call_int_hook_end(rc);

    return rc;
}

#ifdef CONFIG_SECURITY_NETWORK
    static int ops_socket_create(int family, int type,
            int protocol, int kern)
    {
        int rc = 0;

        ops_call_int_hook_begain(socket_create, rc, family, type, protocol, kern);
        rc = hooks->socket_create(family, type, protocol, kern);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_socket_post_create(struct socket *sock, int family,
            int type, int protocol, int kern)
    {
        int rc = 0;

        ops_call_int_hook_begain(socket_post_create, rc, sock, family, type, protocol, kern);
        rc = hooks->socket_post_create(sock, family, type, protocol, kern);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_socket_accept(struct socket *sock, struct socket *newsock)
    {
        int rc = 0;

        ops_call_int_hook_begain(socket_accept, rc, sock, newsock);
        rc = hooks->socket_accept(sock, newsock);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_socket_bind(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        ops_call_int_hook_begain(socket_bind, rc, sock, address, addrlen);
        rc = hooks->socket_bind(sock, address, addrlen);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_socket_connect(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        ops_call_int_hook_begain(socket_connect, rc, sock, address, addrlen);
        rc = hooks->socket_connect(sock, address, addrlen);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_socket_sendmsg(struct socket *sock,
            struct msghdr *msg, int size)
    {
        int rc = 0;

        ops_call_int_hook_begain(socket_sendmsg, rc, sock, msg, size);
        rc = hooks->socket_sendmsg(sock, size);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static int ops_socket_recvmsg(struct socket *sock, struct msghdr *msg,
            int size, int flags)
    {
        int rc = 0;

        ops_call_int_hook_begain(socket_recvmsg, rc, sock, msg, size, flags);
        rc = hooks->socket_recvmsg(sock, size, flags);
        ops_call_int_hook_end(rc);

        return rc;
    }

    static void ops_sk_free_security(struct sock *sk)
    {
        ops_call_void_hook_begain(sk_free_security, sk);
        hooks->sk_free_security(sk);
        ops_call_void_hook_end();
    }
#endif

#define OPS_LSM_HOOK_INIT(FUNC) _mid_hooks.FUNC = ops_##FUNC

static void ops_mid_hooks_init(void)
{
    memcpy(&_mid_hooks, lsm_org_ops, sizeof(_mid_hooks));
    strcpy(_mid_hooks.name, KOSEC_SYSFS_NAME "_ops");
    OPS_LSM_HOOK_INIT(ptrace_access_check);
    OPS_LSM_HOOK_INIT(bprm_check_security);
    OPS_LSM_HOOK_INIT(sb_kern_mount);
    OPS_LSM_HOOK_INIT(sb_mount);
#ifdef CONFIG_SECURITY_PATH
    OPS_LSM_HOOK_INIT(path_unlink);
    OPS_LSM_HOOK_INIT(path_mkdir);
    OPS_LSM_HOOK_INIT(path_rmdir);
    OPS_LSM_HOOK_INIT(path_mknod);
    OPS_LSM_HOOK_INIT(path_truncate);
    OPS_LSM_HOOK_INIT(path_symlink);
    OPS_LSM_HOOK_INIT(path_link);
    OPS_LSM_HOOK_INIT(path_rename);
    OPS_LSM_HOOK_INIT(path_chmod);
    OPS_LSM_HOOK_INIT(path_chown);
#endif
    OPS_LSM_HOOK_INIT(inode_free_security);
    OPS_LSM_HOOK_INIT(inode_create);
    OPS_LSM_HOOK_INIT(inode_link);
    OPS_LSM_HOOK_INIT(inode_mknod);
    OPS_LSM_HOOK_INIT(inode_symlink);
    OPS_LSM_HOOK_INIT(inode_unlink);
    OPS_LSM_HOOK_INIT(inode_mkdir);
    OPS_LSM_HOOK_INIT(inode_rmdir);
    OPS_LSM_HOOK_INIT(inode_rename);
    OPS_LSM_HOOK_INIT(inode_setattr);
    OPS_LSM_HOOK_INIT(file_free_security);
    OPS_LSM_HOOK_INIT(file_ioctl);
    OPS_LSM_HOOK_INIT(mmap_file);
    OPS_LSM_HOOK_INIT(file_open);
    OPS_LSM_HOOK_INIT(task_free);
    OPS_LSM_HOOK_INIT(task_kill);
#ifdef CONFIG_SECURITY_NETWORK
    OPS_LSM_HOOK_INIT(socket_create);
    OPS_LSM_HOOK_INIT(socket_post_create);
    OPS_LSM_HOOK_INIT(socket_accept);
    OPS_LSM_HOOK_INIT(socket_bind);
    OPS_LSM_HOOK_INIT(socket_connect);
    OPS_LSM_HOOK_INIT(socket_sendmsg);
    OPS_LSM_HOOK_INIT(socket_recvmsg);
    OPS_LSM_HOOK_INIT(sk_free_security);
#endif
}

static int comm_lsm_init_hook(void)
{
    struct security_operations **psec_ops;

    psec_ops = ops_find_security_ops();
    if (IS_ERR(psec_ops)) {
        return PTR_ERR(psec_ops);
    }
    lsm_org_ops = *psec_ops;
    pp_lsm_ops = psec_ops;

    ops_mid_hooks_init();

    LOG_INFO("osec hook init security_ops ok\n");
    return 0;
}

extern int hook_replace_pointer(void **pp_addr, void *pointer);
static void comm_lsm_uninit_hook(void)
{
    struct security_operations **psec_ops = ops_find_security_ops();
    if (!lsm_org_ops) return;
    if (*psec_ops == &_mid_hooks) {
        hook_replace_pointer((void **)pp_lsm_ops, lsm_org_ops);
        lsm_org_ops = NULL;
    } else {
        LOG_ERROR("osec hook disable ops: there were other hooked after us!\n");
    }
}

static int comm_lsm_enable(void)
{
    int rc;

    if (!lsm_org_ops) {
        return -ENOTSUPP;
    }
    if (test_and_set_bit(0, &ops_lsm_enabled)) {
        return -EAGAIN;
    }

    rc = hook_replace_pointer((void **)pp_lsm_ops, &_mid_hooks);
    if (rc != 0) {
        clear_bit(0, &ops_lsm_enabled);
    }
    LOG_INFO("osec hook enable ops: %d\n", rc);

    return 0;
}

static int comm_lsm_disable(void)
{
    int rc = -EFAULT;

    if (test_and_clear_bit(0, &ops_lsm_enabled)) {
        //此时注销会导致系统崩溃,移到模块卸载时处理
        rc = 0;
        LOG_INFO("osec hook disable ops\n");
    }

    return rc;
}

static int comm_lsm_is_enabled(void)
{
    return test_bit(0, &ops_lsm_enabled);
}

static char * comm_lsm_hook_mode(void)
{
    return "lsm-hook";
}

static int comm_lsm_register_hook(struct kvd_security_operations *hooks)
{
    return comm_lsm_register_do(hooks);
}

static int comm_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    return comm_lsm_unregister_do(hooks);
}
