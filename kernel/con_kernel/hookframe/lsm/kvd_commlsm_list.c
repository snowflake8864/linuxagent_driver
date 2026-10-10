/*
 * 适用Linux版本: KERNEL_VERSION >= 4.2.0
 * 及 华为UOS(CONFIG_SECURITY_WRITABLE_HOOKS), KERNEL_VERSION >= 4.19.0
 * */
#include <linux/lsm_hooks.h>
#include "hook/wp.h"

static struct security_hook_heads *_hook_heads = NULL;
static struct security_hook_list _mid_hooks[64];
static int _mid_hooks_count = 0;
static unsigned long list_lsm_enabled = 0;

extern int hook_search_ksym(const char *sym_name, unsigned long *sym_addr);
static struct security_hook_heads * list_find_security_heads(void)
{
    struct security_hook_heads *pheads;

    pheads = (void *)kallsyms_lookup_name("security_hook_heads");
    if (!pheads) {
        hook_search_ksym("security_hook_heads",
                (unsigned long*)&pheads);
    }

    return pheads;
}

static int list_ptrace_access_check(struct task_struct *child,
        unsigned int mode)
{
    int rc = 0;

    call_hook_begin(ptrace_access_check);
    rc = hooks->ptrace_access_check(child, mode);
    call_int_hook_end(rc);

    return rc;
}

static int list_bprm_check_security(struct linux_binprm *bprm)
{
    int rc = 0;

    call_hook_begin(bprm_check_security);
    rc = hooks->bprm_check_security(bprm);
    call_int_hook_end(rc);

    return rc;
}

//rhel-8.4, linux-5.1.0 and later
#if defined(RHEL_RELEASE_CODE) && defined(RHEL_RELEASE_VERSION)
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 4)
        #define USED_SB_KERN_MOUNT_NEW
    #endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) 
static int list_sb_kern_mount(const struct super_block *sb)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) || \
        defined(USED_SB_KERN_MOUNT_NEW)
static int list_sb_kern_mount(struct super_block *sb)
#else
static int list_sb_kern_mount(struct super_block *sb, int flags, void *data)
#endif
{
    int rc = 0;

    call_hook_begin(sb_kern_mount);
    rc = hooks->sb_kern_mount(sb);
    call_int_hook_end(rc);

    return rc;
}

static int list_sb_mount(const char *dev_name,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
        const struct path *path,
#else
        struct path *path,
#endif
        const char *type, unsigned long flags, void *data)
{
    int rc = 0;

    call_hook_begin(sb_mount);
    rc = hooks->sb_mount(dev_name, (const struct path *)path,
			type, flags, data);
    call_int_hook_end(rc);

    return rc;
}

#ifdef CONFIG_SECURITY_PATH
    static int list_path_unlink(
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

    static int list_path_mkdir(
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
            const struct path *dir,
    #else
            struct path *dir,
    #endif
            struct dentry *dentry,
            umode_t mode)
    {
        int rc = 0;
        call_hook_begin(path_mkdir);
        rc = hooks->path_mkdir((const struct path *)dir,
                dentry, mode);
        call_int_hook_end(rc);

        return rc;
    }

    static int list_path_rmdir(
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

    static int list_path_mknod(
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

    static int list_path_truncate(
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

    static int list_path_symlink(
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

    static int list_path_link(struct dentry *old_dentry,
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
    static int list_path_rename(const struct path *old_dir,
        struct dentry *old_dentry, const struct path *new_dir,
        struct dentry *new_dentry, unsigned int flags)
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
    static int list_path_rename(const struct path *old_dir,
            struct dentry *old_dentry, const struct path *new_dir,
            struct dentry *new_dentry)
    #else
    static int list_path_rename(struct path *old_dir,
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

    static int list_path_chmod(
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

    static int list_path_chown(
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

static void list_inode_free_security(struct inode *inode)
{
    call_hook_begin(inode_free_security);
    hooks->inode_free_security(inode);
    call_void_hook_end();
}

static int list_inode_link(struct dentry *old_dentry, struct inode *dir,
                        struct dentry *new_dentry)
{
    int rc = 0;
    call_hook_begin(inode_link);
    rc = hooks->inode_link(old_dentry, dir, new_dentry);
    call_int_hook_end(rc);

    return rc;
}

static int list_inode_mknod(struct inode *dir, struct dentry *dentry,
                        umode_t mode, dev_t dev)
{
    int rc = 0;
    call_hook_begin(inode_mknod);
    rc = hooks->inode_mknod(dir, dentry, mode, dev);
    call_int_hook_end(rc);

    return rc;
}

static int list_inode_symlink(struct inode *dir, struct dentry *dentry,
                        const char *old_name)
{
    int rc = 0;
    call_hook_begin(inode_symlink);
    rc = hooks->inode_symlink(dir, dentry, old_name);
    call_int_hook_end(rc);

    return rc;
}

static int list_inode_create(struct inode *dir,
        struct dentry *dentry, umode_t mode)
{
    int rc = 0;

    call_hook_begin(inode_create);
    rc = hooks->inode_create(dir, dentry, mode);
    call_int_hook_end(rc);

    return rc;
}

static int list_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    call_hook_begin(inode_unlink);
    rc = hooks->inode_unlink(dir, dentry);
    call_int_hook_end(rc);

    return rc;
}

static int list_inode_mkdir(struct inode *dir, struct dentry *dentry,
        umode_t mode)
{
    int rc = 0;

    call_hook_begin(inode_mkdir);
    rc = hooks->inode_mkdir(dir, dentry, mode);
    call_int_hook_end(rc);

    return rc;
}

static int list_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;

    call_hook_begin(inode_rmdir);
    rc = hooks->inode_rmdir(dir, dentry);
    call_int_hook_end(rc);

    return rc;
}

static int list_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry)
{
    int rc = 0;

    call_hook_begin(inode_rename);
    rc = hooks->inode_rename(old_dir, old_dentry, new_dir, new_dentry);
    call_int_hook_end(rc);

    return rc;
}

static int list_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    int rc = 0;

    call_hook_begin(inode_setattr);
    rc = hooks->inode_setattr(dentry, attr);
    call_int_hook_end(rc);

    return rc;
}

static void list_file_free_security(struct file *file)
{
    call_hook_begin(file_free_security);
    hooks->file_free_security(file);
    call_void_hook_end();
}

static int list_file_ioctl(struct file *file, unsigned int cmd,
        unsigned long arg)
{
    int rc = 0;

    call_hook_begin(file_ioctl);
    rc = hooks->file_ioctl(file, cmd, arg);
    call_int_hook_end(rc);

    return rc;
}

static int list_mmap_file(struct file *file, unsigned long reqprot,
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
static int list_file_open(struct file *file)
#else
static int list_file_open(struct file *file, const struct cred *cred)
#endif
{
    int rc = 0;

    call_hook_begin(file_open);
    rc = hooks->file_open(file);
    call_int_hook_end(rc);

    return rc;
}

static void list_task_free(struct task_struct *task)
{
    call_hook_begin(task_free);
    hooks->task_free(task);
    call_void_hook_end();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) || \
            defined(KVD_COMMLSM_TASK_KILL)
    static inline int list_is_info_special(struct kernel_siginfo *info)
    {
        return info <= (struct kernel_siginfo *)SEND_SIG_FORCED;
    }

    static int list_task_kill(struct task_struct *p,
            struct kernel_siginfo *_info,
            int sig, const struct cred *cred)
    {
        int rc = 0;
        struct siginfo *info = (struct siginfo *)_info;
        struct siginfo dup_info;

        if (!list_is_info_special(_info)) {
            info = &dup_info;
            memset(info, 0, sizeof(*info));
            memcpy(info, _info, sizeof(*info));
        }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    static int list_task_kill(struct task_struct *p, struct siginfo *info,
            int sig, const struct cred *cred)
    {
        int rc = 0;
#else
    static int list_task_kill(struct task_struct *p, struct siginfo *info,
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
    static int list_socket_create(int family, int type,
            int protocol, int kern)
    {
        int rc = 0;

        call_hook_begin(socket_create);
        rc = hooks->socket_create(family, type, protocol, kern);
        call_int_hook_end(rc);

        return rc;
    }

    static int list_socket_post_create(struct socket *sock, int family,
            int type, int protocol, int kern)
    {
        int rc = 0;

        call_hook_begin(socket_post_create);
        rc = hooks->socket_post_create(sock, family, type, protocol, kern);
        call_int_hook_end(rc);

        return rc;
    }

    static int list_socket_accept(struct socket *sock, struct socket *newsock)
    {
        int rc = 0;

        call_hook_begin(socket_accept);
        rc = hooks->socket_accept(sock, newsock);
        call_int_hook_end(rc);

        return rc;
    }

    static int list_socket_bind(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        call_hook_begin(socket_bind);
        rc = hooks->socket_bind(sock, address, addrlen);
        call_int_hook_end(rc);

        return rc;
    }

    static int list_socket_connect(struct socket *sock,
            struct sockaddr *address, int addrlen)
    {
        int rc = 0;

        call_hook_begin(socket_connect);
        rc = hooks->socket_connect(sock, address, addrlen);
        call_int_hook_end(rc);

        return rc;
    }

    static int list_socket_sendmsg(struct socket *sock,
            struct msghdr *msg, int size)
    {
        int rc = 0;

        call_hook_begin(socket_sendmsg);
        rc = hooks->socket_sendmsg(sock, size);
        call_int_hook_end(rc);

        return rc;
    }

    static int list_socket_recvmsg(struct socket *sock,
            struct msghdr *msg, int size, int flags)
    {
        int rc = 0;

        call_hook_begin(socket_recvmsg);
        rc = hooks->socket_recvmsg(sock, size, flags);
        call_int_hook_end(rc);

        return rc;
    }

    static void list_sk_free_security(struct sock *sk)
    {
        call_hook_begin(sk_free_security);
        hooks->sk_free_security(sk);
        call_void_hook_end();
    }
#endif

#define LIST_LSM_HOOK_INIT(HOOK_LIST, HEAD, HOOK) \
	do { \
		struct security_hook_list *plist = &HOOK_LIST; \
		if (_hook_heads) { \
			plist->head = &_hook_heads->HEAD; \
			plist->hook.HEAD = HOOK; \
		} \
	} while (0)

static void list_mid_hooks_init(void)
{
    _mid_hooks_count = 0;
	memset(_mid_hooks, 0, sizeof(_mid_hooks));
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			ptrace_access_check, list_ptrace_access_check);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			bprm_check_security, list_bprm_check_security);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			sb_kern_mount,list_sb_kern_mount);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			sb_mount,     list_sb_mount);
#ifdef CONFIG_SECURITY_PATH
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_unlink,  list_path_unlink);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_mkdir,   list_path_mkdir);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_rmdir,   list_path_rmdir);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_mknod,   list_path_mknod);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_truncate,list_path_truncate);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_symlink, list_path_symlink);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_link,    list_path_link);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_rename,  list_path_rename);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_chmod,   list_path_chmod);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			path_chown,   list_path_chown);
#endif
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_free_security,list_inode_free_security);
    LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_link,         list_inode_link);
    LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_mknod,         list_inode_mknod);
    LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_symlink,         list_inode_symlink);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_create,       list_inode_create);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_unlink,       list_inode_unlink);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_mkdir,        list_inode_mkdir);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_rmdir,        list_inode_rmdir);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_rename,       list_inode_rename);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			inode_setattr,      list_inode_setattr);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			file_free_security, list_file_free_security);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			file_ioctl,         list_file_ioctl);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			mmap_file,          list_mmap_file);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			file_open,          list_file_open);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			task_free, list_task_free);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			task_kill, list_task_kill);
#ifdef CONFIG_SECURITY_NETWORK
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			socket_create,    list_socket_create);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			socket_post_create, list_socket_post_create);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			socket_accept, list_socket_accept);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			socket_bind,      list_socket_bind);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			socket_connect,   list_socket_connect);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			socket_sendmsg,   list_socket_sendmsg);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			socket_recvmsg,   list_socket_recvmsg);
	LIST_LSM_HOOK_INIT(_mid_hooks[_mid_hooks_count++],
			sk_free_security, list_sk_free_security);
#endif
}

static int list_mid_hooks_add(void)
{
    int i;
	unsigned long old_v;

    if (disable_wp(&old_v)) {
        return -EAGAIN;
    }
    for (i = 0; i < _mid_hooks_count; i++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
        hlist_add_tail_rcu(&_mid_hooks[i].list, _mid_hooks[i].head);
#else
        list_add_tail_rcu(&_mid_hooks[i].list, _mid_hooks[i].head);
#endif
    }
    restore_wp(old_v);

    return 0;
}

static int list_mid_hooks_del(void)
{
    int i;
    unsigned long old_v;

    if (disable_wp(&old_v)) {
        return -EAGAIN;
    }
    for (i = 0; i < _mid_hooks_count; i++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
        hlist_del_rcu(&_mid_hooks[i].list);
#else
        list_del_rcu(&_mid_hooks[i].list);
#endif
    }
    restore_wp(old_v);

    /* mips上使用必崩, 暂时移除
     * loongarch
     * 麒麟990
     * */
#if !defined(__mips__) && !defined(__loongarch__) \
        && !defined(CONFIG_HUAWEI_ARMPC_PLATFORM) \
        && !defined(__sw_64__)
    synchronize_rcu();
#endif

    return 0;
}

static int list_lsm_init_hook(void)
{
    struct security_hook_heads* pheads;

    pheads = list_find_security_heads();
    if(!pheads) {
        LOG_ERROR("failed to find security_hook_heads\n");
        return -ENOTSUPP;
    }
    _hook_heads = pheads;
    LOG_INFO("find security_hook_heads at: 0x%lx\n",(long)pheads);

    list_mid_hooks_init();
    return 0;
}

static void list_lsm_uninit_hook(void)
{
    _hook_heads = NULL;
    if (test_and_clear_bit(LSM_STATE_INITED, &list_lsm_enabled)) {
        //在centos9平台上在用户态退出时使用通知链通知注销
        //会导致系统崩溃,放在模块卸载时注销
        list_mid_hooks_del();
    }
}

static int list_enable_lsm(void)
{
    int rc;

    if (!_hook_heads) {
        return -ENOTSUPP;
    }
    //已经向系统注册过，不再注册
    if (test_bit(LSM_STATE_INITED, &list_lsm_enabled)) {
        return -EAGAIN;
    }

    if (test_and_set_bit(LSM_STATE_ENABLED, &list_lsm_enabled)) {
        return -EAGAIN;
    }

    rc = list_mid_hooks_add();
    if (rc != 0) {
        clear_bit(LSM_STATE_ENABLED, &list_lsm_enabled);
    } else {
        //标记向系统注册了lsm回调
        set_bit(LSM_STATE_INITED, &list_lsm_enabled);
    }
    LOG_INFO("osec hook enable list: %d\n", rc);

    return rc;
}

static int list_disable_lsm(void)
{
    int rc = -EFAULT;

    if (test_and_clear_bit(LSM_STATE_ENABLED, &list_lsm_enabled)) {
        //在centos9此时注销会导致系统崩溃,移到模块卸载时处理
        //rc = list_mid_hooks_del();
        rc = 0;
        LOG_INFO("osec hook disable list: %d\n", rc);
    }

    return rc;
}

static int list_lsm_is_enabled(void)
{
    return test_bit(LSM_STATE_ENABLED, &list_lsm_enabled);
}

static char * list_lsm_hook_mode(void)
{
    return "lsm-hook";
}

static int list_lsm_register_hook(struct kvd_security_operations *hooks)
{
    if (!_hook_heads) {
        return -EFAULT;
    }
    return comm_lsm_register_do(hooks);
}

static int list_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    if (!_hook_heads) {
        return -EAGAIN;
    }
    return comm_lsm_unregister_do(hooks);
}

#include "kvd_commlsm_kws.c"
#include "kvd_commlsm_uos.c"

static int comm_lsm_init_hook(void)
{
    int rc;

    rc = kws_lsm_init_hook();
    if (rc == 0) {
        return rc;
    }

    rc = uos_lsm_init_hook();
    if (rc == 0) {
        return rc;
    }

    return list_lsm_init_hook();
}

static void comm_lsm_uninit_hook(void)
{
    if (test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)) {
        kws_lsm_uninit_hook();
        return;
    }

    if (test_bit(COMMLSM_TYPE_UOS, &lsm_type_use)) {
        uos_lsm_uninit_hook();
        return;
    }

    list_lsm_uninit_hook();
}

static int comm_lsm_enable(void)
{
    if (test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)) {
        return kws_enable_lsm();
    }

    if (test_bit(COMMLSM_TYPE_UOS, &lsm_type_use)) {
        return uos_enable_lsm();
    }

    return list_enable_lsm();
}

static int comm_lsm_disable(void)
{
    if (test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)) {
        return kws_disable_lsm();
    }

    if (test_bit(COMMLSM_TYPE_UOS, &lsm_type_use)) {
        return uos_disable_lsm();
    }

    return list_disable_lsm();
}

static int comm_lsm_is_enabled(void)
{
    if (test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)) {
        return kws_lsm_is_enabled();
    }

    if (test_bit(COMMLSM_TYPE_UOS, &lsm_type_use)) {
        return uos_lsm_is_enabled();
    }

    return list_lsm_is_enabled();
}

static char * comm_lsm_hook_mode(void)
{
    if (test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)) {
        return kws_lsm_hook_mode();
    }

    if (test_bit(COMMLSM_TYPE_UOS, &lsm_type_use)) {
        return uos_lsm_hook_mode();
    }

    return list_lsm_hook_mode();
}

static int comm_lsm_register_hook(struct kvd_security_operations *hooks)
{
    if (test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)) {
        return kws_lsm_register_hook(hooks);
    }

    if (test_bit(COMMLSM_TYPE_UOS, &lsm_type_use)) {
        return uos_lsm_register_hook(hooks);
    }

    return list_lsm_register_hook(hooks);
}

static int comm_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    if (test_bit(COMMLSM_TYPE_KWS, &lsm_type_use)) {
        return kws_lsm_unregister_hook(hooks);
    }

    if (test_bit(COMMLSM_TYPE_UOS, &lsm_type_use)) {
        return uos_lsm_unregister_hook(hooks);
    }

    return list_lsm_unregister_hook(hooks);
}
