#ifndef KWS_COMMLSM_HOOK_H
#define KWS_COMMLSM_HOOK_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/time.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/security.h>

/*
 *Note:
 *此处为了类型定义的兼容，我们将没有的类型都定义一下
 *不然很多低版本的系统上无法编译过去
 *如果类型定义在不同系统之间不兼容也不要紧，因为我们不用考虑4.4以下版本的
 *在4.4以上版本的内核这些类型定义都是存在的；
 *所以很多低版本上我们直接将一些结构体时直接定义为空即可
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
struct cred;
#endif

struct timespec64;
struct user_namespace;

/**
 * struct kws_lsm_list_options - KWS Mdule hook function list
 *
 * * @ptrace_access_check:
 *	Check permission before allowing the current process to trace the
 *	@child process.
 *	Security modules may also want to perform a process tracing check
 *	during an execve in the set_security or apply_creds hooks of
 *	tracing check during an execve in the bprm_set_creds hook of
 *	binprm_security_ops if the process is being traced and its security
 *	attributes would be changed by the execve.
 *	@child contains the task_struct structure for the target process.
 *	@mode contains the PTRACE_MODE flags indicating the form of access.
 *	Return 0 if permission is granted.
 * @ptrace_traceme:
 *	Check that the @parent process has sufficient permission to trace the
 *	current process before allowing the current process to present itself
 *	to the @parent process for tracing.
 *	@parent contains the task_struct structure for debugger process.
 *	Return 0 if permission is granted.
 * @capset:
 *	Set the @effective, @inheritable, and @permitted capability sets for
 *	the current process.
 *	@new contains the new credentials structure for target process.
 *	@old contains the current credentials structure for target process.
 *	@effective contains the effective capability set.
 *	@inheritable contains the inheritable capability set.
 *	@permitted contains the permitted capability set.
 *	Return 0 and update @new if permission is granted.
 * @capable:
 *	Check whether the @tsk process has the @cap capability in the indicated
 *	credentials.
 *	@cred contains the credentials to use.
 *	@ns contains the user namespace we want the capability in
 *	@cap contains the capability <include/linux/capability.h>.
 *	@audit contains whether to write an audit message or not
 *	Return 0 if the capability is granted for @tsk.
 * @syslog:
 *	Check permission before accessing the kernel message ring or changing
 *	logging to the console.
 *	See the syslog(2) manual page for an explanation of the @type values.
 *	@type contains the type of action.
 *	@from_file indicates the context of action (if it came from /proc).
 *	Return 0 if permission is granted.
 * @settime:
 *	Check permission to change the system time.
 *	struct timespec64 is defined in include/linux/time64.h and timezone
 *	is defined in include/linux/time.h
 *	@ts contains new time
 *	@tz contains new timezone
 *	Return 0 if permission is granted.
 *
 * Security hooks for program execution operations.
 *
 * @bprm_check_security:
 *	This hook mediates the point when a search for a binary handler will
 *	begin.  It allows a check the @bprm->security value which is set in the
 *	preceding set_creds call.  The primary difference from set_creds is
 *	that the argv list and envp list are reliably available in @bprm.  This
 *	hook may be called multiple times during a single execve; and in each
 *	pass set_creds is called first.
 *	@bprm contains the linux_binprm structure.
 *	Return 0 if the hook is successful and permission is granted.
 *
 * Security hooks for filesystem operations.
 *
 * @sb_mount:
 *	Check permission before an object specified by @dev_name is mounted on
 *	the mount point named by @nd.  For an ordinary mount, @dev_name
 *	identifies a device if the file system type requires a device.  For a
 *	remount (@flags & MS_REMOUNT), @dev_name is irrelevant.  For a
 *	loopback/bind mount (@flags & MS_BIND), @dev_name identifies the
 *	pathname of the object being mounted.
 *	@dev_name contains the name for object being mounted.
 *	@path contains the path for mount point object.
 *	@type contains the filesystem type.
 *	@flags contains the mount flags.
 *	@data contains the filesystem-specific data.
 *	Return 0 if permission is granted.
 * @sb_umount:
 *	Check permission before the @mnt file system is unmounted.
 *	@mnt contains the mounted file system.
 *	@flags contains the unmount flags, e.g. MNT_FORCE.
 *	Return 0 if permission is granted.
 * @sb_pivotroot:
 *	Check permission before pivoting the root filesystem.
 *	@old_path contains the path for the new location of the
 *	current root (put_old).
 *	@new_path contains the path for the new root (new_root).
 *	Return 0 if permission is granted.
 *
 *
 * Security hooks for inode operations.
 *
 * @inode_create:
 *	Check permission to create a regular file.
 *	@dir contains inode structure of the parent of the new file.
 *	@dentry contains the dentry structure for the file to be created.
 *	@mode contains the file mode of the file to be created.
 *	Return 0 if permission is granted.
 * @inode_link:
 *	Check permission before creating a new hard link to a file.
 *	@old_dentry contains the dentry structure for an existing
 *	link to the file.
 *	@dir contains the inode structure of the parent directory
 *	of the new link.
 *	@new_dentry contains the dentry structure for the new link.
 *	Return 0 if permission is granted.
 * @path_link:
 *	Check permission before creating a new hard link to a file.
 *	@old_dentry contains the dentry structure for an existing link
 *	to the file.
 *	@new_dir contains the path structure of the parent directory of
 *	the new link.
 *	@new_dentry contains the dentry structure for the new link.
 *	Return 0 if permission is granted.
 * @inode_unlink:
 *	Check the permission to remove a hard link to a file.
 *	@dir contains the inode structure of parent directory of the file.
 *	@dentry contains the dentry structure for file to be unlinked.
 *	Return 0 if permission is granted.
 * @path_unlink:
 *	Check the permission to remove a hard link to a file.
 *	@dir contains the path structure of parent directory of the file.
 *	@dentry contains the dentry structure for file to be unlinked.
 *	Return 0 if permission is granted.
 * @inode_symlink:
 *	Check the permission to create a symbolic link to a file.
 *	@dir contains the inode structure of parent directory of
 *	the symbolic link.
 *	@dentry contains the dentry structure of the symbolic link.
 *	@old_name contains the pathname of file.
 *	Return 0 if permission is granted.
 * @path_symlink:
 *	Check the permission to create a symbolic link to a file.
 *	@dir contains the path structure of parent directory of
 *	the symbolic link.
 *	@dentry contains the dentry structure of the symbolic link.
 *	@old_name contains the pathname of file.
 *	Return 0 if permission is granted.
 * @inode_mkdir:
 *	Check permissions to create a new directory in the existing directory
 *	associated with inode structure @dir.
 *	@dir contains the inode structure of parent of the directory
 *	to be created.
 *	@dentry contains the dentry structure of new directory.
 *	@mode contains the mode of new directory.
 *	Return 0 if permission is granted.
 * @path_mkdir:
 *	Check permissions to create a new directory in the existing directory
 *	associated with path structure @path.
 *	@dir contains the path structure of parent of the directory
 *	to be created.
 *	@dentry contains the dentry structure of new directory.
 *	@mode contains the mode of new directory.
 *	Return 0 if permission is granted.
 * @inode_rmdir:
 *	Check the permission to remove a directory.
 *	@dir contains the inode structure of parent of the directory
 *	to be removed.
 *	@dentry contains the dentry structure of directory to be removed.
 *	Return 0 if permission is granted.
 * @path_rmdir:
 *	Check the permission to remove a directory.
 *	@dir contains the path structure of parent of the directory to be
 *	removed.
 *	@dentry contains the dentry structure of directory to be removed.
 *	Return 0 if permission is granted.
 * @inode_mknod:
 *	Check permissions when creating a special file (or a socket or a fifo
 *	file created via the mknod system call).  Note that if mknod operation
 *	is being done for a regular file, then the create hook will be called
 *	and not this hook.
 *	@dir contains the inode structure of parent of the new file.
 *	@dentry contains the dentry structure of the new file.
 *	@mode contains the mode of the new file.
 *	@dev contains the device number.
 *	Return 0 if permission is granted.
 * @path_mknod:
 *	Check permissions when creating a file. Note that this hook is called
 *	even if mknod operation is being done for a regular file.
 *	@dir contains the path structure of parent of the new file.
 *	@dentry contains the dentry structure of the new file.
 *	@mode contains the mode of the new file.
 *	@dev contains the undecoded device number. Use new_decode_dev() to get
 *	the decoded device number.
 *	Return 0 if permission is granted.
 * @inode_rename:
 *	Check for permission to rename a file or directory.
 *	@old_dir contains the inode structure for parent of the old link.
 *	@old_dentry contains the dentry structure of the old link.
 *	@new_dir contains the inode structure for parent of the new link.
 *	@new_dentry contains the dentry structure of the new link.
 *	Return 0 if permission is granted.
 * @path_rename:
 *	Check for permission to rename a file or directory.
 *	@old_dir contains the path structure for parent of the old link.
 *	@old_dentry contains the dentry structure of the old link.
 *	@new_dir contains the path structure for parent of the new link.
 *	@new_dentry contains the dentry structure of the new link.
 *	Return 0 if permission is granted.
 * @path_chmod:
 *	Check for permission to change DAC's permission of a file or directory.
 *	@dentry contains the dentry structure.
 *	@mnt contains the vfsmnt structure.
 *	@mode contains DAC's mode.
 *	Return 0 if permission is granted.
 * @path_chown:
 *	Check for permission to change owner/group of a file or directory.
 *	@path contains the path structure.
 *	@uid contains new owner's ID.
 *	@gid contains new group's ID.
 *	Return 0 if permission is granted.
 * @path_chroot:
 *	Check for permission to change root directory.
 *	@path contains the path structure.
 *	Return 0 if permission is granted.
 * @wfile_close:
 *  write regular file close notify. no need return val
 *	@filename contains the closing write-file-full path
 *	@kst	struct kstat for filename
 * @inode_permission:
 *	Check permission before accessing an inode.  This hook is called by the
 *	existing Linux permission function, so a security module can use it to
 *	provide additional checking for existing Linux permission checks.
 *	Notice that this hook is called when a file is opened (as well as many
 *	other operations), whereas the file_security_ops permission hook is
 *	called when the actual read/write operations are performed.
 *	@inode contains the inode structure to check.
 *	@mask contains the permission mask.
 *	Return 0 if permission is granted.
 * @inode_setattr:
 *	Check permission before setting file attributes.  Note that the kernel
 *	call to notify_change is performed from several locations, whenever
 *	file attributes change (such as when a file is truncated, chown/chmod
 *	operations, transferring disk quotas, etc).
 *	@dentry contains the dentry structure for the file.
 *	@attr is the iattr structure containing the new file attributes.
 *	Return 0 if permission is granted.
 * @path_truncate:
 *	Check permission before truncating a file.
 *	@path contains the path structure for the file.
 *	Return 0 if permission is granted.
 *
 * Security hooks for file operations
 *
 * * @file_permission:
 *	Check file permissions before accessing an open file.  This hook is
 *	called by various operations that read or write files.  A security
 *	module can use this hook to perform additional checking on these
 *	operations, e.g.  to revalidate permissions on use to support privilege
 *	bracketing or policy changes.  Notice that this hook is used when the
 *	actual read/write operations are performed, whereas the
 *	inode_security_ops hook is called when a file is opened (as well as
 *	many other operations).
 *	Caveat:  Although this hook can be used to revalidate permissions for
 *	various system call operations that read or write files, it does not
 *	address the revalidation of permissions for memory-mapped files.
 *	Security modules must handle this separately if they need such
 *	revalidation.
 *	@file contains the file structure being accessed.
 *	@mask contains the requested permissions.
 *	Return 0 if permission is granted.
 * @file_ioctl:
 *	@file contains the file structure.
 *	@cmd contains the operation to perform.
 *	@arg contains the operational arguments.
 *	Check permission for an ioctl operation on @file.  Note that @arg
 *	sometimes represents a user space pointer; in other cases, it may be a
 *	simple integer value.  When @arg represents a user space pointer, it
 *	should never be used by the security module.
 *	Return 0 if permission is granted.
 * @mmap_file:
 *	Check permissions for a mmap operation.  The @file may be NULL, e.g.
 *	if mapping anonymous memory.
 *	@file contains the file structure for file to map (may be NULL).
 *	@reqprot contains the protection requested by the application.
 *	@prot contains the protection that will be applied by the kernel.
 *	@flags contains the operational flags.
 *	Return 0 if permission is granted.
 * @file_lock:
 *	Check permission before performing file locking operations.
 *	Note: this hook mediates both flock and fcntl style locks.
 *	@file contains the file structure.
 *	@cmd contains the posix-translated lock operation to perform
 *	(e.g. F_RDLCK, F_WRLCK).
 *	Return 0 if permission is granted.
 * @file_fcntl:
 *	Check permission before allowing the file operation specified by @cmd
 *	from being performed on the file @file.  Note that @arg sometimes
 *	represents a user space pointer; in other cases, it may be a simple
 *	integer value.  When @arg represents a user space pointer, it should
 *	never be used by the security module.
 *	@file contains the file structure.
 *	@cmd contains the operation to be performed.
 *	@arg contains the operational arguments.
 *	Return 0 if permission is granted.
 * @file_open:
 *	Save open-time permission checking state for later use upon
 *	file_permission, and recheck access if anything has changed
 *	since inode_permission.
 *
 * Security hooks for task operations.
 *
 * @task_alloc:
 *	@task task being allocated.
 *	@clone_flags contains the flags indicating what should be shared.
 *	Handle allocation of task-related resources.
 *	Returns a zero on success, negative values on failure.
 * @task_free:
 *	@task task about to be freed.
 *	Handle release of task-related resources. (Note that this can be called
 *	from interrupt context.)
 * @task_kill:
 *	Check permission before sending signal @sig to @ptarget.  @info can be NULL,
 *	the constant 1, or a pointer to a siginfo structure.  If @info is 1 or
 *	SI_FROMKERNEL(info) is true, then the signal should be viewed as coming
 *	from the kernel and should typically be permitted.
 *	SIGIO signals are handled separately by the send_sigiotask hook in
 *	file_security_ops.
 *	@ptarget contains the task_struct for process.
 *	@info contains the signal information.
 *	@sig contains the signal value.
 *	@cred contains the cred of the process where the signal originated, or
 *	NULL if the current task is the originator.
 *	Return 0 if permission is granted.
 *
 *
 * Security hooks for Unix domain networking.
 *
 * @unix_stream_connect:
 *	Check permissions before establishing a Unix domain stream connection
 *	between @sock and @other.
 *	@sock contains the sock structure.
 *	@other contains the peer sock structure.
 *	@newsk contains the new sock structure.
 *	Return 0 if permission is granted.
 * @unix_may_send:
 *	Check permissions before connecting or sending datagrams from @sock to
 *	@other.
 *	@sock contains the socket structure.
 *	@other contains the peer socket structure.
 *	Return 0 if permission is granted.
 *
 * The @unix_stream_connect and @unix_may_send hooks were necessary because
 * Linux provides an alternative to the conventional file name space for Unix
 * domain sockets.  Whereas binding and connecting to sockets in the file name
 * space is mediated by the typical file permissions (and caught by the mknod
 * and permission hooks in inode_security_ops), binding and connecting to
 * sockets in the abstract name space is completely unmediated.  Sufficient
 * control of Unix domain sockets in the abstract name space isn't possible
 * using only the socket layer hooks, since we need to know the actual target
 * socket, which is not looked up until we are inside the af_unix code.
 *
 * Security hooks for socket operations.
 *
 * @socket_create:
 *	Check permissions prior to creating a new socket.
 *	@family contains the requested protocol family.
 *	@type contains the requested communications type.
 *	@protocol contains the requested protocol.
 *	@kern set to 1 if a kernel socket.
 *	Return 0 if permission is granted.
 * @socket_bind:
 *	Check permission before socket protocol layer bind operation is
 *	performed and the socket @sock is bound to the address specified in the
 *	@address parameter.
 *	@sock contains the socket structure.
 *	@address contains the address to bind to.
 *	@addrlen contains the length of address.
 *	Return 0 if permission is granted.
 * @socket_connect:
 *	Check permission before socket protocol layer connect operation
 *	attempts to connect socket @sock to a remote address, @address.
 *	@sock contains the socket structure.
 *	@address contains the address of remote endpoint.
 *	@addrlen contains the length of address.
 *	Return 0 if permission is granted.
 * @socket_listen:
 *	Check permission before socket protocol layer listen operation.
 *	@sock contains the socket structure.
 *	@backlog contains the maximum length for the pending connection queue.
 *	Return 0 if permission is granted.
 * @socket_accept:
 *	Check permission before accepting a new connection.  Note that the new
 *	socket, @newsock, has been created and some information copied to it,
 *	but the accept operation has not actually been performed.
 *	@sock contains the listening socket structure.
 *	@newsock contains the newly created server socket for connection.
 *	Return 0 if permission is granted.
 * @socket_sendmsg:
 *	Check permission before transmitting a message to another socket.
 *	@sock contains the socket structure.
 *	@msg contains the message to be transmitted.
 *	@size contains the size of message.
 *	Return 0 if permission is granted.
 * @socket_recvmsg:
 *	Check permission before receiving a message from a socket.
 *	@sock contains the socket structure.
 *	@msg contains the message structure.
 *	@size contains the size of message structure.
 *	@flags contains the operational flags.
 *	Return 0 if permission is granted.
 * @socket_shutdown:
 *	Checks permission before all or part of a connection on the socket
 *	@sock is shut down.
 *	@sock contains the socket structure.
 *	@how contains the flag indicating how future sends and receives
 *	are handled.
 *	Return 0 if permission is granted.
 * @inet_conn_request:
 *	Sets the openreq's sid to socket's sid with MLS portion taken
 *	from peer sid.
 * @inet_conn_established:
 *	Sets the connection's peersid to the secmark on skb.
 *
 *
 */
struct kws_security_hook_options {
    struct list_head list;
    const char* name;
    struct module* pmod;
	int (*ptrace_access_check)(struct task_struct *child,
					unsigned int mode);
	int (*ptrace_traceme)(struct task_struct *parent);
	int (*capset)(struct cred *new, const struct cred *old,
			const kernel_cap_t *effective,
			const kernel_cap_t *inheritable,
			const kernel_cap_t *permitted);
	//Note:一定要小心，这个函数调用非常非常频繁
	int (*capable)(const struct cred *cred, struct user_namespace *ns,
			int cap, int audit);
	//Note:一定要小心，这个函数调用非常非常频繁
	int (*syslog)(int type);
	int (*settime)(const struct timespec64 *ts, const struct timezone *tz);

	int (*bprm_check_security)(struct linux_binprm *bprm);

	int (*sb_mount)(const char *dev_name, const struct path *path,
			const char *type, unsigned long flags, void *data);
	int (*sb_umount)(struct vfsmount *mnt, int flags);
	int (*sb_pivotroot)(const struct path *old_path,
                        const struct path *new_path);


// #ifdef CONFIG_SECURITY_PATH
	int (*path_unlink)(const struct path *dir, struct dentry *dentry);
	int (*path_mkdir)(const struct path *dir, struct dentry *dentry,
				umode_t mode);
	int (*path_rmdir)(const struct path *dir, struct dentry *dentry);
	int (*path_mknod)(const struct path *dir, struct dentry *dentry,
				umode_t mode, unsigned int dev);
	int (*path_truncate)(const struct path *path);
	int (*path_symlink)(const struct path *dir, struct dentry *dentry,
				const char *old_name);
	int (*path_link)(struct dentry *old_dentry, const struct path *new_dir,
				struct dentry *new_dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
	int (*path_rename)(const struct path *old_dir, struct dentry *old_dentry,
				const struct path *new_dir, struct dentry *new_dentry,
                unsigned int flags);
#else
	int (*path_rename)(const struct path *old_dir, struct dentry *old_dentry,
				const struct path *new_dir, struct dentry *new_dentry);
#endif
	int (*path_chmod)(const struct path *path, umode_t mode);
	int (*path_chown)(const struct path *path, kuid_t uid, kgid_t gid);
	int (*path_chroot)(const struct path *path);
// #endif

	int (*inode_create)(struct inode *dir, struct dentry *dentry,
				umode_t mode);
	int (*inode_link)(struct dentry *old_dentry, struct inode *dir,
				struct dentry *new_dentry);
	int (*inode_unlink)(struct inode *dir, struct dentry *dentry);
	int (*inode_symlink)(struct inode *dir, struct dentry *dentry,
				const char *old_name);
	int (*inode_mkdir)(struct inode *dir, struct dentry *dentry,
				umode_t mode);
	int (*inode_rmdir)(struct inode *dir, struct dentry *dentry);
	int (*inode_mknod)(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev);
	int (*inode_rename)(struct inode *old_dir, struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry);
	//Note:
	//一定要小心，这个函数调用非常非常频繁，
	//几乎任何文件的访问操作都会调用
	//所以能不用尽量不要用这个函数
	int (*inode_permission)(struct inode *inode, int mask);
	int (*inode_setattr)(struct dentry *dentry, struct iattr *attr);

	//Note:一定要小心，这个函数调用非常非常频繁
	int (*file_permission)(struct file *file,int mask);
	int (*file_ioctl)(struct file *file, unsigned int cmd,
				unsigned long arg);
	int (*mmap_file)(struct file *file, unsigned long reqprot,
				unsigned long prot, unsigned long flags);
	int (*file_lock)(struct file *file, unsigned int cmd);
	//Note:一定要小心，这个函数调用非常非常频繁
	int (*file_fcntl)(struct file *file, unsigned int cmd,
				unsigned long arg);
	int (*file_open)(struct file *file);

	int (*task_alloc)(struct task_struct *task,
                    unsigned long clone_flags);
	void (*task_free)(struct task_struct *task);
    int (*task_kill)(struct task_struct *ptarget,
                    struct siginfo *info,
                    int sig);

	int (*unix_stream_connect)(struct sock *sock, struct sock *other,
					struct sock *newsk);

	int (*socket_create)(int family, int type, int protocol, int kern);
	int (*socket_bind)(struct socket *sock, struct sockaddr *address,
				int addrlen);
	int (*socket_connect)(struct socket *sock, struct sockaddr *address,
				int addrlen);
	int (*socket_listen)(struct socket *sock, int backlog);
	int (*socket_accept)(struct socket *sock, struct socket *newsock);
	int (*socket_sendmsg)(struct socket *sock, struct msghdr *msg,
				int size);
	int (*socket_recvmsg)(struct socket *sock, struct msghdr *msg,
				int size, int flags);
	void (*sk_free_security)(struct sock *sk);
	int (*inet_conn_request)(struct sock *sk, struct sk_buff *skb,
					struct request_sock *req);
	void (*inet_conn_established)(struct sock *sk, struct sk_buff *skb);

	//这个函数内部不用调用d_path,还有vfs_getattr这类函数，不然一定会崩溃
	void (*wfile_close)(const char* filename,const struct kstat* kst);
};

typedef int (*kws_security_register_fn_t)(struct kws_security_hook_options* hooks,
						const char* sig,int insert);
typedef void (*kws_security_unregister_fn_t)(struct kws_security_hook_options* hooks);

#endif
