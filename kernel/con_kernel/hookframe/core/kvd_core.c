#include <linux/types.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/statfs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
#include <linux/cred.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h> //fo get_task_struct,put_task_struct
#include <linux/sched/mm.h> //fo get_task_mm,mmput
#endif

#include "kvd_core.h"
#include "khookframe.h"


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
void nameidata_to_path(struct nameidata* nd,struct path* path)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    path->mnt = nd->mnt;
    path->dentry = nd->dentry;
#else
    *path = nd->path;
#endif
}
#endif

int kvd_user_path_at(int dfd, const char __user *name, unsigned flags,
		 struct path *path)
{
    int rc = -ENOENT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
    struct nameidata nd;
    rc = __user_walk_fd(dfd,name,flags,&nd);
    if(!rc) { nameidata_to_path(&nd,path); }
#else
    rc = user_path_at(dfd,name,flags,path);
#endif

    return rc;
}

//kernel base path lookup
int kvd_path_lookup(const char* pathname,
				unsigned int flags,struct path* path)
{
	int rc = -ENOENT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
	struct nameidata nd;
	rc = path_lookup(pathname,flags,&nd);
	if(!rc) {
        nameidata_to_path(&nd,path);
	}
#else
	rc = kern_path(pathname,flags,path);
#endif

	return rc;
}

void kvd_path_get(struct path* path)
{
    mntget(path->mnt);
	dget(path->dentry);
}

void kvd_path_put(struct path* path)
{
	dput(path->dentry);
	mntput(path->mnt);
}

char* kvd_get_pathname(struct path* path,unsigned int* len)
{
    char* tmp = NULL,*start = NULL;
    char* result = ERR_PTR(-EINVAL);

	if((!path) || (!path->dentry) || (!path->mnt)) {
		goto out;
	}

    result = ERR_PTR(-ENOMEM);
    //Note:此处的__getname是从内核预先创建的全局slab缓存names_cachep中分配的内存
    //一定要使用__putname来释放,另外__getname分配出来的内存大小是PATH_MAX
	tmp = __getname();
	if(!tmp) { goto out; }

    /* get the path */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
    start = d_path(path->dentry,path->mnt, tmp,PATH_MAX);
#else
    start = d_path(path,tmp,PATH_MAX);
#endif
    if(IS_ERR(start)) {
		result = start;
		goto out;
	}

    result = tmp;
	*len = tmp + PATH_MAX - start - 1;
	memmove(result,start,*len);
    result[*len] = '\0';

    return result;

out:
	if(tmp) { __putname(tmp); }
    return result;
}

void kvd_put_pathname(const char* pathname)
{
	if(pathname && !IS_ERR(pathname)) {
		__putname(pathname);
	}
}

void kvd_get_fs_root(struct fs_struct* fs,struct path* root)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	get_fs_root(fs,root);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
    read_lock(&fs->lock);
    root->mnt = mntget(fs->root.mnt);
    root->dentry = dget(fs->root.dentry);
    read_unlock(&fs->lock);
#else
	read_lock(&fs->lock);
	root->mnt = mntget(fs->rootmnt);
	root->dentry = dget(fs->root);
	read_unlock(&fs->lock);
#endif
}

void kvd_get_fs_pwd(struct fs_struct* fs,struct path* pwd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	get_fs_pwd(fs,pwd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
    read_lock(&fs->lock);
    pwd->mnt = mntget(fs->pwd.mnt);
    pwd->dentry = dget(fs->pwd.dentry);
    read_unlock(&fs->lock);
#else
	read_lock(&fs->lock);
	pwd->mnt = mntget(fs->pwdmnt);
	pwd->dentry = dget(fs->pwd);
	read_unlock(&fs->lock);
#endif
}

int kvd_filp_path(struct file* filp,struct path* path)
{
    int rc = -EINVAL;

	if(unlikely(!filp)) { goto out; }
   
    rc = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	path->mnt = mntget(filp->f_vfsmnt);
	path->dentry = dget(filp->f_dentry);
#else
	path->mnt = mntget(filp->f_path.mnt);
    path->dentry = dget(filp->f_path.dentry);
#endif
    
    //两者都不为空才表示成功
    if(path->mnt && path->dentry) {
        goto out;
    }

    rc = -EBADF;
    if(path->mnt) { mntput(path->mnt); }
    if(path->dentry) { dput(path->dentry); }

out:
    return rc;
}

/*
 * get pathname by struct file
 * you must call kvd_put_pathname to free the return-value
 */
char* kvd_filp_pathname(struct file* filp,unsigned int* pathlen)
{
    struct path path;
	char* pathname = NULL;

	pathname = ERR_PTR(-EINVAL);
	if(unlikely(!filp)) { goto out; }

    kvd_filp_path(filp,&path);
	pathname = kvd_get_pathname(&path,pathlen);
    kvd_path_put(&path);

out:
	return pathname;
}

int kvd_dentry_path(struct dentry *dentry, struct path *path)
{

	if (!dentry || !path || 
        !(current->fs) || 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        !(current->fs->pwd.mnt)) 
#else
        !(current->fs->pwdmnt))
#endif
    {
		return -EINVAL;
	}	

	path->dentry = dget(dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	path->mnt = mntget(current->fs->pwd.mnt);
#else
    path->mnt = mntget(current->fs->pwdmnt);
#endif
	
	return 0;
}

//Google Murmurhash
uint32_t kvd_murmur_hash2(const u_char *data, size_t len)
{
	uint32_t  h, k;
	h = 0 ^ len;
	while (len >= 4) {
		k  = data[0];
		k |= data[1] << 8;
		k |= data[2] << 16;
        k |= data[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;

        h *= 0x5bd1e995;
        h ^= k;

        data += 4;
        len -= 4;
	}

	switch (len) {
	case 3:
		h ^= data[2] << 16;
	case 2:
		h ^= data[1] << 8;
	case 1:
		h ^= data[0];
		h *= 0x5bd1e995;
	}

	h ^= h >> 13;
	h *= 0x5bd1e995;
	h ^= h >> 15;

	return h;
}



uid_t kvd_get_kstat_uid(const struct kstat* stat)
{
    uid_t uid;
    KVD_SET_UID(uid,stat->uid);
    return uid;
}

gid_t kvd_get_kstat_gid(const struct kstat* stat)
{
    gid_t gid;
    KVD_SET_GID(gid,stat->gid);
    return gid;
}

int kvd_vfs_getattr(struct path* path,struct kstat* stat)
{
    int rc = -EINVAL;
    if(!path || !stat) { return rc; }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    rc = vfs_getattr(path,stat,STATX_BASIC_STATS,
                    AT_STATX_SYNC_AS_STAT);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
    rc = vfs_getattr(path,stat);
#else
    rc = vfs_getattr(path->mnt,path->dentry,stat);
#endif

    return rc;
}

int kvd_vfs_getstatfs(struct path* path,struct kstatfs* kstfs)
{
    int rc = -EINVAL;
    if(!path || !kstfs) { return rc; }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
    rc = vfs_statfs(path,kstfs);
#elif defined(RHEL_RELEASE_CODE)
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,2)
        rc = vfs_statfs(path,kstfs);
    #else
        rc = vfs_statfs(path->dentry,kstfs);
    #endif
#else
    rc = vfs_statfs(path->dentry,kstfs);
#endif

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
int kvd_generic_fillattr(struct mnt_idmap *idmap, struct inode* inode,struct kstat* stat)
{
    if (!idmap || !inode || !stat) {
        return -EINVAL;
    }
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
    generic_fillattr(idmap, STATX_BASIC_STATS, inode, stat);
  #else
    generic_fillattr(idmap, inode, stat);
  #endif
    return 0;
}
#else
int kvd_generic_fillattr(struct inode* inode,struct kstat* stat)
{
    int rc = -EINVAL;
    if(!inode || !stat) {
        return rc;
    }

    rc = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
    generic_fillattr(&init_user_ns,inode,stat);
#else
    generic_fillattr(inode,stat);
#endif
    return rc;
}
#endif

int kvd_vfs_getattr_nosec(struct path* path,struct kstat* stat)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    return vfs_getattr_nosec(path,stat,
               STATX_BASIC_STATS | STATX_BTIME,AT_STATX_SYNC_TYPE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
    #ifdef __i386__
        struct inode* inode = path->dentry->d_inode;
        generic_fillattr(inode,stat);

        return 0;
    #else
        return vfs_getattr_nosec(path,stat);
    #endif
#else
    struct inode* inode = path->dentry->d_inode;
    generic_fillattr(inode,stat);

    return 0;
#endif
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
/**
 * kstrndup - allocate space for and copy an existing string
 * @s: the string to duplicate
 * @max: read at most @max chars from @s
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 */
char *kstrndup(const char *s, size_t max, gfp_t gfp)
{
    size_t len;
	char *buf;

	if (!s)
		return NULL;

	len = strnlen(s, max);
	buf = kcalloc(1,len+1, gfp);
	if (buf) {
		memcpy(buf, s, len);
		buf[len] = '\0';
	}
	return buf;
}
#endif

int kvd_snprintf(char* buf,size_t size, const char *fmt,...)
{
    va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, size, fmt, args);
	va_end(args);

    //这里是内核vsnprintf的特性导致的
    //在内核里snprintf,vsnprintf返回的值如果>=size
    //表示数据被truncate了，我们在此处返回真正写入的长度

    //下面这样写更好一些，避免i为小于0的值导致转换成size_t
    //出现问题，但实际情况vsnprintf应该不会返回小于０的值
    if(likely(i < size))
        return i;
    
    if (size != 0)
		return size - 1;
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
uid_t kvd_get_task_uid(struct task_struct* tsk)
{
    uid_t uid = 0;
    kuid_t kuid = task_cred_xxx(tsk,uid);

    SET_UID(uid, from_kuid_munged(current_user_ns(),kuid));

    return uid;
}
uid_t kvd_get_task_euid(struct task_struct* tsk)
{
    uid_t euid = 0;
    kuid_t keuid = task_cred_xxx(tsk,euid);

    SET_UID(euid, from_kuid_munged(current_user_ns(),keuid));

    return euid;
}

gid_t kvd_get_task_gid(struct task_struct* tsk)
{
    gid_t gid = 0;
    kgid_t kgid = task_cred_xxx(tsk,gid);

    SET_GID(gid, from_kgid_munged(current_user_ns(),kgid));

    return gid;
}

gid_t kvd_get_task_egid(struct task_struct* tsk)
{
    gid_t egid = 0;
    kgid_t kegid = task_cred_xxx(tsk,egid);

    SET_GID(egid, from_kgid_munged(current_user_ns(),kegid));

    return egid;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
uid_t kvd_get_task_uid(struct task_struct* tsk)
{
    uid_t uid = 0;
    uid_t kuid = task_cred_xxx(tsk,uid);

    SET_UID(uid,kuid);

    return uid;
}
uid_t kvd_get_task_euid(struct task_struct* tsk)
{
    uid_t euid = 0;
    uid_t keuid = task_cred_xxx(tsk,euid);

    SET_UID(euid,keuid);

    return euid;
}

gid_t kvd_get_task_gid(struct task_struct* tsk)
{
    gid_t gid = 0;
    gid_t kgid = task_cred_xxx(tsk,gid);

    SET_GID(gid,kgid);

    return gid;
}

gid_t kvd_get_task_egid(struct task_struct* tsk)
{
    gid_t egid = 0;
    gid_t kegid = task_cred_xxx(tsk,egid);

    SET_GID(egid,kegid);

    return egid;
}
#else
uid_t kvd_get_task_uid(struct task_struct* tsk)
{
    uid_t uid = 0;

    SET_UID(uid,tsk->uid);
    return uid;
}

uid_t kvd_get_task_euid(struct task_struct* tsk)
{
    uid_t euid = 0;

    SET_UID(euid,tsk->euid);
    return euid;
}

gid_t kvd_get_task_gid(struct task_struct* tsk)
{
    gid_t gid = 0;

    SET_GID(gid,tsk->gid);
    return gid;
}

gid_t kvd_get_task_egid(struct task_struct* tsk)
{
    gid_t egid = 0;

    SET_GID(egid,tsk->egid);
    return egid;
}
#endif

pid_t kvd_get_sid(struct task_struct* tsk)
{
    pid_t sid = 0;
    rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    sid = task_session_vnr(tsk);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
    sid = process_session(tsk);
#else
    sid = tsk->signal->session;
#endif
    rcu_read_unlock();

    return sid;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
        /**
         * get_mm_exe_file - acquire a reference to the mm's executable file
         *
         * Returns %NULL if mm has no associated executable file.
         * User must release file via fput().
         */
         #if 0
        static struct file *my_get_mm_exe_file(struct mm_struct *mm)
        {
            struct file *exe_file;

            rcu_read_lock();
            exe_file = rcu_dereference(mm->exe_file);
            #if LINUX_VERSION_CODE <= KERNEL_VERSION(6,8,0)
            if (exe_file && !get_file_rcu(exe_file))
            #endif
                exe_file = NULL;
            rcu_read_unlock();
            return exe_file;
        }
#else
    static struct file *my_get_mm_exe_file(struct mm_struct *mm)
    {
        struct file *exe_file = NULL;

        rcu_read_lock();
#if SPEC_VERSION_BUILD == 6
        exe_file = rcu_dereference(mm->exe_file);
        if (exe_file)
            get_file(exe_file);
#else
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
        exe_file = get_file_rcu(&mm->exe_file);
        #else
        exe_file = rcu_dereference(mm->exe_file);
        if (exe_file)
            get_file(exe_file);
        #endif
#endif
        rcu_read_unlock();
        return exe_file;
    }
    #endif

/**
 * get_task_exe_file - acquire a reference to the task's executable file
         *
         * Returns %NULL if task's mm (if any) has no associated executable file or
         * this is a kernel thread with borrowed mm (see the comment above get_task_mm).
         * User must release file via fput().
         */
        static struct file* my_get_task_exe_file(struct task_struct *task)
        {
            struct file *exe_file = NULL;
            struct mm_struct *mm;

            task_lock(task);
            mm = task->mm;
            if (mm) {
                if (!(task->flags & PF_KTHREAD))
                    exe_file = my_get_mm_exe_file(mm);
            }
            task_unlock(task);
            return exe_file;
        }
    #else
        static struct file* my_get_task_exe_file(struct task_struct *task)
        {
            return get_task_exe_file(task);
        }
    #endif

    int kvd_get_task_exe(struct task_struct* tsk,struct path* path)
    {
        int rc = -ENOENT;
        struct file* exe_file = NULL;
        exe_file = my_get_task_exe_file(tsk);

    	if (exe_file) {
    		*path = exe_file->f_path;
    		path_get(&exe_file->f_path);
    		fput(exe_file);
            rc = 0;
    	}

        return rc;
    }
#else
    #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
        #ifdef CONFIG_MMU
        static int get_task_exe(struct mm_struct* mm,struct path* path)
        {
            int rc = -ENOENT;
            struct vm_area_struct * vma = NULL;

            down_read(&mm->mmap_sem);
        	vma = mm->mmap;
        	while (vma) {
        		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
        			break;
        		vma = vma->vm_next;
        	}

        	if (vma) {
        		path->mnt = mntget(vma->vm_file->f_vfsmnt);
        		path->dentry = dget(vma->vm_file->f_dentry);
        		rc = 0;
        	}
        	up_read(&mm->mmap_sem);

            return rc;
        }
        #else
        static int get_task_exe(struct mm_struct* mm,struct path* path)
        {
            int rc = -ENOENT;
            struct vm_list_struct *vml = NULL;
            struct vm_area_struct *vma = NULL;

            down_read(&mm->mmap_sem);
            vml = mm->context.vmlist;
        	while (vml) {
        		if ((vml->vma->vm_flags & VM_EXECUTABLE) && vml->vma->vm_file) {
        			vma = vml->vma;
        			break;
        		}
        		vml = vml->next;
        	}

        	if (vma) {
        		path->mnt = mntget(vma->vm_file->f_vfsmnt);
        		path->dentry = dget(vma->vm_file->f_dentry);
        		rc = 0;
        	}

        	up_read(&mm->mmap_sem)

            return rc;
        }
        #endif
    #else 
		#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
        struct file *get_mm_exe_file(struct mm_struct *mm)
        {
            struct file *exe_file;

            /* We need mmap_sem to protect against races with removal of
             * VM_EXECUTABLE vmas */
            down_read(&mm->mmap_sem);
            exe_file = mm->exe_file;
            if (exe_file)
                get_file(exe_file);
            up_read(&mm->mmap_sem);
            return exe_file;
        }
#endif

        static int get_task_exe(struct mm_struct* mm,struct path* path)
        {
            int rc = -ENOENT;
            struct file* exe_file = NULL;

            exe_file = get_mm_exe_file(mm);
        	if (exe_file) {
                path_get(&exe_file->f_path);
        		*path = exe_file->f_path;
        		fput(exe_file);
                rc = 0;
        	}

            return rc;
        }
#endif

    int kvd_get_task_exe(struct task_struct* tsk,struct path* path)
    {
        int rc = -EINVAL;
        struct mm_struct* mm = NULL;

        if(!tsk || !path) { return rc; }

        rc = -ENOENT;
        mm = get_task_mm(tsk);
        if(!mm) { goto out; }

        rc = get_task_exe(mm,path);
        mmput(mm);

    out:
        return rc;
    }
#endif

char* kvd_get_task_pathname(struct task_struct* tsk,
                            unsigned int* len)
{
    int rc = 0;
    struct path path;
    char* pathname = ERR_PTR(-EINVAL);

    if(!tsk || !len) { goto out; }

    pathname = ERR_PTR(-ENOENT);
    rc = kvd_get_task_exe(tsk,&path);
    if(rc) {
        pathname = ERR_PTR(rc);
        goto out;
    }

    pathname = kvd_get_pathname(&path,len);
    kvd_path_put(&path);

out:
    return pathname;
}


/*此处采用FS_MAGIC直接从dentry的super_block获取fs的magic有可能会失败
*因为对于reisfer之类的文件系统在dentry的super_block标识为0
*另外，vfs_statfs对于任何文件系统类型均能获取到fs-magic,
*但此处先调用FS_MAGIC从dentry中获取，如果成功，则无需要再调用vfs_statfs
*因为vfs_statfs对于网络文件系统可能会涉及到网络请求，从而影响性能
*/
uint64_t kvd_get_fs_magic(struct path* path)
{
    int rc = 0;
    struct kstatfs kstfs;
    uint64_t fs_magic = 0;
    struct dentry* dentry = NULL;

    dentry = path->dentry;
    fs_magic = FS_MAGIC(dentry);
    if(fs_magic) { return fs_magic; }

    //使用FS_MAGIC获取失败，则采用vfs_statfs再次尝试获取
    rc = kvd_vfs_getstatfs(path,&kstfs);
    if(rc == 0) { fs_magic = kstfs.f_type; }

    return fs_magic;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
int d_unlinked(struct dentry *dentry)
{
	return d_unhashed(dentry) && !IS_ROOT(dentry);
}
#endif

//get kernel pathname
char* kvd_get_kernel_pathname(int dfd,const char __user* pathname,unsigned lookup_flags)
{
    int rc = -EINVAL;
    char* res = NULL;
    struct path path;
    unsigned int len = 0;

    rc = kvd_user_path_at(dfd,pathname,lookup_flags,&path);
    if(rc) {
        res = ERR_PTR(rc);
        return res;
    }

    rc = 0;
    res = kvd_get_pathname(&path,&len);
    if(IS_ERR(res)) { goto out; }

out:
    kvd_path_put(&path);
    if(rc) { res = ERR_PTR(rc); }
    return res;
}

struct task_struct* kvd_get_task_struct(pid_t pid)
{
    struct task_struct* tsk = NULL;

    #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,26)
        struct pid* spid = NULL;
       
        //此处获取pid要在全局init_pid_ns命名空间中获取
        //不然在有docker的情况下可能会有问题
        rcu_read_lock();
        spid = find_pid_ns(pid,&init_pid_ns);
        if(spid) {
            tsk = pid_task(spid,PIDTYPE_PID);
            if(tsk) { get_task_struct(tsk); }
        }
        rcu_read_unlock();
    #else
        rcu_read_lock();
    	tsk = find_task_by_pid(pid);
    	if(tsk) { get_task_struct(tsk); }
    	rcu_read_unlock();
    #endif

    return tsk;
}

//持有rcu_read_lock的情况下才能调用该函数，否则极有可能出问题
struct task_struct* kvd_get_task_struct_locked(pid_t pid)
{
    struct task_struct* tsk = NULL;

    #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,26)
        struct pid* spid = NULL;
       
        //此处获取pid要在全局init_pid_ns命名空间中获取
        //不然在有docker的情况下可能会有问题
        spid = find_pid_ns(pid,&init_pid_ns);
        if(spid) {
            tsk = pid_task(spid,PIDTYPE_PID);
        }
    #else
    	tsk = find_task_by_pid(pid);
    #endif

    return tsk;
}


//get THIS_MODULE
int kvd_try_self_module_get(void)
{
    return try_module_get(THIS_MODULE);
}

void kvd_self_module_put(void)
{
    int refcnt = 0;
    refcnt = module_refcount(THIS_MODULE);
    if(refcnt <= 0) {
        LOG_ERROR("warning: we try to module_put,"
            "but module refcnt[%d] is not legal\n",refcnt);
        return;
    }

    module_put(THIS_MODULE);
}


//the kernel define file_inode from 3.9.0
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
struct inode* file_inode(struct file* filp)
{
    struct dentry* dentry = NULL;
    #if LINUX_VERSION_CODE > KERNEL_VERSION(3,19,0)
        dentry = filp->f_path.dentry;
    #else
        dentry = filp->f_dentry;
    #endif

    return dentry->d_inode;
}
#endif

#ifdef CONFIG_MMU
//此处仅以只读方式获取相应的用户态页即可
int kvd_get_user_pages(struct task_struct* tsk,
                        struct mm_struct* mm,
                        unsigned long pos,
                        struct page** ppage,
                        struct vm_area_struct** pvma)
{
    int ret = 0;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
        unsigned int gnu_flags = FOLL_FORCE;
        mmap_read_lock(mm);
        ret = get_user_pages_remote(mm, pos,
                1,gnu_flags,ppage,NULL);
        mmap_read_unlock(mm);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
        unsigned int gnu_flags = FOLL_FORCE;
        mmap_read_lock(mm);
        ret = get_user_pages_remote(mm, pos,
                1,gnu_flags,ppage,pvma,NULL);
        mmap_read_unlock(mm);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
		unsigned int gnu_flags = FOLL_FORCE;     		
        ret = get_user_pages_remote(mm, pos,
                1,gnu_flags,ppage,pvma,NULL);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
        unsigned int gnu_flags = FOLL_FORCE;
        ret = get_user_pages_remote(tsk, mm, pos,
                1,gnu_flags,ppage,pvma,NULL);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
        unsigned int gnu_flags = FOLL_FORCE;
        ret = get_user_pages_remote(tsk, mm, pos,
                1,gnu_flags,ppage,pvma);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
        ret = get_user_pages_remote(tsk, mm, pos,
                1, 0, 1,ppage, pvma);
    #else
    	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
        	ret = get_user_pages(tsk,mm, pos,
                1, 0, 1,ppage, pvma);
    	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,168)
			unsigned int gnu_flags = FOLL_FORCE;     	
        	ret = get_user_pages(tsk, mm, pos,
		            1,gnu_flags,ppage,pvma);
        #elif (defined(CONFIG_SUSE_KERNEL) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,73)))
            unsigned int gnu_flags = FOLL_FORCE;
            ret = get_user_pages_remote(tsk, mm, pos,
                    1,gnu_flags,ppage,pvma,NULL);
		#else
			ret = get_user_pages(tsk,mm, pos,
                1, 0, 1,ppage, pvma);
		#endif
    #endif

    return ret;
}
#endif

void kvd_bin2hex(const u_char* bin,size_t len,u_char* hexs)
{
    static u_char hex[] = "0123456789ABCDEF";

    while(len--) {
        *hexs++ = hex[*bin >> 4];
        *hexs++ = hex[*bin++ & 0xf];
    }
}

int kvd_hexc2n(char c)
{
    int ok = 0;
    int rc = -EINVAL;

    ok = (((c >= '0') && (c <= '9')) || 
            ((c >= 'a') && (c <= 'f')) || 
            ((c >= 'A') && (c <= 'F')));
    if(!ok) { return rc; }

    if(c <= '9') {
        rc = (c - '0'); 
    } else {
        c = toupper(c);
        rc = (c - 'A') + 10;
    }

    return rc;
}

int kvd_hex2bin(const char* hexs,size_t hex_len,
                    u_char* bins,size_t bin_len)
{
    int n = 0;
    int val = 0;
    size_t i = 0;

    for(;i < hex_len && n < bin_len;i++,n++) {
        val = kvd_hexc2n(hexs[i++]);
        if(val < 0) { return val; }

        if(i < hex_len) {
            val *= 16;
            val += kvd_hexc2n(hexs[i]);
        }

        bins[n] = val & 0xff;
    }

    return n;
}

static int do_getname(const char __user *filename, char *page)
{
	int retval;
	unsigned long len = PATH_MAX;

	retval = strncpy_from_user(page, filename, len);
	if (retval > 0) {
		if (retval < len)
			return 0;
		return -ENAMETOOLONG;
	} else if (!retval)
		retval = -ENOENT;
	return retval;
}

char* kvd_getname(const char __user* filename)
{
    char *tmp, *result;

	result = ERR_PTR(-ENOMEM);
	tmp = __getname();
	if (tmp)  {
		int retval = do_getname(filename, tmp);

		result = tmp;
		if (retval < 0) {
			__putname(tmp);
			result = ERR_PTR(retval);
		}
	}

    return result;
}

int kvd_strncasecmp(const char *s1, const char *s2, size_t n)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}

int kvd_strcasecmp(const char *s1, const char *s2)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while (c1 == c2 && c1 != 0);
	return c1 - c2;
}


u_char *kvd_skb_tail_pointer(const struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    return skb_tail_pointer(skb);
#else
	return skb->tail;
#endif
}

int kvd_skb_network_offset(const struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    return skb_network_offset(skb);
#else
	return ((skb)->nh.raw - (skb)->data);
#endif
}

u_char* kvd_skb_network_header(const struct sk_buff* skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    return skb_network_header(skb);
#else
	return (skb)->nh.raw;
#endif
}

int kvd_skb_transport_offset(const struct sk_buff* skb,u_int nhdrlen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    int len = skb_transport_offset(skb);
    return len ? len : nhdrlen;
#else
    //在低于2.6.22版本的内核上，skb->h.raw是没有设置的与skb->data是同样的值
    //所以无法通过skb->h.raw来直接计算传输层头偏移,其值直接是nhdrlen网络层的头部大小
    BUG_ON(nhdrlen == 0);
	return nhdrlen;
#endif
}

u_char* kvd_skb_transport_header(const struct sk_buff* skb,u_int nhdrlen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    (void)nhdrlen;
    return skb_transport_header(skb);
#else
    //在低于2.6.22版本的内核上，skb->h.raw是没有设置的与skb->data是同样的值
    //所以无法通过skb->h.raw来直接计算传输层头偏移,其值直接是nhdrlen网络层的头部大小
    BUG_ON(nhdrlen == 0);
	return ((skb)->data + nhdrlen);
#endif
}

/**
 * kvd_strnstr - Find the first substring in a length-limited string
 * @s1: The string to be searched
 * @s2: The string to search for
 * @len: the maximum number of characters to search
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
    char *kvd_strnstr(const char *s1, const char *s2, size_t len)
    {
        return strnstr(s1,s2,len);
    }
#else
    char *kvd_strnstr(const char *s1, const char *s2, size_t len)
    {
        size_t l2;

        l2 = strlen(s2);
        if (!l2)
            return (char *)s1;
        while (len >= l2) {
            len--;
            if (!memcmp(s1, s2, l2))
                return (char *)s1;
            s1++;
        }
        return NULL;
    }
#endif

ssize_t kvd_kernel_read(struct file* file,void* buf,
                        size_t count,loff_t* pos)
{
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
		ssize_t nlen = kernel_read(file,buf,count,pos);
	#else
		mm_segment_t old_fs;
        ssize_t nlen = 0;

        old_fs = get_fs();
        set_fs(get_ds());
        /* The cast to a user pointer is valid due to the set_fs() */
        nlen = vfs_read(file, (void __user *)buf, count,pos);
        set_fs(old_fs);
	#endif

	return nlen;
}

char* kvd_get_pwd_pathname(unsigned* plen)
{
    struct path pwd;
    char* kpathname = ERR_PTR(-EINVAL);

    if(!plen) { goto out; }

    kvd_get_fs_pwd(current->fs,&pwd);
    kpathname = kvd_get_pathname(&pwd,plen);
    kvd_path_put(&pwd);

out:
    return kpathname;
}

void kvd_module_core_addr(struct module* this,u_long* start,u_long* end)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0))
    *start = (u_long)this->mem[MOD_TEXT].base;
    *end = (u_long)(this->mem[MOD_TEXT].base + this->mem[MOD_TEXT].size);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)) || \
    defined(__module_layout_align)
    *start = (u_long)this->core_layout.base;
	*end = (u_long)this->core_layout.base + this->core_layout.size;
#else
    *start = (u_long)this->module_core;
	*end = (u_long)this->module_core + this->core_size;
#endif
}

void kvd_module_init_addr(struct module* this,u_long* start,u_long* end)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0))
    *start = (u_long)this->mem[MOD_INIT_TEXT].base;
    *end = (u_long)(this->mem[MOD_INIT_TEXT].base + this->mem[MOD_INIT_TEXT].size);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0) || \
    defined(__module_layout_align)
    *start = (u_long)this->init_layout.base;
	*end = (u_long)this->init_layout.base + this->init_layout.size;
#else
    *start = (unsigned long)this->module_init;
	*end = (unsigned long)this->module_init + this->init_size;
#endif
}

int kvd_within_module(struct module* mod,
                    unsigned long addr)
{
    u_long core_beg,core_end;
    u_long init_beg,init_end;

    kvd_module_core_addr(mod,&core_beg,&core_end);
    kvd_module_init_addr(mod,&init_beg,&init_end);

    return (((addr >= core_beg) && (addr < core_end)) ||
            ((addr >= init_beg) && (addr < init_end)));
}

int kvd_register_binfmt(struct linux_binfmt* binfmt)
{
    int rc = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,29)
    insert_binfmt(binfmt);
#else
    rc = register_binfmt(binfmt);
#endif

    return rc;
}

void kvd_unregister_binfmt(struct linux_binfmt* binfmt)
{
    unregister_binfmt(binfmt);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)) || \
    (defined(CONFIG_SUSE_KERNEL) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)))
	ssize_t kvd_kernel_write(struct file* file,const char* buf,size_t count,loff_t* pos)
	{
		return kernel_write(file,buf,count,pos);
	}
#else
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
        //Note: 这里的pos参数绝对不允许传NULL
		ssize_t kvd_kernel_write(struct file *file, const char *buf, size_t count,loff_t* pos)
		{
            ssize_t ret = 0;
            BUG_ON(pos == NULL);
			ret = kernel_write(file,buf,count,*pos);
            if(ret > 0) { *pos += ret; }

            return ret;
		}
	#else
		//3.9.0以前版本的内核未定义kernel_write
		ssize_t kvd_kernel_write(struct file *file,const char *buf,size_t count,loff_t* pos)
		{
			mm_segment_t old_fs;
			ssize_t res;

			old_fs = get_fs();
			set_fs(get_ds());
			/* The cast to a user pointer is valid due to the set_fs() */
			res = vfs_write(file, (const char __user *)buf, count,pos);
			set_fs(old_fs);

			return res;
		}
	#endif
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,28)
	int kvd_fsync(struct file *file, int datasync)
	{
		int ret;
		int err;
		struct address_space *mapping = file->f_mapping;

		if (!file->f_op || !file->f_op->fsync) {
			/* Why?  We can still call filemap_fdatawrite */
			ret = -EINVAL;
			goto out;
		}

		ret = filemap_fdatawrite(mapping);

		/*
		 * We need to protect against concurrent writers, which could cause
		 * livelocks in fsync_buffers_list().
		 */
		mutex_lock(&mapping->host->i_mutex);
		err = file->f_op->fsync(file, file->f_dentry, datasync);
		if (!ret)
				ret = err;
		mutex_unlock(&mapping->host->i_mutex);
		err = filemap_fdatawait(mapping);
		if (!ret)
			ret = err;
		out:
			return ret;
	}
#else
	int kvd_fsync(struct file* fp,int datasync)
	{
		int ret = -EINVAL;
		if(!fp) { return ret; }

		#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
			ret = vfs_fsync(fp,datasync);
		#else
			ret = vfs_fsync(fp,fp->f_path.dentry, datasync);
		#endif	

		return ret;
	}
#endif

uint64_t kvd_appver(const char* appver)
{
    uint64_t nver = 0;
    uint64_t nv1,nv2,nv3,nv4;
    int n = sscanf(appver,"%llu.%llu.%llu.%llu",
                    &nv1,&nv2,&nv3,&nv4);
    if(n != 4) { return nver; }

    nver = ((nv1 << 45) + (nv2 << 30) + (nv3 << 15) + nv4);

    return nver;
}

char* kvd_str_appver(char* buf,size_t len,
                                uint64_t nver)
{
    kvd_snprintf(buf,len,"%u.%u.%u.%u",
            (nver >> 45),
            ((nver >> 30) & 0x7FFF),
            ((nver >> 15) & 0x7FFF),
            (nver & 0x7FFF));
    
    return buf;
}

int kvd_vercmp(const char* sver1,
               const char* sver2)
{
    uint64_t nv1 = kvd_appver(sver1);
    uint64_t nv2 = kvd_appver(sver2);

    return ((nv1 == nv2) ? 
            0 : ((nv1 < nv2 ? -1 : 1)));
}

static int preset_config_enable = 0;
void kvd_preset_config_setenable(void)
{
    preset_config_enable = 1;
}

int kvd_preset_config_enabled(void)
{
    return preset_config_enable;
}
