#include <linux/file.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/types.h>
#include "utils/fs_magic.h"
#include "core/kvd_core.h"
#include "fs_core.h"


/*此处采用FS_MAGIC直接从dentry的super_block获取fs的magic有可能会失败
*因为对于reisfer之类的文件系统在dentry的super_block标识为0
*另外，vfs_statfs对于任何文件系统类型均能获取到fs-magic,
*但此处先调用FS_MAGIC从dentry中获取，如果成功，则无需要再调用vfs_statfs
*因为vfs_statfs对于网络文件系统可能会涉及到网络请求，从而影响性能
*/
uint64_t get_fs_magic(struct path* path)
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

//检测是否是我们关心的file-system
int is_valid_fs(struct path* path)
{
    int rc = 0;
    uint64_t fs_magic = 0;

    fs_magic = get_fs_magic(path);
    if(fs_magic == 0) { return rc; }

    //是我们需要关注的文件系统类型
    //则一定是有效的文件系统类型
    rc = vsec_is_care_fs(fs_magic);
    if(rc) { return rc; }

    rc = !vsec_is_skip_fs(fs_magic);

    return rc;
}

int is_valid_path(struct path* path)
{
    int rc = 0;
    struct dentry* dentry = NULL;

    if(!path) { goto out; }

    rc = is_valid_fs(path);
    if(!rc) { goto out; }
    //is path deleted ?
    dentry = path->dentry;
    rc = !d_unlinked(dentry);

out:
    return rc;
}

/*
 *是否是文件写事件:
 */
int is_file_write(struct file* filp)
{
    int rc = 0;
    umode_t mode = 0;
    unsigned int f_flags = 0;

    if(!filp) { return rc; }

    mode = filp->f_mode;
    f_flags = filp->f_flags;

    //对于文件写操作，其f_flags一定要有如下值之一,否则一定不会是写操作
    rc = (f_flags & (O_CREAT | O_TRUNC | O_APPEND | O_WRONLY | O_RDWR));
    return rc;
}


//get kernel pathname and stat
char* get_kernel_pathname_stat(int dfd,const char __user* pathname,unsigned flags,
            struct kstat *stat)
{
    int rc = -EINVAL;
    char* res = NULL;
    struct path path;
    unsigned int len = 0;

    rc = kvd_user_path_at(dfd,pathname,flags,&path);
    if(rc) {
        res = ERR_PTR(rc);
        return res;
    }

    rc = -EINVAL;
    if(!is_valid_path(&path)) {
        goto out;
    }

    rc = 0;
    res = kvd_get_pathname(&path,&len);
    if(IS_ERR(res)) { goto out; }

    rc = kvd_vfs_getattr(&path, stat);
    if(rc) { kvd_put_pathname(res); }

out:
    kvd_path_put(&path);
    if(rc) { res = ERR_PTR(rc); }
    return res;
}

int get_vfs_stat(int dfd,const char __user *name,unsigned flags,struct kstat *stat)
{
    int rc = 0;
    struct path path;
    unsigned lookup_flags = LOOKUP_FOLLOW;

    if(flags & O_NOFOLLOW) {
        lookup_flags &= ~LOOKUP_FOLLOW;
    }

    rc = kvd_user_path_at(dfd,name,lookup_flags,&path);
	if (rc) { return rc; }

    rc = -EINVAL;
    if(!is_valid_path(&path)) {
        goto out;
    }

	rc = kvd_vfs_getattr(&path, stat);

out:
    kvd_path_put(&path);
	return rc;
}

int get_stat_by_path(struct path* path,struct kstat* stat)
{
    int rc = -EINVAL;
    struct inode* inode = NULL;
    struct dentry* dentry = NULL;

    if(!path || !stat) {
        return rc; 
    }

    dentry = path->dentry;
	inode = dentry->d_inode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    rc = kvd_generic_fillattr(mnt_idmap(path->mnt), inode, stat);
#else
    rc = kvd_generic_fillattr(inode,stat);
#endif

    return rc;
}

int get_stat_by_file(struct file* filp,struct kstat* stat)
{
    int rc = -EBADF;
    struct path path;
  

    if(!filp || !stat) { return rc; }

    rc = kvd_filp_path(filp,&path);
    if(rc) { return rc; }

    rc = -EINVAL;
    if(!is_valid_path(&path)) {
        goto out;
    }

    rc = get_stat_by_path(&path,stat);

out:
    kvd_path_put(&path);
    return rc;
}

/* 
 *flag-->sys_linkat,sys_fchmodat传入的的原始flag参数:0,AT_SYMLINK_NOFOLLOW,AT_EMPTY_PATH
 *lookup_flags-->路径查找时的flag: 0,LOOKUP_FOLLOW,LOOKUP_EMPTY
 */
int get_lookup_flags(int flag,int* lookup_flags)
{
    int error = 0;

    #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)
        if(flag & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) {
            error = -EINVAL;
        } else {
            *lookup_flags = (flag & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;
        	if (flag & AT_EMPTY_PATH)
        		*lookup_flags |= LOOKUP_EMPTY;
        }
    #else
        if(!(flag & ~AT_SYMLINK_NOFOLLOW)) {
            *lookup_flags = (flag & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;
        } else {
            error = -EINVAL;
        }
    #endif

    return error;
}
