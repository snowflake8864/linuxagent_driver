#include <linux/slab.h>
#include <linux/file.h>
#include <linux/statfs.h>
#include "core/kvd_core.h"
#include "path_security.h"
#include "utils/fs_magic.h"
#include "utils/utils.h"
#include "fs/fs_core.h"
#include "defense_inner.h"
#include "gnHead.h"

/*对于自保而言:
 *1.我们的程序肯定不会安装在网络文件路径中
 *2.如果文件系统类型是非正常的文件系统类型(proc,sys,devpts之类)肯定也不会是我们的安装路径
 */
static int is_path_ok(struct path* path)
{
    int ok = 0;
    uint64_t fs_magic = 0;

    fs_magic = get_fs_magic(path);
    if(fs_magic == 0) { goto out; }

    //is netfs?
    ok = !vsec_is_net_fs(fs_magic);
    if(!ok) { goto out; }

    //is_valid_path检查文件系统及对应文件路径是否已被删除,返回0或1
    ok = is_valid_path(path);

out:
    return ok;
}

/*
 *获取以当前工作路径
 */
static char* get_pwd_pathname(unsigned* plen)
{
    struct path pwd;
    char* kpathname = ERR_PTR(-EINVAL);

    if(!plen) { goto out; }

    kvd_get_fs_pwd(current->fs,&pwd);
    if(is_path_ok(&pwd)) {
        kpathname = kvd_get_pathname(&pwd,plen);
    }
    kvd_path_put(&pwd);

out:
    return kpathname;
}

/*
 *patname对应的路径实际可能是不存在的
 */
static char* get_offical_pathname(const char* path,unsigned* reslen)
{
    int rc = 0;
    char *npath = NULL;
    unsigned pwdpathlen = 0;
    char* res = ERR_PTR(-EINVAL);
    unsigned maxreslen = PATH_MAX;
    char* pwdpath = ERR_PTR(-ENOENT);

    if(!path) { goto out; }

    rc = -ENOMEM;
    res = __getname();
    if(!res) { goto out; }

    npath = res;
    if (*path != '/') {
        pwdpath = get_pwd_pathname(&pwdpathlen);
        if(IS_ERR(pwdpath)) {
            rc = PTR_ERR(pwdpath);
            goto out;
        }

        if(pwdpathlen > maxreslen - 2) {
            rc = -ENAMETOOLONG;
            goto out;
        }
        memcpy(npath,pwdpath,pwdpathlen);

        npath += pwdpathlen;
        if (npath[-1] != '/') {
          *npath++ = '/';
        }
    } else {
        *npath++ = '/';
        path++;
    }

    while (*path != '\0') {
        if (*path == '/') {
          path++;
          continue;
        }

        if (*path == '.' && (path[1] == '\0' || path[1] == '/')) {
          path++;
          continue;
        }

        if (*path == '.' && path[1] == '.' && (path[2] == '\0' || path[2] == '/')) {
          path += 2;
          while (npath > res + 1 && (--npath)[-1] != '/')
            ;
          continue;
        }

        while (*path != '\0' && *path != '/') {
          if (npath - res > maxreslen - 2) {
            rc = -ENAMETOOLONG;
            goto out;
          }
          *npath++ = *path++;
        }
        *npath++ = '/';
    }

    if (npath != res + 1 && npath[-1] == '/') {
        npath--;
    }

    rc = 0;
    *npath = '\0';
    *reslen = (npath - res);

out:
    if(rc) {
        if(res) { kvd_put_pathname(res); }
        res = ERR_PTR(rc);
    }
    if(!IS_ERR(pwdpath)) { kvd_put_pathname(pwdpath); }

    return res;
}

/*注意此处处理的pathname一定以/开始的路径,
 *并且patname对应的路径实际可能是不存在的
 *此处所谓的parent只是在路径中字符中查找的直属父路径，
 *但pathname对应的直属父路径可能是不存在的
 *另外，注意pathname是可变参加，并且该函数内部会对pathname做修改，
 *但该函数返回后会保持pathname不变
 */
static char* get_path_parent(char* pathname,unsigned int flags,unsigned* plen)
{
    char c;
    int rc = 0;
    struct path path;
    int dentry_ok = 0;
    char* pp_end = NULL;//pointer to parent end
    char* res = ERR_PTR(-EINVAL);

    //find the end to parent path
    pp_end = strrchr(pathname,'/');
    if(!pp_end) { goto out; }

    if(pp_end <= pathname) { pp_end++; }
    c = *pp_end;
    *pp_end = '\0';

    rc = kvd_path_lookup(pathname,flags,&path);
    if(rc) { goto out; }

    rc = -EINVAL;
    dentry_ok = is_path_ok(&path);
    if(!dentry_ok) {
        kvd_path_put(&path);
        goto out;
    }

    rc = 0;
    res = kvd_get_pathname(&path,plen);
    kvd_path_put(&path);

out:
    if(pp_end) { *pp_end = c; } //reset pathname value
    if(rc) { res = ERR_PTR(rc); }
	return res;
}

static char* get_pathname_by_fd(int fd,unsigned* len)
{
    struct path path;
    struct file* filp = NULL;
    char* res = ERR_PTR(-EBADF);

    //fd是文件描述符
    filp = fget(fd);
    if(!filp) { goto out; }

    if(kvd_filp_path(filp,&path)) {
        goto out;
    }

    res = ERR_PTR(-EINVAL);
    //is a valid file-system ?
    if(!is_path_ok(&path)) {
        kvd_path_put(&path);
        goto out;
    }

    res = kvd_filp_pathname(filp,len);
    kvd_path_put(&path);

out:
    if(filp) { fput(filp); }
    return res;
}

//获取真实的文件路径，该文件路径可能不存在
//此处的真实路径，即对该路径中的直属父路径做处理，获取直属父路径的真实路径;
//然后加上最后的文件名组成所谓的真实路径
static char* get_real_path(int dfd,const char __user* pathname,int flags,
                            unsigned* rpathlen)
{
    char* p = NULL;
	unsigned len = 0;
    unsigned plen = 0; //parent path length
    char* psep = NULL;
	char* res = ERR_PTR(-ENOMEM);
    char* parent = ERR_PTR(-ENOMEM);
    char* kpathname = ERR_PTR(-EINVAL);

	res = strndup_user(pathname,PAGE_SIZE);
	if(IS_ERR(res)) { goto out; }
    kpathname = res;

    if(dfd == AT_FDCWD) {
        res = get_offical_pathname(res,&len);
    } else {
        res = get_pathname_by_fd(dfd,&len);
    }

    kfree(kpathname); //释放修正前的路径
    kpathname = ERR_PTR(-EINVAL);

    if(IS_ERR(res)) { goto out; }
    kpathname = res;

    //此时res表示的肯定是以/开始的路径,
    //获取直属父路径的真实路径,父路径也有可能不存在
    //其直属父路径不存在则直接返回，且不应当阻止相应文件操作
    parent = get_path_parent(res,flags,&plen);
    if(IS_ERR(parent)) {
        res = parent;
        goto out;
    }
//    LOG_DEBUG("parent path: %s\n",parent);
    if(len + plen >= PATH_MAX) {
        res = ERR_PTR(-ENAMETOOLONG);
        goto out;
    }

    p = __getname();
    if(!p) {
        res = ERR_PTR(-ENOMEM);
        goto out;
    }

    memcpy(p,parent,plen);
    //if plen == 1,the parent value must be /
    if(plen > 1) { p[plen++] = '/'; }
    *rpathlen = plen;

    psep = strrchr(res,'/');
    if(psep) {
        len = res + len - psep;
        memcpy(p + plen,psep + 1,len);
        *rpathlen += len; 
    }

    res = p;

out:
    if(!IS_ERR(parent))  { kvd_put_pathname(parent); }
    if(!IS_ERR(kpathname)) { kvd_put_pathname(kpathname); }
	return res;
}

extern int may_defense_modify(const int action_type, const char* kpathname,
                            size_t len,int is_dir, int is_cut_kpathname);

extern int may_defense_modify_mv(const int action_type, const char* kpathname, const size_t len1, const char* kpathnamenew, const size_t len2,int is_dir);

//到此处自保肯定已开启了
static int generic_path_security(const int action_type, const char* pathname,int is_dir)
{
    int error = 0;

    //参数有问题，不阻止相应文件操作
    if(!pathname) { goto out; }
    error = may_defense_modify(action_type, pathname,
                strlen(pathname),is_dir, 0);

out:
    return error;
}

//到此处自保肯定已开启了
static int generic_path_security2(const int action_type, int dfd,const char __user* pathname,
                int lookup_flags,int is_dir)
{
    int error = 0;
    unsigned rpathlen = 0;
    char* kpathname = ERR_PTR(-EINVAL);

    //首先尝试获取路径
    kpathname = get_real_path(dfd,pathname,
                    lookup_flags,&rpathlen);
    //此处失败，则直接返回;且不阻止相应文件操作
    if(IS_ERR(kpathname)) { goto out; }

    //此处的is_dir判断不要使用stat中的mode值
    //因为对于rename之类的stat中的mode是不准确的,应该以原始路径的类型为准
    //error = may_defense_modify(action_type, kpathname,\
                    rpathlen ,is_dir, 0);

    error = may_defense_modify(action_type, kpathname,
                    rpathlen - 1 ,is_dir, 0);
    kvd_put_pathname(kpathname);

out:
    return error;
}


static int generic_path_security3(const int action_type, int dfd,const char __user* pathname,
                const char __user* pathname_new,
                int lookup_flags,int is_dir)
{
    int error = 0;
    unsigned rpathlen1 = 0, rpathlen2 = 0;
    char* kpathname = ERR_PTR(-EINVAL);

    //首先尝试获取路径
    kpathname = get_real_path(dfd,pathname,lookup_flags,&rpathlen1);
    //此处失败，则直接返回;且不阻止相应文件操作
    if(IS_ERR(kpathname)) { goto out; }

    char* kpathname_new = ERR_PTR(-EINVAL);
    kpathname_new = get_real_path(dfd,pathname_new,lookup_flags, &rpathlen2);
    //此处失败，则直接返回;且不阻止相应文件操作
    if(IS_ERR(kpathname_new)) { goto out; }

    //此处的is_dir判断不要使用stat中的mode值
    //因为对于rename之类的stat中的mode是不准确的,应该以原始路径的类型为准
    //error = may_defense_modify_mv(action_type, kpathname, rpathlen1, kpathname_new, rpathlen2, is_dir);
    //error = may_defense_modify_mv(action_type, kpathname, rpathlen1 - 1, kpathname_new, rpathlen2 - 1, is_dir);
    error = may_defense_modify_mv(action_type,  kpathname_new, rpathlen2 - 1,  kpathname, rpathlen1 - 1, is_dir);
    kvd_put_pathname(kpathname);
    kvd_put_pathname(kpathname_new);
out:
    return error;
}


int may_open_path(int dfd,const char __user* pathname,int flags)
{
    int error = 0;
    unsigned lookup_flags = LOOKUP_FOLLOW;

    if(flags & O_NOFOLLOW) {
        lookup_flags &= ~LOOKUP_FOLLOW;
    }

    if ((flags & (O_CREAT | O_TRUNC | O_APPEND | O_WRONLY | O_RDWR)) != 0) {
        error = generic_path_security2(FILE_MODIFY, dfd,pathname,
                lookup_flags,0);
    } else {
        error = generic_path_security2(FILE_OPEN, dfd,pathname,
                lookup_flags,0);
    }                            
    return error;
}

int may_open_path_ex(int dfd,const char __user* pathname,int flags)
{
    int error = 0;
    unsigned lookup_flags = LOOKUP_FOLLOW;

    if(flags & O_NOFOLLOW) {
        lookup_flags &= ~LOOKUP_FOLLOW;
    }

    error = generic_path_security2(FILE_MODIFY, dfd,pathname,
                            lookup_flags,0);
    return error;
}

int may_unlink_path(const char* pathname,int is_dir)
{
    return generic_path_security(FILE_REMOTE, pathname,is_dir);
}

int may_rmdir(const char* pathname)
{
    return generic_path_security(FILE_REMOTE, pathname,1);
}

int may_mkdir(int dfd,const char __user* pathname)
{
    return generic_path_security2(FILE_CREATE, dfd,pathname,
                        LOOKUP_FOLLOW,1);
}

int may_truncate_path(const char* pathname)
{
    return generic_path_security(FILE_MODIFY, pathname,0);
}

#if 0
int may_rename_path(const char* koldname,int newdfd,
        const char __user* newname,int is_dir)
{
    int error = -ENOENT;
    error = generic_path_security(koldname,is_dir);
    if(error) { goto out; }

    //Note: the newname may be not existing
    error = generic_path_security2(newdfd,newname,0,is_dir);
out:
    return error;
}
#else
int may_rename_path(const char* koldname,int newdfd,
        const char __user* oldname, const char __user* newname, int is_dir)
{
    int error = -ENOENT;

    //error = generic_path_security(FILE_RENAME, koldname,is_dir);
    //if(error) { goto out; }

    //Note: the newname may be not existing

    error = generic_path_security3(FILE_RENAME, newdfd,oldname,newname, 0,is_dir);

out:
    return error;
}

#endif

int may_chmod_path(const char* pathname,int is_dir)
{
    return generic_path_security(FILE_MODIFY, pathname,is_dir);
}

int may_chown_path(const char* pathname,int is_dir)
{
    return generic_path_security(FILE_MODIFY, pathname,is_dir);
}

int may_close_path(const char* pathname,int is_dir)
{
    return generic_path_security(FILE_CLOSE, pathname,is_dir);
}


int may_ioctl_path(const char* pathname,int is_dir)
{
    return generic_path_security(FILE_MODIFY, pathname,is_dir);
}

int may_utimes_path(const char* pathname,int is_dir)
{
    return generic_path_security(FILE_MODIFY, pathname,is_dir);
}

//hard link
int may_link_path(const char* koldname,int newdfd,
            const char __user* newname,
            int lookup_flags,int is_dir)
{
    int error = -ENOENT;

    error = generic_path_security(FILE_MODIFY, koldname,is_dir);
    if(error) { goto out; }

    //Note: the newname may be not existing
    error = generic_path_security2(FILE_MODIFY, newdfd,newname,
                        lookup_flags,is_dir);

out:
    return error;
}

int may_symlink_path(const char* koldname,int is_dir,
        int newdfd,const char __user* newname)
{
    int error = -ENOENT;

    error = generic_path_security(FILE_MODIFY, koldname,is_dir);
    if(error) { goto out; }

    //Note: the newname may be not existing,follow link
    error = generic_path_security2(FILE_MODIFY, newdfd,newname,LOOKUP_FOLLOW,0);

out:
    return error;
}
