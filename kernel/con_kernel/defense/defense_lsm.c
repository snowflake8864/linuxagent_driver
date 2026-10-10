#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h> //fo SEND_SIG_FORCED
#endif

#include "gnHead.h"
#include "utils/utils.h"
#include "lsm/kvd_commlsm.h"
#include "core/kvd_core.h"
#include "defense_inner.h"
#include "defense_lsm.h"
#include "core/gnkernel.h"
#include "khookframe.h"

static u_long defense_lsm_on = 0;
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)

#define PID_MAX 4194304
static uint32_t pidBitMap[PID_MAX/32];

static int pid_to_index(uint32_t pid) {  
    return pid / 32;  
}  
  
void set_block_pid(int pid) 
{  
    int index = pid_to_index(pid);  
    int bit = pid % 32;  
    pidBitMap[index] |= 1 << bit;  
}  
static void clear_block_all_pid(void) 
{  
    int i;
    for (i = 0; i < PID_MAX / 32; i++) {
        pidBitMap[i] = 0;
    }
}

// 清除指定的阻止 PID
static void clear_block_pid(int pid) 
{
    int index = pid_to_index(pid);
    int bit = pid % 32;
    pidBitMap[index] &= ~(1 << bit);
}

static int is_block_pid(int pid) {  
    int index = pid_to_index(pid);  
    int bit = pid % 32; 
    return (pidBitMap[index] & (1 << bit)) != 0;  
}  
#endif
#endif

static int may_modify_path(const int action, struct path* path)
{
    int rc = 0;
    int is_dir = 0;
    unsigned len = 0;
    char* pathname = NULL;
    struct inode* inode = NULL;

    if(!path || !path->mnt || !path->dentry) 
    {
        return rc;    
    }

    //是否为已删除的路径
    if(d_unlinked(path->dentry)) {
        return rc;
    }

    //inode在某些情况下可能为空，
    //比如defense_hook_lsm_path_mknod调用的第二个参数dentry
    inode = path->dentry->d_inode;
    if(!inode) { return rc; }
    
    //是否需要放过
    if(need_defense_skip(current)) {
        return rc;
    }

    pathname = kvd_get_pathname(path,&len);
    if(IS_ERR(pathname)) { return rc; }
    is_dir = S_ISDIR(inode->i_mode);
    //rc = may_defense_modify(action, pathname,len,is_dir, 0);
    rc = may_defense_modify(action, pathname, strlen(pathname),is_dir, 0);
    kvd_put_pathname(pathname);

    return rc;
}


static int may_modify_path2(const struct path* dir,
                struct dentry* dentry)
{
    struct path path = {
            .mnt = dir->mnt,
            .dentry = dentry
        };

    return may_modify_path(FILE_MODIFY, &path);
}

static int may_delete_path2(const struct path* dir,
                struct dentry* dentry)
{
    struct path path = {
            .mnt = dir->mnt,
            .dentry = dentry
        };

    return may_modify_path(FILE_REMOTE, &path);
}


static int may_modify_path3(struct path *path, int is_dir)
{
    int rc = 0;
    unsigned len = 0;
    char* pathname = NULL;

    if(!path || !path->mnt || !path->dentry) 
    {
        return rc;    
    }

    //是否为已删除的路径
    if(d_unlinked(path->dentry)) {
        return rc;
    }

    //是否需要放过
    if(need_defense_skip(current)) {
        return rc;
    }

    pathname = kvd_get_pathname(path,&len);
    if(IS_ERR(pathname)) { return rc; }
    
    //rc = may_defense_modify(FILE_MODIFY, pathname, len,is_dir, 0);
    rc = may_defense_modify(FILE_MODIFY, pathname, strlen(pathname),is_dir, 0);
    kvd_put_pathname(pathname);

    return rc;

}

static int may_create_path(struct path *path)
{
    int rc = 0;
#if 1
    unsigned len = 0;
    char* pathname = NULL;
    char _pathname[256] = {0};
    unsigned trip_len = 0;

    if(!path || !path->mnt || !path->dentry) 
    {
        return rc;    
    }

#if 1
    //是否为已删除的路径
    if(d_unlinked(path->dentry)) {
        //return rc;
        trip_len = 10;
    }
#endif

    //是否需要放过
    if(need_defense_skip(current)) {
        return rc;
    }

    pathname = kvd_get_pathname(path,&len);
    if(IS_ERR(pathname)) { return rc; }
   

    rc = may_defense_modify(FILE_CREATE, pathname,len - trip_len, 0, !!trip_len);
    //LOG_INFO("create =rc=%d======pid:%d, pathname:%s\n",rc,CURRENT_PID, pathname);
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    set_block_pid((int)CURRENT_PID);
    LOG_INFO("=rc=%d==set=====pid:%d, pathname:%s\n",rc,CURRENT_PID, pathname);
#endif
#endif
    kvd_put_pathname(pathname);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    set_block_pid((int)CURRENT_PID);
#endif

#endif
    return rc;

}

//for: chattr
//it's just for chattr
static int is_set_ioctl_cmd(unsigned int cmd)
{
	return ((cmd == FS_IOC32_SETFLAGS) ||
			(cmd == FS_IOC_SETFLAGS));
}

static int may_file_ioctl(struct file *file, unsigned int cmd)
{
    int rc = 0;
    unsigned len = 0;
    char* pathname = NULL;

    if(!is_set_ioctl_cmd(cmd)) {
        goto out;
    }

    //先判断一下是否要放过，能快一些就快一些
    //因为下面获取路径是相对较慢的
    if(need_defense_skip(current)) {
        goto out;
    }

    pathname = kvd_filp_pathname(file,&len);
    if(IS_ERR(pathname)) {
        goto out;
    }
    
    //rc = may_defense_modify(FILE_MODIFY, pathname,len,0, 0);
    rc = may_defense_modify(FILE_MODIFY, pathname, strlen(pathname),0, 0);
out:
    if(!KVD_IS_ERR_OR_NULL(pathname)) {
        kvd_put_pathname(pathname);
    }
    return rc;
}

static int is_file_write(struct file* filp)
{
    int rc = 0;
    unsigned int f_flags = 0;

    if(!filp) { return rc; }

    f_flags = filp->f_flags;

    return is_modify_open_flag(f_flags);
}

static int may_file_open(struct file* file)
{
    int rc = 0;
    unsigned len = 0;
    char* pathname = NULL;
#if 0    
    if(!is_file_write(file)) {
        return rc;
    }
#endif
    //先判断一下是否要放过，能快一些就快一些
    //因为下面获取路径是相对较慢的
    if(need_defense_skip(current)) {
        return rc;
    }

    pathname = kvd_filp_pathname(file,&len);
    if(IS_ERR(pathname)) {
        goto out;
    }
     if(!is_file_write(file)) {
        rc = may_defense_modify(FILE_OPEN, pathname, strlen(pathname),0, 0);
    } else {
    //rc = may_defense_modify(FILE_OPEN, pathname,len,0, 0);
    rc = may_defense_modify(FILE_MODIFY, pathname, strlen(pathname),0, 0);
    //LOG_INFO("open =rc=%d======pid:%d, pathname:%s\n",rc,CURRENT_PID, pathname);
    }
out:
    if(!KVD_IS_ERR_OR_NULL(pathname)) {
        kvd_put_pathname(pathname);
    }

    return rc;
}

int defense_hook_lsm_ptrace_access_check(struct task_struct *child,
					            unsigned int mode)
{
	int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

	//目前只需要支持4.4以上版本的内核
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	if(mode & PTRACE_MODE_ATTACH) { 
		rc = may_defense_task_ptrace(child);
	}
#endif
    kvd_self_module_put();

	return rc;
}

int defense_hook_lsm_path_unlink(const struct path *dir,
                        struct dentry *dentry)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path2(dir,dentry);

    kvd_self_module_put();
    return rc;
}


int defense_hook_lsm_path_mkdir(const struct path *dir,
                        struct dentry *dentry,
                        umode_t mode)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }
    rc = may_modify_path(FILE_CREATE, (struct path*)dir);

    kvd_self_module_put();
    return rc;
}

int defense_hook_lsm_path_rmdir(const struct path *dir,
                    struct dentry *dentry)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    //rc = may_modify_path2((struct path*)dir,dentry);
    rc = may_delete_path2((struct path*)dir,dentry);
    kvd_self_module_put();

    return rc;
}


//for: defense create new file
int defense_hook_lsm_path_mknod(const struct path *dir,
                    struct dentry *dentry,
                    umode_t mode, unsigned int dev)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_CREATE,(struct path*)dir);
    kvd_self_module_put();

    return rc;
}

int defense_hook_lsm_path_truncate(const struct path *path)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_MODIFY,(struct path*)path);
    kvd_self_module_put();

    return rc;
}

int defense_hook_lsm_path_symlink(const struct path *dir,
                struct dentry *dentry,
                const char *old_name)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_CREATE, (struct path*)dir);
    kvd_self_module_put();

    return rc;
}

//for hard-link
int defense_hook_lsm_path_link(struct dentry *old_dentry,
                const struct path *new_dir,
                struct dentry *new_dentry)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    struct path path1 = { .mnt = new_dir->mnt, .dentry = old_dentry };

    if(!gotmod) { return rc; }

    //先判断一下是否要放过，能快一些就快一些
    //因为下面获取路径是相对较慢的
    if(need_defense_skip(current)) {
        goto out;
    }

    rc = may_modify_path(FILE_CREATE, (struct path*)new_dir);
    if(rc) { goto out; }

    rc = may_modify_path(FILE_OPEN, &path1);

out:
    kvd_self_module_put();

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
int defense_hook_lsm_path_rename(const struct path *old_dir,struct dentry *old_dentry,
            const struct path *new_dir,struct dentry *new_dentry, unsigned int flags)
#else
int defense_hook_lsm_path_rename(const struct path *old_dir,struct dentry *old_dentry,
            const struct path *new_dir,struct dentry *new_dentry)
#endif
{
    int rc = 0;
    struct inode* inode = NULL;
    int gotmod = kvd_try_self_module_get();
    struct path path1 = { .mnt = old_dir->mnt, .dentry = old_dentry };
    struct path path2 = { .mnt = new_dir->mnt, .dentry = new_dentry };

    if(!gotmod) { return rc; }

    //先判断一下是否要放过，能快一些就快一些
    //因为下面获取路径是相对较慢的
    if(need_defense_skip(current)) {
        goto out;
    }
#if 0

    //先检测目地路径,此处没有必要使用new_dentry了
    //只检测目地路径目录即可
    rc = may_modify_path(FILE_CREATE, (struct path*)new_dir);
    if(rc) { goto out; }
    rc = may_modify_path(FILE_CREATE, (struct path*)old_dir);
    if(rc) { goto out; }



    //error = may_defense_modify_mv(action_type, kpathname, rpathlen1, kpathname_new, rpathlen2, is_dir);
    //再检测源路径
    rc = may_modify_path(FILE_OPEN,&path1);
    rc = may_modify_path(FILE_OPEN,&path2);
#else

    int len1 = 0, len2 = 0;
    char *pathname1 = kvd_get_pathname(&path1,&len1);
    if(IS_ERR(pathname1)) { return rc; }
    inode = path1.dentry->d_inode;
    if(unlikely(inode == NULL)) { return rc; }
    int is_dir = S_ISDIR(inode->i_mode);

    char *pathname2 = kvd_get_pathname(&path2,&len2);
    rc = may_defense_modify_mv(FILE_RENAME, pathname1, len1, pathname2, len2, is_dir);
    kvd_put_pathname(pathname2);
    kvd_put_pathname(pathname1);
#endif
out:
    kvd_self_module_put();

    return rc;
}

int defense_hook_lsm_path_chmod(const struct path *path, umode_t mode)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_MODIFY,(struct path*)path);
    kvd_self_module_put();
    
    return rc;
}

int defense_hook_lsm_path_chown(const struct path *path,kuid_t uid, kgid_t gid)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_MODIFY,(struct path*)path);
    kvd_self_module_put();

    return rc;
}

//for: inode
int defense_hook_lsm_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;
    int is_dir = 0;
    struct path path;

    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    if (!dir) { goto out; }

    rc = kvd_dentry_path(dentry, &path);
    if (0 != rc) {
        rc = 0;                                       
        goto out; 
    } 

    is_dir = S_ISDIR(dir->i_mode);
   
    rc = may_modify_path3(&path,is_dir);
    kvd_path_put(&path);
out:  
    kvd_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_mkdir(struct inode *dir, struct dentry *dentry,
                            umode_t mode)
{
    int rc = 0;
    int is_dir = 0;
    struct path path;

    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    if (!dir) {goto out; }

    rc = kvd_dentry_path(dentry, &path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);

    rc = may_modify_path3(&path,is_dir);
    kvd_path_put(&path);
out:    
    kvd_self_module_put();
    return rc;
}


int defense_hook_lsm_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;
    int is_dir = 0;
    struct path path;

    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    if (!dir) {goto out; }

    rc = kvd_dentry_path(dentry, &path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);
    //rc = may_modify_path(FILE_MODIFY,&path);
    rc = may_modify_path(FILE_REMOTE,&path);
    kvd_path_put(&path);
out:   
    kvd_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                                struct inode *new_dir, struct dentry *new_dentry)
{
    int rc = 0;
    int is_dir = 0;
    struct path old_path;
    struct path new_path;

    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }
     
    if(!old_dir) { goto out; } 
    //尽量快一点
    if(need_defense_skip(current)) {
        goto out;
    }

    rc = kvd_dentry_path(old_dentry, &old_path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    rc = kvd_dentry_path(new_dentry, &new_path);
    if (0 != rc) {
        rc = 0;
        kvd_path_put(&old_path);
        goto out;
    }

    is_dir = S_ISDIR(old_dir->i_mode);
    //先检测目地路径
    rc = may_modify_path3(&new_path,is_dir);
    if(rc) { 
        kvd_path_put(&old_path);
        kvd_path_put(&new_path);
        goto out; 
    }

    //再检测源路径
    rc = may_modify_path3(&old_path,is_dir);

    kvd_path_put(&old_path);
    kvd_path_put(&new_path);

out:
    kvd_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_link(struct dentry *old_dentry, struct inode *dir,
                            struct dentry *new_dentry)
{
    int rc = 0 ;
    int is_dir = 0;
    struct path old_path;
    struct path new_path;

    int gotmod = kvd_try_self_module_get();
    if (!gotmod) {
        return rc;
    }

    if(!dir) {goto out; } 
    //尽量快一点
    if(need_defense_skip(current)) {
        goto out;
    }

    rc = kvd_dentry_path(old_dentry,&old_path);
    if(0 != rc) {
        rc = 0;
        goto out;
    }

    rc = kvd_dentry_path(new_dentry,&new_path);
    if(0 != rc) {
        rc = 0;
        kvd_path_put(&old_path);
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);
    //先检测目的路径
    rc = may_modify_path3(&new_path,is_dir);
    if(rc) { 
        kvd_path_put(&old_path);
        kvd_path_put(&new_path);
        goto out; 
    }

     //再检测源路径
    rc = may_modify_path3(&old_path,is_dir);

    kvd_path_put(&old_path);
    kvd_path_put(&new_path);
out:
    kvd_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_mknod(struct inode *dir, struct dentry *dentry,
                            umode_t mode, dev_t dev)
{   
    int rc = 0;
    int is_dir = 0;
    struct path path;

    int gotmod = kvd_try_self_module_get();
    if(!gotmod) {
        return rc;
    }

    if(!dir) {goto out; }

    rc = kvd_dentry_path(dentry,&path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);

    rc = may_modify_path3(&path,is_dir);
    kvd_path_put(&path);

out:
    kvd_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_symlink(struct inode *dir, struct dentry *dentry,
                            const char *old_name)
{
    int rc = 0;
    int is_dir = 0;
    struct path path;
    int gotmod = kvd_try_self_module_get();
    if (!gotmod) {
        return rc;
    }

    if(!dir) {goto out; }

    rc = kvd_dentry_path(dentry,&path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);
    
    rc = may_modify_path3(&path,is_dir);
    kvd_path_put(&path);

out:
    kvd_self_module_put();
    return rc;
}

//for: chattr
int defense_hook_lsm_file_ioctl(struct file *file, unsigned int cmd,
            unsigned long arg)
{
    int rc = 0;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_file_ioctl(file,cmd);
    kvd_self_module_put();

    return rc;
}

//for: just for utimes,we don't care chmod,chown or others at here
int defense_hook_lsm_inode_setattr(struct dentry* dentry,struct iattr* attr)
{
    int rc = 0;
    struct path pwd;
    struct path path;
    unsigned ia_valid = ATTR_CTIME | ATTR_MTIME | ATTR_ATIME;

    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    if(!dentry || !attr) {
        goto out;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,9)
    //明确是utimes操作
    if(!(attr->ia_valid & ATTR_TOUCH)) {
        goto out;
    }
#endif

    if(!(attr->ia_valid & ia_valid)) {
        goto out;
    }

    if(d_unlinked(dentry)) {
        goto out;
    }

    //这个不是很准确：
    //dentry对应的mnt不一定跟当前进程相同
    //我们也只能保证尽可能的准确
    kvd_get_fs_pwd(current->fs,&pwd);
    path.mnt = pwd.mnt;
    path.dentry = dentry;

    rc = may_modify_path(FILE_MODIFY,&path);

    kvd_path_put(&pwd);

out:
    kvd_self_module_put();
    return rc;
}

//for: open exist file to write,
//无法防不存时的create file
int defense_hook_lsm_file_open(struct file *file)
{
    int rc = 0;

    int gotmod = kvd_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_file_open(file);
    kvd_self_module_put();

    return rc;
}
static void defense_get_task_comm(char comm[TASK_COMM_LEN],pid_t pid)
{
    struct task_struct* ts = NULL;

    rcu_read_lock();
    ts = kvd_get_task_struct_locked(pid);
    if (ts) {
        strncpy(comm,ts->comm,
            TASK_COMM_LEN - 1);
    }
    rcu_read_unlock();
}

//@pid-->target pid
static int may_defense_kill(pid_t pid,
            struct task_struct* sender)
{
    int rc = 0;
    char comm[TASK_COMM_LEN] = "NULL";
//    LOG_INFO("may_defense_kill self enable:%d\n", is_self_enable());
    if (!is_self_enable() ) {
        //LOG_INFO("may_defense_kill self enable:%d\n", self_enable);
        rc = 0;
    } else {
        defense_get_task_comm(comm,pid);
        if(memcmp(comm, "MagicArmor", 10) == 0) 
        {
            rc = -EACCES;
        } else {
            return 0;
        }
    }
    return rc;
}

static inline int get_process_path(pid_t pid, char *buf, size_t buflen) {
    struct path path_struct;
    char* real_path = NULL;
    char dbuffer[512];
    char path[128];
    dbuffer[0] = '\0';
    memset(path, 0, 128);
    snprintf(path, 128, "/proc/%d/exe", pid);
    // 解析路径

    int ret = kern_path(path, LOOKUP_FOLLOW, &path_struct);
    if (ret) {
//        printk("ret=%d,path[%s]\n",ret, path);
        return -1;
    }
    // 获取绝对路径
    real_path = d_path(&path_struct, dbuffer, 512);
    if (real_path) {
        strncpy(buf, real_path, buflen);
    }
    path_put(&path_struct);
    return 0;
}



static inline int send_kill_self_protect_data_to_user(pid_t pid)
{
    int nDeny = 0;
    struct av_self_protection_info pi;
    memset(&pi, 0, sizeof(struct av_self_protection_info));
    pi.uid = CURRENT_UID;
    pi.pid = CURRENT_PID;
    get_process_path(CURRENT_PID, pi.comm, sizeof(pi.comm));
    pi.type = 4710;
    strncpy(pi.path, "MagicArmor_0", sizeof(pi.path) - 1);
    send_nowait_nl_data(NL_POLICY_AV_SELF_PROTECTION_NOTIFY, &pi, sizeof(struct av_self_protection_info));
    return nDeny;
}


static int defense_hook_lsm_kill(struct task_struct *p, struct siginfo *info,
            int sig)
{
    int rc = 0;
    //rc = -EACCES;
    pid_t pid = PID(p);
    rc = may_defense_kill(pid, current);
    if(rc) {
        send_kill_self_protect_data_to_user(pid);
    }
    return rc;
}

#if 1

int defense_hook_lsm_inode_create(struct inode *dir, struct dentry *dentry,
                            umode_t mode)
{   
    int rc = 0;

  //  int is_dir = 0;
    struct path path;
    int gotmod = kvd_try_self_module_get();
    if(!gotmod) {
        return rc;
    }

    if(!dir) {goto out; }

    rc = kvd_dentry_path(dentry,&path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

//    is_dir = S_ISDIR(dir->i_mode);
    rc = may_create_path(&path);
    kvd_path_put(&path);

out:
    kvd_self_module_put();
    return rc;
}
#endif

static int defense_socket_bind_lsm_socket_bind(struct socket *sock, struct sockaddr *address,
        int addrlen)
{
    int rc = 0;

    LOG_INFO("bin ========================\n");
    return rc;
}

static struct kvd_security_operations defense_options = {
    .name = "defense_security",

    .ptrace_access_check = defense_hook_lsm_ptrace_access_check,
#ifdef CONFIG_SECURITY_PATH
    .path_unlink = defense_hook_lsm_path_unlink,
    .path_mkdir = defense_hook_lsm_path_mkdir,
    .path_rmdir = defense_hook_lsm_path_rmdir,
    .path_mknod = defense_hook_lsm_path_mknod,
    .path_truncate = defense_hook_lsm_path_truncate,
    .path_symlink = defense_hook_lsm_path_symlink,
    .path_link = defense_hook_lsm_path_link,
    .path_rename = defense_hook_lsm_path_rename,
    .path_chmod = defense_hook_lsm_path_chmod,
    .path_chown = defense_hook_lsm_path_chown,
#else
    .inode_unlink = defense_hook_lsm_inode_unlink,
    .inode_mkdir = defense_hook_lsm_inode_mkdir,
    .inode_rmdir = defense_hook_lsm_inode_rmdir,
    .inode_rename = defense_hook_lsm_inode_rename,
    .inode_link = defense_hook_lsm_inode_link,
    .inode_mknod = defense_hook_lsm_inode_mknod,
    .inode_symlink = defense_hook_lsm_inode_symlink,
#endif
    .inode_setattr = defense_hook_lsm_inode_setattr,
    .file_ioctl = defense_hook_lsm_file_ioctl,
    .file_open = defense_hook_lsm_file_open,
    .inode_create = defense_hook_lsm_inode_create,
    .task_kill = defense_hook_lsm_kill,

#ifdef CONFIG_SECURITY_NETWORK
//    .socket_bind =  defense_socket_bind_lsm_socket_bind,
#endif
};

extern int _hook_lsm_on;
void defense_hook_lsm_ops(void)
{
    if(_hook_lsm_on && !test_and_set_bit(0, &defense_lsm_on)) {
        kvd_register_commlsm_hook(&defense_options);
    }
}

void defense_cleanup_lsm_ops(void)
{
}

int defense_lsm_init(void)
{
    return 0;
}

void defense_lsm_uninit(void)
{
    if(_hook_lsm_on && test_and_clear_bit(0, &defense_lsm_on)) {
        kvd_unregister_commlsm_hook(&defense_options);
    }
}
