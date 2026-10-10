#ifndef kvd_CORE_H
#define kvd_CORE_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/err.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h> //fo get_task_struct,put_task_struct
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
#include <linux/cred.h> //for current_user_ns
#endif

/*
 *struct path在2.6.20之前的内核中是没有定义的.
 *2.6.25之前的内核struct path定义在linux/namei.h头文件中
 *从2.6.25开始struct path定义在linux/path.h头文件中
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#include <linux/path.h> //for struct path
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
#include <generated/utsrelease.h> //for UTS_RELEASE
#else
#include <linux/vermagic.h> //for UTS_RELEASE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
    //get the pid-id seen from the init namespace
    #define PID(ts) task_tgid_nr(ts)
#else
    #define PID(ts) ((ts)->tgid)
#endif

/* uid and euid */
#define EUID(ts) kvd_get_task_euid((ts))
#define UID(ts)  kvd_get_task_uid((ts))
#define EGID(ts) kvd_get_task_egid((ts))
#define GID(ts)  kvd_get_task_gid((ts))
#define COMM(ts) (ts->group_leader)->comm

#define CURRENT_PID PID(current)
#define CURRENT_EUID EUID(current)
#define CURRENT_UID UID(current)
#define CURRENT_COMM (current->group_leader)->comm


//file system name
#define FS_NAME(dentry)      (dentry)->d_sb->s_type->name
#define FS_MAGIC(dentry)     (dentry)->d_sb->s_magic

uid_t kvd_get_task_uid(struct task_struct* tsk);
uid_t kvd_get_task_euid(struct task_struct* tsk);
gid_t kvd_get_task_gid(struct task_struct* tsk);
gid_t kvd_get_task_egid(struct task_struct* tsk);


/*
 *here we don't define the function begin with "kbase",
 *because kernel has defined nameidata_to_path after 2.6.39
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
void nameidata_to_path(struct nameidata* nd,struct path* path);
#endif

/*
 *get struct path by pathname of user-space
 *Caller must call kvd_path_put to free return-value "path"
 *flags -->lookup flags like: 0,LOOKUP_EMPTY,LOOKUP_FOLLOW
 */
int kvd_user_path_at(int dfd, const char __user *name, unsigned flags,
		 struct path *path);

/*
 *lookup pathname,return struct path
 *Caller must call kvd_path_put to free return-value "path"
 *flags-->lookup flags like: 0,LOOKUP_EMPTY,LOOKUP_FOLLOW,LOOKUP_DIRECTORY
 */
int kvd_path_lookup(const char* pathname,
				unsigned int flags,struct path* path);

void kvd_path_get(struct path* path);
void kvd_path_put(struct path* path);

/*
 *get pathname by struct path
 *Caller must ensure that "path" is pinned before calling kvd_get_pathname(),
 *and Caller must call kvd_put_pathname to free the return-value
 */
char* kvd_get_pathname(struct path* path,unsigned int* len);
void kvd_put_pathname(const char* pathname);

/*
 *get struct path by struct filp
 *Caller must call kvd_path_put to free the return-value "path"
 */
int kvd_filp_path(struct file* filp,struct path* path);
/*
 *get fs-root by struct fs_struct
 *Caller must call kvd_path_put to free the return-value "root"
 */
void kvd_get_fs_root(struct fs_struct* fs,struct path* root);

/*
 *get file system pwd by fs_struct
 * Caller must call kvd_path_put to free the return-value "pwd"
 */
 void kvd_get_fs_pwd(struct fs_struct* fs,struct path* pwd);
/*
 *get pathname by struct file
 *Caller must call kvd_put_pathname to free the return-value
 */
char* kvd_filp_pathname(struct file* filp,unsigned int* pathlen);
int kvd_dentry_path(struct dentry *dentry, struct path *path);

uint32_t kvd_murmur_hash2(const u_char *data, size_t len);
uid_t kvd_get_kstat_uid(const struct kstat* stat);
gid_t kvd_get_kstat_gid(const struct kstat* stat);

int kvd_vfs_getattr(struct path* path,struct kstat* stat);
int kvd_vfs_getstatfs(struct path* path,struct kstatfs* kstfs);

//Note:调用这个函数时要保证struct inode在整个调用期间是有效的
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
#include <linux/mnt_idmapping.h>
int kvd_generic_fillattr(struct mnt_idmap *idmap,
        struct inode *inode, struct kstat *stat);
#else
int kvd_generic_fillattr(struct inode* inode,struct kstat* stat);
#endif

//Get attributes without calling security_inode_getattr
int kvd_vfs_getattr_nosec(struct path* path,struct kstat* stat);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
/**
 * kstrndup - allocate space for and copy an existing string
 * @s: the string to duplicate
 * @max: read at most @max chars from @s
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 */
char *kstrndup(const char *s, size_t max, gfp_t gfp);
#endif

//这里跟内核的snprintf不同，我们返回真正写入的数据长度;
//而内核的snprintf可能会返回>=size的值，此时表示数据被截断了
int kvd_snprintf(char* buf,size_t size, const char *fmt,...);
//get session-id
pid_t kvd_get_sid(struct task_struct* tsk);

//get executable path for task,
//the caller must call kvd_path_put to free the return value path
int kvd_get_task_exe(struct task_struct* tsk,struct path* path);

//获取运行中进程对应的可执行文件完整路径，返回值需要使用kvd_put_pathname释放
//如果需要在binfmt结构中获取进程对应的可执行文件，一定不能调用这个函数
char* kvd_get_task_pathname(struct task_struct* tsk,
                            unsigned int* len);

//get file-system type magic number
uint64_t kvd_get_fs_magic(struct path* path);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
int d_unlinked(struct dentry *dentry);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
struct inode* file_inode(struct file* filp);
#endif

//lookup_flags-->0,LOOKUP_FOLLOW,LOOKUP_EMPTY
char* kvd_get_kernel_pathname(int dfd,const char __user* pathname,unsigned lookup_flags);

int kvd_hexc2n(char c);
//将二进制串转化为16进制大写可打印串
void kvd_bin2hex(const u_char* bin,size_t len,u_char* hexs);
//将16进制(不区分大小写)转化为二进制串
//hexs存在非16进制字符时返回错误
int kvd_hex2bin(const char* hexs,size_t hex_len,
                    u_char* bins,size_t bin_len);


//like getname in kernel,copy filename from user-space
//caller must call kvd_put_pathname to free the retval
char* kvd_getname(const char __user* filename);
 /*
 * get struct task_struct by pid and pid_type
 * Caller must call kbase_put_task_struct(struct task_struct*) to release task_struct reference
 */
struct task_struct* kvd_get_task_struct(pid_t pid);
/*
 *目前发现在Rocky4.0.2 _2.6.32.41的系统上
 *put_task_struct没有导出，所以处尽量不要使用
 *保留这个代码只是为了方便后面从现有代码中抽取相关代码独立使用
 */
#define kvd_put_task_struct put_task_struct

//持有rcu_read_lock的情况下才能调用该函数，否则极有可能出问题
struct task_struct* kvd_get_task_struct_locked(pid_t pid);

int kvd_try_self_module_get(void);
void kvd_self_module_put(void);

#if defined(CONFIG_MMU)
struct page;
struct mm_struct;
struct vm_area_struct;
//此处仅以只读方式获取相应的用户态页即可
int kvd_get_user_pages(struct task_struct* tsk,
                            struct mm_struct* mm,
                            unsigned long pos,
                            struct page** ppage,
                            struct vm_area_struct** pvma);
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    #define KVD_SET_UID(uid,kuid) \
        SET_UID(uid, from_kuid_munged(current_user_ns(),kuid))
#else
    #define KVD_SET_UID(uid,kuid) \
        SET_UID(uid,kuid)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    #define KVD_SET_GID(gid,kgid) \
        SET_GID(gid, from_kgid_munged(current_user_ns(),kgid))
#else
    #define KVD_SET_GID(gid,kgid) \
        SET_GID(gid,kgid)
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    /*
    * 1.RHEL5.0 has no macro RHEL_RELEASE_CODE
    * 2.other non-rhel don't have this marco, either.
    */
    #if defined RHEL_RELEASE_CODE
        #if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(5,1)
            #define RHEL_DEFINED_BOOL_TRUE_FALSE
        #endif
    #endif

    #ifndef RHEL_DEFINED_BOOL_TRUE_FALSE
        /*
        * Boolen type _Bool is introduced in C99. It's same to int/char/short.
        * And bool/true/false are defined as below in linux version 2.6.19, so
        * they are copied here.
        * But, again, the RHEL migrate these in their 2.6.18 branch, therefore,
        * if RHEL, don't define them except centos5.0(2.6.18-8).
        */
        typedef _Bool   bool;

        enum {
                false   = 0,
                true    = 1
        };
    #endif
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
    #define KVD_IS_ERR_OR_NULL IS_ERR_OR_NULL
#else
    static inline long KVD_IS_ERR_OR_NULL(const void *ptr)
    {
        return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
    }
#endif

int kvd_strncasecmp(const char *s1, const char *s2, size_t n);
int kvd_strcasecmp(const char *s1, const char *s2);

struct sk_buff;
u_char *kvd_skb_tail_pointer(const struct sk_buff *skb);

/*
 *Note:下面这几个kvd_skb_xxx函数一定要注意　
 *它们的使用场景很特定，都是在netfilter的hook中使用的
 *因为其使用的前提都是假定skb已经剥离了链路层头部了
 */
int kvd_skb_network_offset(const struct sk_buff *skb);
u_char* kvd_skb_network_header(const struct sk_buff* skb);


/*Note:
 *
 *在低于2.6.22版本的内核上，skb->h.raw是没有设置的与skb->data是同样的值
 *所以无法通过skb->h.raw来直接计算传输层头偏移,其值直接是nhdrlen网络层的头部大小
 *
 *@skb: socket buffer
 *@nhdrlen: 网络层协议头部长度
 */
int kvd_skb_transport_offset(const struct sk_buff* skb,u_int nhdrlen);

/*Note: 
* 在低于2.6.22版本的内核上，skb->h.raw是没有设置的与skb->data是同样的值
 *@skb: socket buffer
 *@nhdrlen: 网络层协议头部长度
 */
u_char* kvd_skb_transport_header(const struct sk_buff* skb,u_int nhdrlen);

char *kvd_strnstr(const char *s1, const char *s2, size_t len);
ssize_t kvd_kernel_read(struct file* file,void* buf,
                        size_t count,loff_t* pos);


char* kvd_get_pwd_pathname(unsigned* plen);

void kvd_module_core_addr(struct module* this,u_long* start,u_long* end);
void kvd_module_init_addr(struct module* this,u_long* start,u_long* end);
int kvd_within_module(struct module* mod,
                    unsigned long addr);

int kvd_register_binfmt(struct linux_binfmt* binfmt);
void kvd_unregister_binfmt(struct linux_binfmt* binfmt);


ssize_t kvd_kernel_write(struct file* file,const char* buf,
                        size_t count,loff_t* pos);
int kvd_fsync(struct file *file, int datasync);

static inline u_long kvd_task_state(struct task_struct* task)
{
#if SPEC_VERSION_BUILD == 1
    return READ_ONCE(task->__state);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
    return READ_ONCE(task->__state);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    return READ_ONCE(task->state);
#else
    return task->state;
#endif
#endif
}

//版本号只能是xxx.xxx.xxx.xxx这种，
//并且最多支持9999.9999.9999.9999
//每一节转换成整数时占15位
uint64_t kvd_appver(const char* appver);
//版本号只能是xxx.xxx.xxx.xxx这种，
//并且最多支持9999.9999.9999.9999
//每一节转换成整数时占15位
char* kvd_str_appver(char* buf,size_t len,
                    uint64_t nver);

//版本号比较，只支持:xxx.xxx.xxx.xxx这种
//sv1 == sv2: 返回0
//sv1 < sv2 返回-1
//sv1 > sv2 返回1
int kvd_vercmp(const char* sv1,
                const char* sv2);

int kvd_preset_config_enabled(void);
void kvd_preset_config_setenable(void);

#endif //end define
