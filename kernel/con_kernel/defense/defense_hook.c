#include <linux/fs.h>
#include <net/genetlink.h>
#include <linux/profile.h>
#include <linux/unistd.h>
#include <linux/ctype.h>

#include "utils/utils.h"
#include "defense_hook.h"
#include "fs/fs_core.h"
#include "core/gnkernel.h"
#include "clientexit/client_exit.h"
#include "utils/hash_table.h"
#include "utils/sub_path.h"
#include "hook/hook.h"
#include "path_security.h"
#include "syscall_def.h"
#include "defense_inner.h"
#include "defense_sysfs.h"
#include "defense_lsm.h"
#include "utils/var_proc.h"


extern struct proc_dir_entry *proc_osec;
u_long defense_debug = 0;
static struct vsec_rb_htable protect_paths;

void defense_do_debug(int bon)
{
    if(bon) { set_bit(0,&defense_debug); }
    else { clear_bit(0,&defense_debug); }

    vsec_rb_htable_debug(&protect_paths,bon);
}
////////////////////////////////////////////////////////////////////////////////


static volatile int root_pid = 0;
static unsigned long self_protect_enable = 0;
static unsigned long defense_enable = 0;
static unsigned long syslog_enable = 0;

enum DEFENSEBFLAGS{
    DEFENSE_ENABLE = 0,
    SELF_PROTECT_ENABLE,
    PROCESS_PROTECT_ENABLE,
    EXPOIT_PROTECT_ENABLE,
    FILE_PROTECT_ENABLE,
    FILE_MODE_ENABLE,
    PROCESS_MODE_ENABLE,
    EXPOIT_MODE_ENABLE,
    INTERNEL_ENABLE,
    SHOW_PROC_ENABLE,
};

enum SYSLOGBFLAGS{
    SYSLOG_INNER_ENABLE,
    SYSLOG_OUTER_ENABLE,
    SYSLOG_DNS_ENABLE,
};

int is_defense_enable(void)
{
    return test_bit(DEFENSE_ENABLE,&defense_enable);
}

void turn_off_defense(void)
{
    clear_bit(DEFENSE_ENABLE,&defense_enable);
}

void turn_on_defense(void)
{
    set_bit(DEFENSE_ENABLE,&defense_enable);    
}


int is_self_enable(void)
{
    //return self_enable;
    return (test_bit(SELF_PROTECT_ENABLE,&self_protect_enable));
}

void turn_on_self(void)
{
    set_bit(SELF_PROTECT_ENABLE,&self_protect_enable);    
}

void turn_off_self(void)
{
    clear_bit(SELF_PROTECT_ENABLE,&self_protect_enable);
}

int is_enable_show_proc(void)
{
    return (test_bit(SHOW_PROC_ENABLE,&self_protect_enable));
}
void turn_on_show_proc(void) 
{
    set_bit(SHOW_PROC_ENABLE,&self_protect_enable);    
}
void turn_off_show_proc(void) 
{
    clear_bit(SHOW_PROC_ENABLE,&self_protect_enable);    
}

int is_process_enable(void)
{
    //return process_enbale;
    return (test_bit(PROCESS_PROTECT_ENABLE,&defense_enable));
}

void turn_on_process(void)
{
    set_bit(PROCESS_PROTECT_ENABLE,&defense_enable);    
}

void turn_off_process(void)
{
    clear_bit(PROCESS_PROTECT_ENABLE,&defense_enable);
}

void turn_on_expoit(void)
{
    set_bit(EXPOIT_PROTECT_ENABLE,&defense_enable);    
}

void turn_off_expoit(void)
{
    clear_bit(EXPOIT_PROTECT_ENABLE,&defense_enable);
}

int is_expoit_enable(void) //lesuo
{
    return (test_bit(EXPOIT_PROTECT_ENABLE,&defense_enable));
}

int is_file_need_wait(void)
{
    return (defense_enable & ( 1 << FILE_MODE_ENABLE | 1 << EXPOIT_PROTECT_ENABLE));
}
int is_process_need_wait(void)
{
    return (test_bit(PROCESS_MODE_ENABLE,&defense_enable));
}

void turn_on_process_need_wait(void)
{
    set_bit(PROCESS_MODE_ENABLE,&defense_enable);
}
void turn_off_process_need_wait(void)
{
    clear_bit(PROCESS_MODE_ENABLE,&defense_enable);
}

int is_expoit_need_wait(void)
{
    return (test_bit(EXPOIT_MODE_ENABLE,&defense_enable));
}

void turn_on_expoit_need_wait(void)
{
    set_bit(EXPOIT_MODE_ENABLE,&defense_enable);
}
void turn_off_expoit_need_wait(void)
{
    clear_bit(EXPOIT_MODE_ENABLE,&defense_enable);
}

int is_file_enable(void)
{
    return (test_bit(FILE_PROTECT_ENABLE,&defense_enable));
}

void turn_on_file_protect(void)
{
    set_bit(FILE_PROTECT_ENABLE,&defense_enable);
}

void turn_off_file_protect(void)
{
    clear_bit(FILE_PROTECT_ENABLE,&defense_enable);
}


int is_file_protect_need_wait(void)
{
    return (test_bit(FILE_MODE_ENABLE,&defense_enable));
}

void turn_on_protect_need_wait(void)
{
    set_bit(FILE_MODE_ENABLE,&defense_enable);
}
void turn_off_protect_need_wait(void)
{
    clear_bit(FILE_MODE_ENABLE,&defense_enable);
}

void turn_on_internel(void)
{
    clear_bit(INTERNEL_ENABLE,&defense_enable);    
}

void turn_off_internel(void)
{
    set_bit(INTERNEL_ENABLE,&defense_enable);    
}

int is_internel_enable(void)
{
    return (!test_bit(INTERNEL_ENABLE,&defense_enable));
}

int is_syslog_inner_enable(void)
{
    return (test_bit(SYSLOG_INNER_ENABLE,&syslog_enable));
}
void turn_on_syslog_inner(void)
{
    set_bit(SYSLOG_INNER_ENABLE,&syslog_enable);    
}

void turn_off_syslog_inner(void)
{
    clear_bit(SYSLOG_INNER_ENABLE,&syslog_enable);
}

int is_syslog_outer_enable(void)
{
    return (test_bit(SYSLOG_OUTER_ENABLE,&syslog_enable));
}

void turn_on_syslog_outer(void)
{
    set_bit(SYSLOG_OUTER_ENABLE,&syslog_enable);    
}

void turn_off_syslog_outer(void)
{
    clear_bit(SYSLOG_OUTER_ENABLE,&syslog_enable);
}
int is_syslog_dns_enable(void)
{
    return (test_bit(SYSLOG_DNS_ENABLE,&syslog_enable));
}

void turn_on_syslog_dns(void)
{
    set_bit(SYSLOG_DNS_ENABLE,&syslog_enable);    
}

void turn_off_syslog_dns(void)
{
    clear_bit(SYSLOG_DNS_ENABLE,&syslog_enable);
}

typedef struct {
    const char* exe_name;
    size_t len;
} self_exe_t;


//init启动脚本名称
#define KOSEC_INIT_SCRIPT "osec.service"
#define KOSEC_INIT_OSEC_SCRIPT "service"KOSEC_COMP_NAME"osec"


static int match_self(struct task_struct* task)
{
    int ret = 1;
    size_t i = 0;
    self_exe_t* pexe = NULL;
    self_exe_t self_exes[] = {
        {"MagicArmor",10},
        {KOSEC_INIT_SCRIPT,sizeof(KOSEC_INIT_SCRIPT) - 1},
    };
    // if (root_pid == 0) {
    //     return ret;
    // }

    for(i = 0;i < ARRAY_SIZE(self_exes);i++) {
        pexe = self_exes + i;
        //LOG_INFO("process[%s]\n",COMM(task));
        if(!memcmp(COMM(task),
            pexe->exe_name,pexe->len))
        {
            return ret;
        }
    }

    ret = match_task_family(task, root_pid);

    return ret;
}

#if 0
int need_defense_skip(struct task_struct* task)
{
    int bneed = 0;
    bneed = (!is_defense_enable() || 
            match_self(task));

    return bneed;
}
#else
int need_defense_skip(struct task_struct* task)
{
    int bneed = 0;
    bneed = match_self(task);
    return bneed;
    bneed = (!(is_defense_enable() ||is_self_enable()) || 
            match_self(task));
    return bneed;
}
#endif

static int check_target_pid(pid_t pid)
{
    int ret = 0;
    struct task_struct* ts = NULL;
    
    rcu_read_lock();
    ts = kvd_get_task_struct_locked(pid);
    if(ts) {
        ret = match_task_family_locked(ts, root_pid);
    }
    rcu_read_unlock();

    return ret;
}


static int check_target_ptrace(pid_t pid)
{
    int ret = check_target_pid(pid);
    if (ret != 0) {
        DEFENSE_LOG_INFO("DRIVER[DEFENSE]: found ptrace target match, target:%d\n", pid);
    }
    return ret;
}

static int match_gdb(void)
{
    int ret = 0;
    if (memcmp(CURRENT_COMM, "gdb", 3) == 0) {
        ret = 1;
    }
    return ret;
}

////////////////////////////////////////////////////////////////////////////////

typedef struct {
	char* buf;
	size_t size;//buf大小
	int len;
}rbht_walk_ctx_t;

static void rbht_walk_cb(void* key,size_t key_len,
					void* data,void* ctx)
{
	size_t n = 0;
	rbht_walk_ctx_t* pctx = ctx;
	//one more character for ;
    if(pctx->size <= pctx->len) { return; }

	n = pctx->size - pctx->len - 1;
	n = min(key_len,n);

	memcpy(pctx->buf + pctx->len,key,n);		
	pctx->len += n;	
	pctx->buf[pctx->len++] = ';';
}

//此处返回实际的长度或错误
int get_defense_protect_paths(char* buf,size_t len)
{
	int rc = 0;
	rbht_walk_ctx_t ctx;
	
	ctx.len = 0;
	ctx.buf = buf;
	ctx.size = len;
	rc = vsec_rb_htable_walk(&protect_paths,
				&ctx,rbht_walk_cb);
	if(rc < 0) { return rc; }
	
	//此处返回实际的长度
	rc = ctx.len;
	
	return rc;
}

// b_add: true - 添加，false - 删除
int defense_add_del_path(char *path, size_t len, bool b_add)
{
    int ret;
    if (b_add) {
        ret = vsec_path_rbht_insert(&protect_paths, path, len);
    } else {
        ret = vsec_path_rbht_delete(&protect_paths, path, len);
    }
    return ret;
}

int defense_clean_path(void)
{
    vsec_path_rbht_cleanup(&protect_paths);
    return 0;
}




static int handle_cmd_switch_ex(void* data, int size)
{
    int val = *(int*)data;
    static int pre_val;

    //defense_enable = 0;
    if (val &0x10) {
        turn_on_expoit_need_wait();
    } else {
        turn_off_expoit_need_wait();
    }
    if (val &0x20) {
        turn_on_protect_need_wait();
    } else {
        turn_off_protect_need_wait();
    }
    if (val &0x40) {
        turn_on_process_need_wait();
    } else {
        turn_off_process_need_wait();
    }
    if (val &0x80) {
        turn_on_expoit();
    } else {
        turn_off_expoit();
    }
    if (val &0x100) {
        turn_on_file_protect();
    } else {
        turn_off_file_protect();
    }
    if ((val &0x200) != (pre_val &0x200)) {
        if (val &0x200) {
            turn_on_process();
            //start_process_audit_timer();
        } else {
            //stop_process_audit_timer();
            turn_off_process();
        }
    }
    if ((val &0x400) != (pre_val &0x400)) {
        if (val &0x400) {
            turn_on_syslog_inner();
            start_in_netlog_audit_timer();
        } else {
            stop_in_netlog_audit_timer();
            turn_off_syslog_inner();
        }
    }
    if ((val &0x800) != (pre_val &0x800)) {
        if (val &0x800) {
            turn_on_syslog_outer();
            start_out_netlog_audit_timer();
        } else {
            stop_out_netlog_audit_timer();
            turn_off_syslog_outer();
        }
    }
    if ((val &0x1000) != (pre_val &0x1000)) {
        if (val &0x1000) {
            turn_on_syslog_dns();
            start_dns_netlog_audit_timer();
        } else {
            stop_dns_netlog_audit_timer();
            turn_off_syslog_dns();
        }
    }
    if ((val &0x2000) == 0) {
        turn_off_internel();
    }
    if ((val &0x4000) != (pre_val &0x4000)) {
        if (val &0x4000) {
            start_openport_audit_timer();
        } else {
            stop_openport_audit_timer();
        }
    }

    pre_val = val;

    val = val & 0x0f;

    if (val) {
        if (memcmp((current->parent->group_leader)->comm, CURRENT_COMM, sizeof(CURRENT_COMM)) == 0) {
            root_pid = PID(current->parent);
        } else {
            root_pid = CURRENT_PID;
        }
    } else {
        root_pid = 0;
    }

    if (val == 0) {
        turn_off_defense();
    } else if (val == 1) {
        turn_off_defense();
    } else if (val == 2) {
        turn_on_defense();
    } else if (val == 3) {
        turn_on_defense();
    } else {
        LOG_INFO("unknow policy\n");
        turn_off_defense();
    }
    LOG_INFO("=========syslog_outer_switch=%d, syslog_inner_switch=%d, file_flag=%d, internel_enable:%d\n", is_syslog_outer_enable(),is_syslog_inner_enable(), is_file_enable(), is_internel_enable());
    return 0;
}


static int handle_cmd_self_switch(void* data, int size)
{
    int val = *(int*)data;

    if (val) {
        if (memcmp((current->parent->group_leader)->comm, CURRENT_COMM, sizeof(CURRENT_COMM)) == 0) {
            root_pid = PID(current->parent);
        } else {
            root_pid = CURRENT_PID;
        }
    } else {
        root_pid = 0;
    }

    if (val == 1) {
        turn_on_self();
    } else {
        turn_off_self();
    }
    return 0;
}


static vsec_con_cb_t con_callbacks[] = {
    {
        .index = NL_POLICY_DEFENSE_UNSPEC,
    },
    {
        .index = NL_POLICY_DEFENSE_SWITCHER,
//        .pfunc = handle_cmd_switch,
        .pfunc = handle_cmd_switch_ex,
    },
    {
        .index = NL_POLICY_DEFENSE_ADD_WHITE_EXE,
        .pfunc = handle_cmd_add_white_exes,
    },
    {
        .index = NL_POLICY_SELF_SWITCHER,
        .pfunc = handle_cmd_self_switch,
    },


};


static void cleanup_defense_policy(void)
{
    cleanup_white_exes();
    cleanup_hold_procs();
    clear_bit(0,&defense_enable);
    vsec_path_rbht_cleanup(&protect_paths);
}

//ts可能为空
static int client_exit_notify_fn(struct notifier_block* nb,
                            unsigned long val,void* data)
{
    int pid = 0;
    pid_t ts_pid = -1;
    struct task_struct* task = data;
    
    turn_off_defense();
    //打印日志有点慢，先保存一下旧的pid
    pid = root_pid;
    root_pid = 0;
    defense_cleanup_lsm_ops();
    cleanup_defense_policy();
    
    if(task) { ts_pid = PID(task); }
    DEFENSE_LOG_INFO("defense receive client[%d] exit notify,"
        "clear service pid [%d]\n",ts_pid,pid);
    return 0;
}

static struct notifier_block defense_notifier = {
    .notifier_call = client_exit_notify_fn,
};


#define DEFENSE_HOOK_STOP_FLAG (KVD_FLAG_STOP_NEXT | KVD_FLAG_USE_RC | KVD_FLAG_STOP_ORG)

static int is_task_white_exe(struct task_struct* task)
{
    int bwhite = 0;
    unsigned len = 0;
    const char* exe = ERR_PTR(-ENOENT);

    exe = kvd_get_task_pathname(task,&len);
    if(!IS_ERR(exe)) {
        bwhite = is_defense_white_exe(exe,len);
        kvd_put_pathname(exe);
    }

    return bwhite;
}

int is_current_white_exe(void)
{
    return is_task_white_exe(current);
}

int may_defense_modify(const int action, const char* kpathname,size_t len,int is_dir, int is_cut_kpathname)
{
    int rc = 0;
    int allow = 0;
#if 0
    do {
        allow = is_current_white_exe();
        if(allow) { break; }

        allow = !vsec_path_rbht_is_sub(&protect_paths,
                        kpathname,len);
        if(allow) { break; }
        rc = -EACCES;
    }while(0);
#else
    allow = file_audit_filepath(action, CURRENT_PID, kpathname, len, is_dir, is_cut_kpathname);
    if (allow) {
        rc = -EACCES;
    }


#endif
    //DEFENSE_LOG_DEBUG("defense modify file: %s,rc: %d\n",kpathname,rc);

    return rc;
}

int may_defense_modify_mv(const int action_type, const char* kpathname, const size_t len1, const char* kpathnamenew, const size_t len2,int is_dir)
{
    int rc = 0;
    int allow = 0;

    do {
        allow = file_audit_filepath_rename(action_type,CURRENT_PID, kpathname, len1, kpathnamenew, len2, is_dir);
        if (!allow) {
            break;
        }
        rc = -EACCES;
    }while(0);

//    LOG_DEBUG("defense modify file: %s, dstfile :%s, type :%d, rc: %d\n",kpathname, kpathnamenew, action_type, rc);

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

//@task-->target task
int may_defense_task_ptrace(struct task_struct* task)
{
    int rc = 0;

    if(need_defense_skip(current)) {
        return rc;
    }
    
    if (!match_gdb() && 
        match_task_family(task,root_pid)) 
    {
        rc = -EPERM;
        LOG_DEBUG("Defense Process %s:%d to "
                "ptrace vd process %s:%d\n", 
                CURRENT_COMM, CURRENT_PID,
                COMM(task),PID(task));
    }

    return rc;
}

static void defense_hook_ptrace(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    KVD_REG_CAST_TO_ARGS(4,regs,long,request,long,pid,
                u_long,addr,u_long,data);

    if(need_defense_skip(current)) { 
        return; 
    }

    if (match_gdb() || check_target_ptrace((pid_t)pid) == 0) {
        goto out;
    } else {
        char comm[TASK_COMM_LEN] = "NULL";

        rc = -EACCES;
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
        defense_get_task_comm(comm,pid);

        DEFENSE_LOG_INFO("DRIVER [DEFENSE]:Defense Process %s:%d to ptrace vd process %s:%ld\n", 
                CURRENT_COMM, CURRENT_PID, comm, pid);
        goto out;
    }

out:
    return;
}

//@pid-->target pid
static int may_defense_kill(pid_t pid,
            struct task_struct* sender)
{
    int rc = 0;
    char comm[TASK_COMM_LEN] = "NULL";
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
    //LOG_INFO("may_defense_kill self enable:%d , rc:%d\n", is_self_enable(), rc);
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


static void defense_hook_kill(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    KVD_REG_CAST_TO_ARGS(1,regs,long,pid
        );

   
    rc = may_defense_kill(pid, current);

    if(rc) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
        send_kill_self_protect_data_to_user(pid);
    }

out:
    return;
}

static int do_defense_hook_linkat(int olddfd,const char __user* oldname,
                        int newdfd,const char __user* newname,int flags)
{
    int rc = 0;
    int is_dir = 0;
    int lookup_flags = 0;
    struct kstat oldstat;
    char* koldname = ERR_PTR(-ENOENT);

    if(need_defense_skip(current)) { 
        return rc; 
    }

    if(get_lookup_flags(flags,&lookup_flags)) {
        goto out;
    }

    koldname = get_kernel_pathname_stat(olddfd,oldname,
                        lookup_flags,&oldstat);
    if(IS_ERR(koldname)) { goto out; }

    //create an hard link to a directory will occur an error
    is_dir = S_ISDIR(oldstat.mode);
    if(is_dir) { goto out; }

    rc = may_link_path(koldname,newdfd,newname,
                lookup_flags,is_dir);

out:
    if(!IS_ERR(koldname)) { kvd_put_pathname(koldname); }
    return rc;
}

static void defense_hook_linkat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(5,regs,int,olddfd,const char __user*,oldname,
                        int,newdfd,const char __user*,newname,int,flags);

    rc = do_defense_hook_linkat(olddfd,oldname,
                            newdfd,newname,flags);
    if(rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

static void defense_hook_link(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    int olddfd = AT_FDCWD;
    int newdfd = AT_FDCWD;

    KVD_REG_CAST_TO_ARGS(2,regs,const char __user*,oldname,
                        const char __user*,newname);

    rc = do_defense_hook_linkat(olddfd,oldname,
                            newdfd,newname,0);
    if(rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

//it's just for chattr
static int is_set_ioctl_cmd(unsigned int cmd)
{
	return ((cmd == FS_IOC32_SETFLAGS) ||
			(cmd == FS_IOC_SETFLAGS));
}

static void defense_hook_ioctl(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    int is_dir = 0;
    u_int pathlen = 0;
    struct kstat stat;
    struct file* fp = NULL;
    char* kpathname = ERR_PTR(-EBADF);

    KVD_REG_CAST_TO_ARGS(3,regs,
        u_int,fd,u_int,cmd,u_long,arg);
    
    if(!is_set_ioctl_cmd(cmd)) {
        return;
    }

    if(need_defense_skip(current)) { 
        return; 
    }

    rc = -EBADF;
    fp = fget(fd);
    if(!fp) { goto out; }

    rc = get_stat_by_file(fp,&stat);
    if(rc) { goto out; }

    kpathname = kvd_filp_pathname(fp,&pathlen);
    if(IS_ERR(kpathname)) { goto out; }

    is_dir = S_ISDIR(stat.mode);
    rc = may_ioctl_path(kpathname,is_dir);
    if(rc < 0) { 
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
  
out:
    if(fp) { fput(fp); }
    if(!IS_ERR(kpathname)) { kvd_put_pathname(kpathname); }
}

static int do_defense_hook_chown1(int dfd,
            const char __user* filename,int flag)
{
    int rc = 0;
    int error = 0;
    struct kstat oldstat;
    int lookup_flags = 0;
    const char* kpathname = ERR_PTR(-EBADF);

    error = get_lookup_flags(flag,&lookup_flags);
    if(error) { goto out; }

    kpathname = get_kernel_pathname_stat(dfd,filename,
                        lookup_flags,&oldstat);
    if(IS_ERR(kpathname)) { goto out; }

    rc = may_chown_path(kpathname,S_ISDIR(oldstat.mode));

out:
    if(!IS_ERR(kpathname)) { kvd_put_pathname(kpathname); }
    return rc;
}

static int do_defense_hook_chown2(unsigned int fd)
{
    int rc = 0;
    int err = 0;
    struct kstat oldstat;
    unsigned pathlen = 0;
    struct file* filp = NULL;
    const char* kpathname = ERR_PTR(-EBADF);

    filp = fget(fd);
    if(!filp) { goto out; }

    err = get_stat_by_file(filp,&oldstat);
    if(err) { goto out; }

    kpathname = kvd_filp_pathname(filp,&pathlen);
    if(IS_ERR(kpathname)) { goto out; }

    rc = may_chown_path(kpathname,S_ISDIR(oldstat.mode));

out:
    if(filp) { fput(filp); }
    if(!IS_ERR(kpathname)) { kvd_put_pathname(kpathname); }
    return rc;
}

static void defense_hook_chown(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(3,regs,
        const char __user *, filename, 
        uid_t, user, gid_t, group);

    if(need_defense_skip(current)) {
        return; 
    }

    //此处跟踪软链接
    rc = do_defense_hook_chown1(AT_FDCWD,filename,0);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static void defense_hook_lchown(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(3,regs,
        const char __user *, filename, 
        uid_t, user, gid_t, group);

    if(need_defense_skip(current)) { 
        return; 
    }

    //不跟踪软链接
    rc = do_defense_hook_chown1(AT_FDCWD,filename,
                            AT_SYMLINK_NOFOLLOW);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static void defense_hook_fchownat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(5,regs,
        int, dfd, const char __user *, filename, 
        uid_t, user, gid_t, group, int, flag);

    if(need_defense_skip(current)) { 
        return; 
    }

    rc = do_defense_hook_chown1(dfd,filename,flag);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static void defense_hook_fchown(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(3,regs,
       unsigned int, fd, 
       uid_t, user, gid_t, group);

    if(need_defense_skip(current)) { 
        return; 
    }

    rc = do_defense_hook_chown2(fd);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static int do_defense_hook_chmod1(int dfd,
                    const char __user* filename,
                    int flag)
{
    int rc = 0;
    int error = 0;
    struct kstat oldstat;
    int lookup_flags = 0;
    const char* kpathname = ERR_PTR(-EBADF);

    error = get_lookup_flags(flag,&lookup_flags);
    if(error) { goto out; }

    kpathname = get_kernel_pathname_stat(dfd,filename,
                        lookup_flags,&oldstat);
    if(IS_ERR(kpathname)) { goto out; }

    rc = may_chmod_path(kpathname,S_ISDIR(oldstat.mode));

out:
    if(!IS_ERR(kpathname)) { kvd_put_pathname(kpathname); }
    return rc;
}

static int do_defense_hook_chmod2(unsigned int fd)
{
    int rc = 0;
    int err = 0;
    struct kstat oldstat;
    unsigned pathlen = 0;
    struct file* filp = NULL;
    const char* kpathname = ERR_PTR(-EBADF);

    filp = fget(fd);
    if(!filp) { goto out; }

    err = get_stat_by_file(filp,&oldstat);
    if(err) { goto out; }

    kpathname = kvd_filp_pathname(filp,&pathlen);
    if(IS_ERR(kpathname)) { goto out; }

    rc = may_chmod_path(kpathname,S_ISDIR(oldstat.mode));

out:
    if(filp) { fput(filp); }
    if(!IS_ERR(kpathname)) { kvd_put_pathname(kpathname); }
    return rc;
}

static void defense_hook_chmod(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(2,regs,
        const char __user *, filename,
        umode_t, mode);

    if(need_defense_skip(current)) { 
        return; 
    }

    //follow symlink
    rc = do_defense_hook_chmod1(AT_FDCWD,filename,0);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static void defense_hook_fchmod(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(2,regs,
        unsigned int,fd,
        umode_t, mode);

    if(need_defense_skip(current)) { 
        return; 
    }

    rc = do_defense_hook_chmod2(fd);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static void defense_hook_fchmodat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(4,regs,
        int, dfd, 
        const char __user *, filename,
        umode_t, mode,int,flag);

    if(need_defense_skip(current)) { 
        return; 
    }

    rc = do_defense_hook_chmod1(dfd,filename,flag);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static int do_defense_hook_renameat(int olddfd,const char __user* oldname,
                                    int newdfd,const char __user* newname)
{
    int rc = 0;
    int is_dir = 0;
    struct kstat oldstat;
    char* koldname = ERR_PTR(-EINVAL);

    if(need_defense_skip(current)) { 
        return rc; 
    }

    //don't follow link
    koldname = get_kernel_pathname_stat(olddfd,oldname,0,&oldstat);
    if(IS_ERR(koldname)) { goto out; }

    is_dir = S_ISDIR(oldstat.mode);
    //oldname and newname must be same file-type
    rc = may_rename_path(koldname,newdfd,newname, oldname, is_dir);
    kvd_put_pathname(koldname);

out:
    return rc;
}

static void defense_hook_renameat2(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(5,regs,
            int,olddfd,
            const char __user*,oldname,
            int,newdfd,
            const char __user*, newname,
            unsigned int,flags);

    rc = do_defense_hook_renameat(olddfd,oldname,
                                newdfd,newname);
    if(rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

static void defense_hook_renameat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(4,regs,
            int,olddfd,
            const char __user*,oldname,
            int,newdfd,
            const char __user*, newname);

    rc = do_defense_hook_renameat(olddfd,oldname,
                                newdfd,newname);
    if(rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

static void defense_hook_rename(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(2,regs,
            const char __user*,oldname,
            const char __user*, newname);

    rc = do_defense_hook_renameat(AT_FDCWD,oldname,
                                AT_FDCWD,newname);
    if(rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

static void defense_hook_truncate(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    struct kstat oldstat;
    char* kpathname = ERR_PTR(-EINVAL);

    KVD_REG_CAST_TO_ARGS(2,regs,
        const char __user*,pathname,
        u_long,len);

    if(need_defense_skip(current)) { 
        goto out; 
    }

    //follow link
    kpathname = get_kernel_pathname_stat(AT_FDCWD,pathname,
                                LOOKUP_FOLLOW,&oldstat);
    if(IS_ERR(kpathname)) { goto out; }
    //truncate a directory will occur an error
    if(S_ISDIR(oldstat.mode)) { goto out; }

    rc = may_truncate_path(kpathname);
    if(rc) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }

out:
    if(!IS_ERR(kpathname)) { kvd_put_pathname(kpathname); }
}

static int do_defense_hook_mkdirat(int dfd,const char __user* pathname,u_int mode)
{
    int rc = 0;
    (void)mode;

    if(need_defense_skip(current)) { 
        return rc; 
    }

    rc = may_mkdir(dfd,pathname);
    return rc;
}

static void defense_hook_mkdirat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(3,regs,
        int,dfd,
        const char __user*,pathname,
        u_int,mode);

    rc = do_defense_hook_mkdirat(dfd,pathname,mode);
    if(rc) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

static void defense_hook_mkdir(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    int dfd = AT_FDCWD;

    KVD_REG_CAST_TO_ARGS(2,regs,
        const char __user*,pathname,
        u_int,mode);
    rc = do_defense_hook_mkdirat(dfd,pathname,mode);
    if(rc) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

static int do_defense_hook_unlinkat(int dfd,const char __user* pathname,int flag)
{
    int rc = 0;
    int is_dir = 0;
    struct kstat stat;
    char* kpathname = ERR_PTR(-EINVAL);

    if(need_defense_skip(current)) { 
        return rc; 
    }

    //flag just defined AT_REMOVEDIR,so check it
    if ((flag & ~AT_REMOVEDIR) != 0) { goto out; }

    is_dir = (flag & AT_REMOVEDIR);
    //文件路径获取失败，返回0
    kpathname = get_kernel_pathname_stat(dfd,pathname,0,&stat);
    if(IS_ERR(kpathname)) { 
        goto out; 
    }

    //never set AT_REMOVEDIR,but want to remove directory,will occur an error
    if(!is_dir && S_ISDIR(stat.mode)) {
        rc = -EISDIR;
        goto out;
    }

    //we want to remove a directory,but the path is not a directory
    if(is_dir && (!S_ISDIR(stat.mode))) { 
        rc = -ENOTDIR; 
        goto out; 
    }

    rc = may_unlink_path(kpathname,is_dir);
  
out:
    if(!IS_ERR(kpathname)) { kvd_put_pathname(kpathname); }
    return rc;
}

static void defense_hook_unlink(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    int flag = 0;
    int dfd = AT_FDCWD;

    KVD_REG_CAST_TO_ARGS(1,regs,
        const char __user*,pathname);

    rc = do_defense_hook_unlinkat(dfd,pathname,flag);
    if(rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

static void defense_hook_unlinkat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(3,regs,
        int,dfd,
        const char __user*,pathname,
        int,flag);

    rc = do_defense_hook_unlinkat(dfd,pathname,flag);
    if(rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG;
    }
}

int is_modify_open_flag(int flags)
{
    int rc = 0;
    rc = (flags & (O_CREAT | O_TRUNC | O_APPEND | O_WRONLY | O_RDWR));
    return rc;
}

static int do_defense_hook_openat(int dfd,
                    const char __user* pathname,
                    int flags,mode_t mode)
{
    int rc = 0;
    (void)mode;

    if(need_defense_skip(current)) { 
        return rc; 
    }
    if(!is_modify_open_flag(flags)) {
        rc = may_open_path(dfd,pathname,flags);
    } else {
        rc = may_open_path_ex(dfd,pathname,flags);
    }

    return rc;
}

static void defense_hook_open(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;
    int dfd = AT_FDCWD;

    KVD_REG_CAST_TO_ARGS(3,regs,
        const char __user*,pathname,
        int,flags,mode_t,mode);
    
    rc = do_defense_hook_openat(dfd,
                pathname,flags,mode);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static void defense_hook_openat(kvd_regs_t* regs,kvd_hook_ctx_t* ctx)
{
    int rc = 0;

    KVD_REG_CAST_TO_ARGS(4,regs,
        int,dfd,
        const char __user*,pathname,
        int,flags,mode_t,mode);
    
    rc = do_defense_hook_openat(dfd,
                pathname,flags,mode);
    if (rc < 0) {
        regs->rc = rc;
        regs->flag |= DEFENSE_HOOK_STOP_FLAG; 
    }
}

static int defense_product_notify(struct notifier_block* nb,
                            unsigned long val,void* data)
{
    product_notify_t* ptn = data;
    const char* action = "register";

    if(!ptn || (ptn->product != NL_PRODUCTION_SELF)) { 
        return NOTIFY_DONE; 
    }

    if(ptn->action == PTN_ACTION_UNREG) {
        turn_off_defense();
        defense_cleanup_lsm_ops();
        action = "unregister";
    } else {
        defense_hook_lsm_ops();
    }
    DEFENSE_LOG_INFO("self-hold product %s\n",action);

    return NOTIFY_STOP;
}

static struct notifier_block defense_ptn = {
            .notifier_call = defense_product_notify
        };

static struct kvd_hook_ops defense_hook_ops[] = {
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_open,SYS_OPEN_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_openat,SYS_OPENAT_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_mkdir,SYS_MKDIR_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_mkdirat,SYS_MKDIRAT_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_truncate,SYS_TRUNCATE_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_rename,SYS_RENAME_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_renameat,SYS_RENAMEAT_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_renameat2,SYS_RENAMEAT2_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_chmod,SYS_CHMOD_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_fchmod,SYS_FCHMOD_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_fchmodat,SYS_FCHMODAT_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_chown,SYS_CHOWN_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_fchown,SYS_FCHOWN_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_fchownat,SYS_FCHOWNAT_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_lchown,SYS_LCHOWN_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_ioctl,SYS_IOCTL_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_link,SYS_LINK_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_linkat,SYS_LINKAT_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_unlink,SYS_UNLINK_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_unlinkat,SYS_UNLINKAT_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_ptrace,SYS_PTRACE_INDEX),
        KVD_INIT_PREHOOK_FIRST_OPS(defense_hook_kill,SYS_KILL_INDEX),
    };

static int defense_echo_notifier_fn(struct notifier_block* nb,
                        unsigned long ecn,void* data)
{
    if((ecn != ECN_SET_PID) && (ecn != ECN_CLEAR_PID)) { 
        return NOTIFY_DONE; 
    }

    if(_hook_lsm_on == 0) { 
        return NOTIFY_DONE; 
    }

    //defense有产品注册通知，
    //ECN_SET_PID时我们不用在这里开启lsm-hook
    //但由于进程退出时极有可能不会有产品反注册通知
    //所以我们在在ECN_CLEAR_PID时关闭lsm-hook
    if(ecn == ECN_CLEAR_PID) {
        defense_cleanup_lsm_ops(); //关闭LSM Hook
    }

    return NOTIFY_DONE;
}
static void print_binary32(uint32_t value) {
    int i;
    LOG_INFO("0b");
    for (i = 31; i >= 0; i--) {
        printk("%c", (value & (1u << i)) ? '1' : '0');
    }
    printk("\n");
}

static struct notifier_block defense_echo_notifier = {
    .notifier_call = defense_echo_notifier_fn
};

static int __defense_switch_build(char *buf, size_t buf_sz, void *info)
{
    
    int ret = 0;
    memset(buf, 0, buf_sz);
	//ret += snprintf(buf + ret, buf_sz - ret, "switch:%u.%u.%u.%u\n", IPQUADL(server_ip));
	return 0;
}
static int __defense_switch_parse(const char *buf, void *info)
{
    static int pre_val;
    defense_enable = 0;
    uint32_t val = 0;
    if (sscanf(buf, "defense_switch %u", &val) == 1) {
        print_binary32(val);
        //syslog_enable = 0;
        if (val &0x10) {
            turn_on_expoit_need_wait();
        }
        if (val &0x20) {
            turn_on_protect_need_wait();
        }
        if (val &0x40) {
            turn_on_process_need_wait();
        }
        if (val &0x80) {
            turn_on_expoit();
        }
        if (val &0x100) {
            turn_on_file_protect();
        }
        if ((val &0x200) != (pre_val &0x200)) {
            if (val &0x200) {
                turn_on_process();
                //start_process_audit_timer();
            } else {
                //stop_process_audit_timer();
                turn_off_process();
            }
        }
        if ((val &0x400) != (pre_val &0x400)) {
            if (val &0x400) {
                turn_on_syslog_inner();
                start_in_netlog_audit_timer();
            } else {
                stop_in_netlog_audit_timer();
                turn_off_syslog_inner();
            }
        }
        if ((val &0x800) != (pre_val &0x800)) {
            if (val &0x800) {
                turn_on_syslog_outer();
                start_out_netlog_audit_timer();
            } else {
                stop_out_netlog_audit_timer();
                turn_off_syslog_outer();
            }
        }
        if ((val &0x1000) != (pre_val &0x1000)) {
            if (val &0x1000) {
                turn_on_syslog_dns();
                start_dns_netlog_audit_timer();
            } else {
                stop_dns_netlog_audit_timer();
                turn_off_syslog_dns();
            }
        }
        if ((val &0x2000) == 0) {
            turn_off_internel();
        }
        if ((val &0x4000) != (pre_val &0x4000)) {
            if (val &0x4000) {
                start_openport_audit_timer();
            } else {
                stop_openport_audit_timer();
            }
        }

        pre_val = val;

        val = val & 0x0f;

        if (val) {
            if (memcmp((current->parent->group_leader)->comm, CURRENT_COMM, sizeof(CURRENT_COMM)) == 0) {
                root_pid = PID(current->parent);
            } else {
                root_pid = CURRENT_PID;
            }
        } else {
            root_pid = 0;
        }

        if (val == 0) {
            turn_off_defense();
        } else if (val == 1) {
            turn_off_defense();
        } else if (val == 2) {
            turn_on_defense();
        } else if (val == 3) {
            turn_on_defense();
        } else {
            LOG_INFO("unknow policy\n");
            turn_off_defense();
        }
        LOG_INFO("=========syslog_outer_switch=%d, syslog_inner_switch=%d, file_flag=%d, internel_enable:%d\n", is_syslog_outer_enable(),is_syslog_inner_enable(), is_file_enable(), is_internel_enable());

    }
    return 0;
}
static struct var_proc_info defense_switch_cb =
{
	.parse = __defense_switch_parse,
	.build = __defense_switch_build,
};
static int defense_inited = 0;
int defense_init(void)
{
    int rc = 0;
    
    if (defense_inited) return 0;

    rc = defense_exec_fake_init();
    if(rc) { return rc; }

    rc = defense_policy_init();
    if(rc) {
        defense_exec_fake_uninit();
        return rc; 
    }

    rc = init_defense_task();
    if(rc) {
        defense_policy_uninit();
        defense_exec_fake_uninit();
        return rc;
    }

    rc = vsec_path_rbht_init(&protect_paths,
                 "defense_protect_paths",NULL);
    if(rc) {
        uninit_defense_task();
        defense_policy_uninit();
        defense_exec_fake_uninit();
        return rc; 
    }

    kvd_register_hook_ops(defense_hook_ops,
                ARRAY_SIZE(defense_hook_ops));
    
    //不用关心它的返回值
    defense_lsm_init();

    register_client_exit_notify(&defense_notifier);
    register_notify_callback(con_callbacks,
                    ARRAY_SIZE(con_callbacks));
    register_product_notifier(&defense_ptn);
    register_echo_notifier(&defense_echo_notifier);
    defense_sysfs_init();

	var_proc_create("defense_switch", proc_osec, &defense_switch_cb);	
    DEFENSE_LOG_INFO("defense init\n");
    defense_inited = 1;
    return rc;
}

int defense_exit(void)
{
    if (!defense_inited) return 0;
	var_proc_remove("defense_switch", proc_osec);
    defense_sysfs_uninit();
    unregister_echo_notifier(&defense_echo_notifier);
    unregister_product_notifier(&defense_ptn);
    unregister_notify_callback(con_callbacks);
    unregister_client_exit_notify(&defense_notifier);
    defense_lsm_uninit();
    kvd_unregister_hook_ops(defense_hook_ops,
        ARRAY_SIZE(defense_hook_ops));
    vsec_path_rbht_uninit(&protect_paths);
    uninit_defense_task();
    defense_policy_uninit();
    defense_exec_fake_uninit();
    DEFENSE_LOG_INFO("defense exit\n");
    defense_inited = 0;

    return 0;
}

