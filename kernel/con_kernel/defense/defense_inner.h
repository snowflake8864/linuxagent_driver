#ifndef DEFENSE_INNER_H
#define DEFENSE_INNER_H

#include "core/kvd_core.h"

extern u_long defense_debug;
int is_close_net_business(void);
#define DEFENSE_LOG_INFO     LOG_INFO
#define DEFENSE_LOG_ERROR    LOG_ERROR

#define DEFENSE_LOG_DEBUG(fmt, args...) {  \
            if(test_bit(0,&defense_debug)) { \
                printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args); \
            } else { LOG_DEBUG(fmt,##args); } }


void defense_do_debug(int bon);

int handle_cmd_add_white_exes(void* data,int size);
int defense_policy_init(void);
void defense_policy_uninit(void);

int get_defense_white_exes(char* buf,size_t len);
int get_defense_protect_paths(char* buf,size_t len);

int is_modify_open_flag(int flags);

int need_defense_skip(struct task_struct* task);
//int may_defense_task_kill(struct task_struct* task,
//                    int sig,pid_t spid);
int may_defense_task_ptrace(struct task_struct* task);
int may_defense_modify(const int action, const char* kpathname,
                    size_t len,int is_dir, int is_cut_kpathname);
void defense_task(int pid,bool enabled,bool bchild);

void cleanup_white_exes(void);
int is_current_white_exe(void);
int is_defense_white_exe(const char* exe,size_t len);

//bhold-->表是是否执行进程保护操作,如果不执行，
//则仅仅将相应进程加到受保护列表中,后续自保开关来时再进行保护
int hold_one_proc(struct task_struct* task,bool bhold);
int unhold_one_proc(struct task_struct* task);
void unhold_all_procs(void);
void hold_all_procs(void);
void cleanup_hold_procs(void);
ssize_t get_all_hold_procs(char* buf,size_t len);

int defense_exec_fake_init(void);
void defense_exec_fake_uninit(void);

int init_defense_task(void);
void uninit_defense_task(void);
int defense_tlv_proto_init(void);
void defense_tlv_proto_uninit(void);
int is_expoit_enable(void);
int is_file_enable(void);
int is_defense_enable(void);
void turn_off_defense(void);
void turn_on_defense(void);
int is_process_enable(void);
void turn_on_self(void);
void turn_off_self(void);
void proc_start_turn_off(void);
void syslog_turn_off(void);
int is_self_enable(void);
int is_syslog_enable(void);
int is_file_need_wait(void);
int is_process_need_wait(void);
int is_expoit_need_wait(void);
int is_file_protect_need_wait(void);
int is_syslog_inner_enable(void);
int is_syslog_outer_enable(void);
int is_syslog_dns_enable(void);
int is_proc_start_enable(void);
int process_audit_zero_copy_init(void);
int process_audit_zero_copy_exit(void);
void turn_on_internel(void);
void turn_off_internel(void);
int is_internel_enable(void);
void set_md5_load_status(void);
void clear_md5_load_status(void);
void start_in_netlog_audit_timer(void);
void stop_in_netlog_audit_timer(void);
void start_out_netlog_audit_timer(void);
void stop_out_netlog_audit_timer(void);
void start_dns_netlog_audit_timer(void);
void stop_dns_netlog_audit_timer(void);
void start_openport_audit_timer(void);
void stop_openport_audit_timer(void);
void start_process_audit_timer(void);
void stop_process_audit_timer(void);
void start_file_audit_timer(void);
void stop_file_audit_timer(void);

int is_enable_show_proc(void);
void turn_on_show_proc(void);
void turn_off_show_proc(void); 

int file_audit_filepath(const int action, pid_t pid, /*const*/ char * filepath, const size_t len, int is_dir, int is_cut_kpathname);
int file_audit_filepath_rename(const int action, pid_t pid, const char * filepath, const size_t len1, const char* filepathnew,const size_t len2,int is_dir);
//int exe_audit_filepath(const char* filename,  const uint32_t pathlen);
int exe_audit_filepath(const char* filename, const uint32_t pathlen);
int may_defense_modify_mv(const int action_type, const char * kpathname, const size_t len1, const char * kpathnamenew, const size_t len2,int is_dir);

#define NETLOG_AUDIT_TIMER_ON    (1 << 0)  // 第 0 位
#define OPENPORT_AUDIT_TIMER_ON  (1 << 1)  // 第 1 位
#define OUT_NETLOG_AUDIT_TIMER_ON (1 << 2) // 第 2 位
#define DNS_NETLOG_AUDIT_TIMER_ON (1 << 3) // 第 3 位
#define PROCESS_AUDIT_TIMER_ON (1 << 4)
#define FILE_AUDIT_TIMER_ON (1 << 5)


extern unsigned long timer_status;  // 初始值为 0，表示所有定时器都关闭
static inline void atomic_set_timer_status(int bit) {
    set_bit(bit, &timer_status);
}

static inline void atomic_clear_timer_status(int bit) {
    clear_bit(bit, &timer_status);
}

static inline bool atomic_is_timer_status_set(int bit) {
    return test_bit(bit, &timer_status);
}
// 测试并清除某一位（返回旧值）
static inline bool atomic_test_and_clear_timer_status(int bit) {
    return test_and_clear_bit(bit, &timer_status);
}
// 测试并设置某一位（返回旧值）
static inline bool atomic_test_and_set_timer_status(int bit) {
    return test_and_set_bit(bit, &timer_status);
}

void net_block_turn_on(void);
void net_block_turn_off(void);
#if 0
static inline void get_gfp_flag(void) 
{
    if (in_interrupt() || in_atomic()) {
        pr_info("Using GFP_ATOMIC, in_interrupt: %d, in_atomic: %d\n",
                in_interrupt(), in_atomic());
    } else {
        pr_info("Using GFP_KERNEL\n");
    }

}
#endif
#endif
