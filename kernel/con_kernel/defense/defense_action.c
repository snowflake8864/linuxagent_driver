#include <linux/types.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include "core/kvd_core.h"
#include "utils/utils.h"
#include "gnHead.h"
#include "core/gnkernel.h"
#include "defense_inner.h"
//#include "utils/pid_path.h"
#include "dpi/rules.h"
#include "dpi/pattern_tbl.h"
#include "process_audit/process_rules.h"
#include "docker_audit/docker_rules.h"
#include "core/zcopy.h"
#include "md5hash/md5hash.h"
#include "md5hash/md5_rules_tbl.h"
#include "dpi/true_process_tbl.h"
#include "process_audit/dpi_pattern_tbl.h"
#include "utils/exe_cmdline.h"
#include <linux/hardirq.h>
extern int _hook_lsm_on;
static uint8_t md5_in_load = 0;

void debug_print_av_process_info(const char *tag, struct av_process_info *info);
void set_md5_load_status(void)
{
    md5_in_load = 1;
}
void clear_md5_load_status(void)
{
    md5_in_load = 0;
}

const char* docker_process_array[] = {
    //"/usr/bin/containerd-shim-runc-v2",
    "/containerd-shim-runc-v",
    "containerd-shim",
    "/containerd",
    "bin/dockerd",
    "docker-runc-current",
    NULL
};

struct timer_list process_audit_timer;
struct timer_list file_audit_timer;

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
//        LOG_ERROR("ret=%d,path[%s]\n",ret, path);
        return -1;
    }
    // 获取绝对路径
    real_path = d_path(&path_struct, dbuffer, 512);
    if (real_path) {
        strncpy(buf, real_path, buflen);
        ret = 0;
    } else {
        ret = -1;
    }
    path_put(&path_struct);
    return ret;
}

static int get_process_executable_path(struct task_struct *tsk, char *buf, size_t buf_size) 
{
    int len = 0;
    //int _len = 0;
    char *exe_name;
    if (!tsk || !buf || buf_size <= 1) return -1;
    exe_name = kvd_get_task_pathname(tsk, &len);
    if (IS_ERR(exe_name)) {
        return -1;
    }
    //_len = (len + 1) > buf_size ? (buf_size -1):(len + 1);
    //snprintf(buf, _len, exe_name);
    len = len + 1 > buf_size ? buf_size - 1 : len;
    strncpy(buf, exe_name, len);
    buf[len] = '\0';

    kvd_put_pathname(exe_name);
    return 0;
}


static int file_does_not_exist(const char *path)
{
    struct path file_path;
    int err;

    // 调用 kern_path 进行路径解析
    err = kern_path(path, LOOKUP_FOLLOW, &file_path);
    if (err) {
        // 返回 -ENOENT 表示文件不存在
        if (err == -ENOENT) {
            return 1;  // 文件不存在
        }
        //return -1; // 其他错误
        return 1;
    }

    path_put(&file_path);  // 释放路径
    return 0;  // 文件存在
}



static  int check_binary_value(int value, int bit) {
    return  (value>>bit)&0x1;
}
#if 1
static inline int file_audit_kernel(const uint8_t type, const uint8_t need_wait, const uint8_t protect_rw, int action, pid_t pid, const char *process, const char * filepath, const char* filepathnew, int is_dir, int is_cut_kpathname)
{
    int nDeny = 0;
    int log_type = 0;
    int log_level = 0;
  //  LOG_INFO("===== process[%s], type[%d], action[%d],protect_rw[%x]--k[%x]\n", process, type, action, protect_rw);
    switch (type) {
        case LESOU_PROTECTION_TYPE:
            {
                int lesuo_match_vale = 0;

                if (need_wait == 0) {//监控
                    log_level = 2;
                    log_type = 3202;
                } else {
                    log_level = 3;
                    log_type = 3201;
                    nDeny = 1;
                }
                break;
            }
#if 0
        case TAMPER_PROTECTION_TYPE:
            {
                int flag_special = -1;
                int match_status = 0;

                log_level = 1;
                int exec_name_len = strlen(process);
                //LOG_INFO("kernel protect_rw[%x], app protect_rw[%x]\n", ppi->protect_rw, policy.protect_rw);
                switch(*(uint16_t *)(process + exec_name_len - 2)) //倒数第二个字符
                {
                    case 0x6d72: //may rm
                        {
                            if (strcmp(process + exec_name_len - 4, "n/rm") == 0) {

                                if (action == FILE_MODIFY|| action ==  FILE_REMOTE) {
                                    action = FILE_REMOTE;
                                    match_status = check_binary_value(protect_rw, 2);
                                }
                            }                    
                            break;
                        }


                    case 0x766d: //may mv
                        {
                            if (strcmp(process + exec_name_len - 4, "n/mv") == 0) {

                                if (action == FILE_MODIFY || action == FILE_CREATE || action == FILE_RENAME || action == FILE_OPEN) {
                                    action = FILE_RENAME;
                                    match_status = check_binary_value(protect_rw, 3);
                                }
                            }                    
                            break;
                        }

                    case 0x6863: //may touch
                        {
                            if (action == FILE_MODIFY || action == FILE_CREATE) {
                                if (strcmp(process + exec_name_len - 6, "/touch") == 0) {
                                    action = FILE_CREATE;
                                    match_status = check_binary_value(protect_rw, 4);
                                }                    
                            }
                            break;
                        }
                    case 0x7068: //may php 
                        {

                            if ((memcmp(process + exec_name_len - 4, "/php", 3) == 0)) {
                                if ((action == FILE_RENAME) && (check_binary_value(protect_rw, 4))) {
                                    action = FILE_CREATE;
                                    match_status = 1;
                                } else if ((action == FILE_MODIFY) && (check_binary_value(protect_rw, 4))) {
                                    match_status = 1;
                                    action = FILE_CREATE;
                                } else {
                                    match_status = 0;
                                }
                            }
                            break;
                        }
                    case 0x6873:
                        {
                            //echo
                            if ((memcmp(process + exec_name_len - 4, "bash", 4) == 0)) {
                                //LOG_INFO("=====[%s], action:%d, protect_rw:%x,is_cut_kpathname=%d\n", process + exec_name_len - 4, action, protect_rw, is_cut_kpathname);
                                if ((action == FILE_OPEN) && ((check_binary_value(protect_rw, 0)) || (check_binary_value(protect_rw, 4)))) {
                                    if (_hook_lsm_on == 1) {
                                        if (is_cut_kpathname == 1) {
                                            if (check_binary_value(protect_rw, 4)) {
                                                action = FILE_CREATE;
                                                strncpy(process,"/usr/bin/echo", 13);
                                                match_status = 1;
                                            } else {
                                                match_status =  0;
                                            }
                                        } else {
                                            if (check_binary_value(protect_rw, 0)) {
                                                strncpy(process,"/usr/bin/echo", 13);
                                                action = FILE_OPEN;
                                                match_status = 1;
                                            } else {
                                                match_status =  0;
                                            }
                                        }
                                    } else {
                                        if (file_does_not_exist(filepath) == 1) {
                                            if (check_binary_value(protect_rw, 4)) {
                                                action = FILE_CREATE;
                                                strncpy(process,"/usr/bin/echo", 13);
                                                match_status = 1;
                                            } else {
                                                match_status =  0;
                                            }
                                        } else {
                                            if (check_binary_value(protect_rw, 0)) {
                                                action = FILE_OPEN;
                                                strncpy(process,"/usr/bin/echo", 13);
                                                match_status = 1;
                                            } else {
                                                match_status =  0;
                                            }
                                        }

                                    }
                                } else if ( (action == FILE_MODIFY ) && ( (check_binary_value(protect_rw, 4)) || (check_binary_value(protect_rw, 1)) )) {
                                    strncpy(process,"/usr/bin/echo", 13);
                                    if (_hook_lsm_on == 1) {
                                        if (is_cut_kpathname == 1) {
                                            action = FILE_CREATE;
                                        } else {
                                            action = FILE_MODIFY;
                                        }
                                    } else {
                                        if (file_does_not_exist(filepath) == 1) {
                                            action = FILE_CREATE;
                                        } else {
                                            action = FILE_MODIFY;
                                        }

                                    }
                                    match_status = 1;
                                } else if (action == FILE_CREATE) {
                                    strncpy(process,"/usr/bin/echo", 13);
                                    match_status = check_binary_value(protect_rw, 4);
                                } else {
                                    match_status =  0;
                                //LOG_INFO("=====[%s], action:%d, protect_rw:%x,is_cut_kpathname=%d,match_status:%d,nDeny:%d\n", process + exec_name_len - 4, action, protect_rw, is_cut_kpathname, match_status,nDeny);
                                }
                            }
                            break;
                        }
                    default: 
                        {
                            //           LOG_INFO("tamper_protect_match===== rule idx:%d, comm[%s], type[%d], ppi->is_dir[%d]\n", ppi->rules_idx, ppi->comm, ppi->type, ppi->is_dir);
                            switch(action)
                            {
                                case  FILE_CREATE:
                                    {
                                        match_status = check_binary_value(protect_rw, 4);
                                        break;
                                    }
                                case FILE_REMOTE:
                                    {
                                        match_status = check_binary_value(protect_rw, 2);
                                        break;
                                    }
                                case FILE_MODIFY:
                                    {
                                        match_status = check_binary_value(protect_rw, 1);
                                        break;
                                    }
                                case FILE_RENAME:
                                    {
                                        match_status = check_binary_value(protect_rw, 3);
                                        break;
                                    }

                                case FILE_OPEN:
                                    {
                                        if (check_binary_value(protect_rw, 0)) {
                                            if (_hook_lsm_on == 1) {
                                                if (is_cut_kpathname == 1) {
                                                    if (check_binary_value(protect_rw, 4)) {
                                                        action = FILE_CREATE;
                                                        match_status = 1;
                                                    }
                                                } else {
                                                    action = FILE_OPEN;
                                                    match_status = 1;
                                                }
                                            } else {
                                                if (file_does_not_exist(filepath) == 1) {
                                                    if (check_binary_value(protect_rw, 4)) {
                                                        action = FILE_CREATE;
                                                        match_status = 1;
                                                    }
                                                } else {
                                                    action = FILE_OPEN;
                                                    match_status = 1;
                                                }

                                            }
                                        } else {
                                            match_status = 0;
                                        }

                                        break;
                                    }
                                default:
                                    match_status = 0;
                                    break; 

                            }
                            break;
                        }
                }
                log_level = 2;
                if (match_status == 0) {
                    return nDeny;
                }
                if (need_wait == 1) {
                    nDeny = 1; 
                    log_level = 3;       
                }
                break;
            }
#else
        case TAMPER_PROTECTION_TYPE:
            {
                int match_status = 0;
                size_t len = strnlen(process, PATH_MAX);
                if (unlikely(len < 2))  
                    break;

                const char *end = process + len;
                uint16_t tail2 = *(const uint16_t *)(end - 2); // 安全：已确保 len>=2

                //LOG_INFO("tamper_protect_match=====process:%s, action:%d, protect_rw:%x\n",process, action, protect_rw);
                switch (tail2) {
                    case 0x6D72: // "rm" (小端: 'r'=0x72, 'm'=0x6D)
                        if ((len == 2 || process[len - 3] == '/') &&
                                (action == FILE_MODIFY || action == FILE_REMOTE)) {
                            action = FILE_REMOTE;
                            match_status = check_binary_value(protect_rw, 2);
                        }
                        break;

                    case 0x766D: // "mv"
                        if ((len == 2 || process[len - 3] == '/') &&
                                (action == FILE_MODIFY || action == FILE_CREATE || 
                                 action == FILE_RENAME || action == FILE_OPEN)) {
                            action = FILE_RENAME;
                            match_status = check_binary_value(protect_rw, 3);
                        }
                        break;

                    case 0x6863: // "ch" → 可能是 "touch" 的尾部
                        if (len >= 5 && 
                                end[-5] == 't' && end[-4] == 'o' && end[-3] == 'u' && 
                                (len == 5 || process[len - 6] == '/') &&
                                (action == FILE_MODIFY || action == FILE_CREATE)) {
                            action = FILE_CREATE;
                            match_status = check_binary_value(protect_rw, 4);
                        }
                        break;

                    case 0x7068: // "hp" → "php"
                        if (len >= 3 && end[-3] == 'p' && // 完整 "php"
                                (len == 3 || process[len - 4] == '/') &&
                                (action == FILE_RENAME || action == FILE_MODIFY) &&
                                check_binary_value(protect_rw, 4)) {
                            action = FILE_CREATE;
                            match_status = 1;
                        }
                        break;

                    case 0x6873: // "sh" → 可能是 "bash"
                        if (len >= 4 && end[-4] == 'b' && end[-3] == 'a' && // 完整 "bash"
                                (len == 4 || process[len - 5] == '/')) {
                            // === 你的 bash 逻辑（保持不变）===
                            if (action == FILE_OPEN) {
                                int allow_open = check_binary_value(protect_rw, 0);
                                int allow_create = check_binary_value(protect_rw, 4);
                                if (allow_open || allow_create) {
                                    if (_hook_lsm_on == 1) {
                                        if (is_cut_kpathname == 1) {
                                            if (allow_create) {
                                                action = FILE_CREATE;
                                                memcpy(process, "/usr/bin/echo", 14);
                                                match_status = 1;
                                            }
                                        } else {
                                            if (allow_open) {
                                                action = FILE_OPEN;
                                                memcpy(process, "/usr/bin/echo", 14);
                                                match_status = 1;
                                            }
                                        }
                                    } else {
                                        if (file_does_not_exist(filepath)) {
                                            if (allow_create) {
                                                action = FILE_CREATE;
                                                memcpy(process, "/usr/bin/echo", 14);
                                                match_status = 1;
                                            }
                                        } else {
                                            if (allow_open) {
                                                action = FILE_OPEN;
                                                memcpy(process, "/usr/bin/echo", 14);
                                                match_status = 1;
                                            }
                                        }
                                    }
                                }
                            } else if (action == FILE_MODIFY) {
                                if (check_binary_value(protect_rw, 4) || check_binary_value(protect_rw, 1)) {
                                    memcpy(process, "/usr/bin/echo", 14);
                                    action = (_hook_lsm_on && is_cut_kpathname) || 
                                        (!_hook_lsm_on && file_does_not_exist(filepath)) ? 
                                        FILE_CREATE : FILE_MODIFY;
                                    match_status = 1;
                                }
                            } else if (action == FILE_CREATE) {
                                memcpy(process, "/usr/bin/echo", 14);
                                match_status = check_binary_value(protect_rw, 4);
                            }
                        }
                        break;
                    default: 
                        {
                            //LOG_INFO("tamper_protect_match===== action:%d, protect_rw:%x\n", action, protect_rw);
                            switch(action)
                            {
                                case  FILE_CREATE:
                                    {
                                        match_status = check_binary_value(protect_rw, 4);
                                        break;
                                    }
                                case FILE_REMOTE:
                                    {
                                        match_status = check_binary_value(protect_rw, 2);
                                        break;
                                    }
                                case FILE_MODIFY:
                                    {
                                        match_status = check_binary_value(protect_rw, 1);
                                        break;
                                    }
                                case FILE_RENAME:
                                    {
                                        match_status = check_binary_value(protect_rw, 3);
                                        break;
                                    }

                                case FILE_OPEN:
                                    {
                                        if (check_binary_value(protect_rw, 0)) {
                                            if (_hook_lsm_on == 1) {
                                                if (is_cut_kpathname == 1) {
                                                    if (check_binary_value(protect_rw, 4)) {
                                                        action = FILE_CREATE;
                                                        match_status = 1;
                                                    }
                                                } else {
                                                    action = FILE_OPEN;
                                                    match_status = 1;
                                                }
                                            } else {
                                                if (file_does_not_exist(filepath) == 1) {
                                                    if (check_binary_value(protect_rw, 4)) {
                                                        action = FILE_CREATE;
                                                        match_status = 1;
                                                    }
                                                } else {
                                                    action = FILE_OPEN;
                                                    match_status = 1;
                                                }

                                            }
                                        } else {
                                            match_status = 0;
                                        }

                                        break;
                                    }
                                default:
                                    match_status = 0;
                                    break; 

                            }
                            break;
                        }
                }

                log_level = 2;
                if (match_status == 0) {
                    return nDeny;
                }
                if (need_wait == 1) {
                    nDeny = 1; 
                    log_level = 3;       
                }
                break;
            }

#endif
        default:
            return nDeny;
    }

    if (likely(filepathnew == NULL)) {
#if 0
        struct av_file_audit_info *pi;
        pi = (struct av_file_audit_info*)kmalloc(sizeof(struct av_file_audit_info), GFP_KERNEL);
        if (pi) {
            memset(pi, 0, sizeof(*pi));
            pi->uid = CURRENT_UID;
            pi->pid = CURRENT_PID;
            pi->type = action;
            pi->log_level = log_level;
            pi->log_type = log_type;
            pi->is_dir = !!is_dir;
            //pi->is_file = (is_file == 3);
            pi->rules_type = type;
            strncpy(pi->path, filepath, sizeof(pi->path)-1);
            strncpy(pi->comm, process, sizeof(pi->comm) - 1);
            send_nowait_nl_data(NL_POLICY_AV_FILE_CHANGE_NOTIFY, pi, sizeof(struct av_file_audit_info));
            //LOG_INFO("file_audit_filepath filename:%s[%s],type:%d, nDeny:%d, protect_rw:%x,is_dir:%d\n",filepath,  pi->comm, action, nDeny, protect_rw,is_dir);
            kfree(pi);
        }
#else


        if (zero_copy_load_succeed & FILE_AUDIT_ENABLE) {
            struct av_file_info *pi;
            uint32_t idx = get_file_audit_data(&pi);
            memset(pi->path, 0, sizeof(pi->path));
            pi->uid = CURRENT_UID;
            pi->pid = CURRENT_PID;
            pi->log_type = log_type;
            pi->type = (action &0x7);
            pi->log_level = (log_level &0x7);
            pi->is_dir = !!is_dir;
            //pi->is_file = (is_file == 3);
            pi->rules_type = type;
            strncpy(pi->path, filepath, sizeof(pi->path)-1);
            strncpy(pi->comm, process, sizeof(pi->comm) - 1);
            //LOG_INFO("=========file audi flags:%d, rules_type:%d, log_level:%d,type:%d\n", pi->flags, pi->rules_type, pi->log_level,pi->type);
            struct netlink_netlog netlog_msg;
            if (idx >= file_audit_data_count - 1) {
                uint32_t prev_idx = 0;
                netlog_msg.max_idx = get_process_audit_idx(&prev_idx, &idx);
                netlog_msg.start_idx = prev_idx;
                netlog_msg.end_idx = file_audit_data_count - 1;
                //LOG_INFO("file audit idx=%d start idx:%d, end idx:%d......\n",idx, netlog_msg.start_idx, netlog_msg.end_idx);
                send_nl_data(NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
            }
        } else {

            struct av_file_audit_info pi;
            memset(&pi, 0, sizeof(pi));
            pi.uid = CURRENT_UID;
            pi.pid = CURRENT_PID;
            pi.type = action;
            pi.log_level = log_level;
            pi.log_type = log_type;
            pi.is_dir = !!is_dir;
            //pi->is_file = (is_file == 3);
            pi.rules_type = type;
            strncpy(pi.path, filepath, sizeof(pi.path)-1);
            strncpy(pi.comm, process, sizeof(pi.comm) - 1);
            send_nowait_nl_data(NL_POLICY_AV_FILE_CHANGE_NOTIFY, &pi, sizeof(struct av_file_audit_info));
        }
        //LOG_INFO("file_audit_filepath filename:%s[%s],type:%d, nDeny:%d, protect_rw:%x,is_dir:%d\n",filepath,  pi->comm, action, nDeny, protect_rw,is_dir);
#endif
    } else {

        if (zero_copy_load_succeed & FILE_AUDIT_ENABLE) {
            struct av_file_info *pi;
            uint32_t idx = get_file_audit_data(&pi);
            memset(pi->path, 0, sizeof(pi->path));
            pi->uid = CURRENT_UID;
            pi->pid = CURRENT_PID;
            pi->type = action;
            pi->log_level = log_level;
            pi->log_type = log_type;
            pi->is_dir = !!is_dir;
            //pi->is_file = (is_file == 3);
            pi->rules_type = type;
            strncpy(pi->path, filepath, sizeof(pi->path)-1);
            strncpy(pi->dst_path, filepathnew, sizeof(pi->dst_path)-1);
            strncpy(pi->comm, process, sizeof(pi->comm) - 1);
            struct netlink_netlog netlog_msg;
            if (idx >= file_audit_data_count - 1) {
                uint32_t prev_idx = 0;
                netlog_msg.max_idx = get_process_audit_idx(&prev_idx, &idx);
                netlog_msg.start_idx = prev_idx;
                netlog_msg.end_idx = file_audit_data_count - 1;
                //LOG_INFO("file audit idx=%d start idx:%d, end idx:%d......\n",idx, netlog_msg.start_idx, netlog_msg.end_idx);
                send_nl_data(NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
            }
        } else { 
            struct av_file_info *pi;
            pi = (struct av_file_info*)kmalloc(sizeof(struct av_file_info), GFP_KERNEL);
            if (pi) {
                memset(pi, 0, sizeof(*pi));
                pi->uid = CURRENT_UID;
                pi->pid = CURRENT_PID;
                pi->type = action;
                pi->log_level = log_level;
                pi->log_type = log_type;
                pi->is_dir = !!is_dir;
                //pi->is_file = (is_file == 3);
                pi->rules_type = type;
                strncpy(pi->path, filepath, sizeof(pi->path)-1);
                strncpy(pi->dst_path, filepathnew, sizeof(pi->dst_path)-1);
                strncpy(pi->comm, process, sizeof(pi->comm) - 1);
                send_nowait_nl_data(NL_POLICY_AV_FILE_RENAME_NOTIFY, pi, sizeof(struct av_file_info));
                //LOG_INFO("file_audit_filepath s_path:%s, d_path:%s type:%d, rules_type:%d, nDeny:%d, protect_rw:%x,is_dir:%d\n",pi->path, pi->dst_path, action, pi->rules_type, nDeny, protect_rw,is_dir);
                kfree(pi);
            }
        }

    }

    return nDeny;
}
#endif
#if 0
static inline int send_nl_data_to_user(const uint8_t type, const uint8_t need_wait, const int16_t rule_idx, const uint8_t protect_rw, /*const int is_file, */const int action, pid_t pid, const char * filepath, const char* filepathnew, int is_dir)
{
    int nDeny = 0;
    struct av_file_info *pi;
    pi = (struct av_file_info*)kmalloc(sizeof(struct av_file_info), GFP_KERNEL);
    if (pi) {
        memset(pi, 0, sizeof(*pi));
        pi->uid = CURRENT_UID;
        pi->pid = CURRENT_PID;
        pi->type = action;
        pi->is_dir = !!is_dir;
        //pi->is_file = (is_file == 3);
        pi->rules_type = type;
        pi->rules_idx = rule_idx;
        pi->protect_rw = protect_rw;
        strncpy(pi->path, filepath, sizeof(pi->path)-1);

        if (filepathnew != NULL) {
            strncpy(pi->dst_path, filepathnew, sizeof(pi->dst_path)-1);
        }

        get_process_path(CURRENT_PID, pi->comm, sizeof(pi->comm));
        if (need_wait) {
            pi->is_monitor_mode = 0;

            send_wait_nl_data(NL_POLICY_AV_FILE_CHANGE_NOTIFY, pi, sizeof(struct av_file_info), &pi->pwait_flag, &nDeny);
        } else {
            pi->is_monitor_mode = 1;
            send_nowait_nl_data(NL_POLICY_AV_FILE_CHANGE_NOTIFY, pi, sizeof(struct av_file_info));
        }
        LOG_INFO("file_audit_filepath filename:%s,type:%d, nDeny:%d, protect_rw:%x,is_dir:%d\n",filepath,  action, nDeny, protect_rw,is_dir);
        kfree(pi);
    }
    return nDeny;
}
#endif
#if 0
static inline int send_self_protect_data_to_user(const int action, pid_t pid, const char * filepath, const char* filepathnew)
{
    int nDeny = 0;
    struct av_self_protection_info *pi = (struct av_self_protection_info*)kmalloc(sizeof(struct av_self_protection_info), GFP_KERNEL);
    if (pi) {
        memset(pi, 0, sizeof(*pi));
        pi->uid = CURRENT_UID;
        pi->pid = CURRENT_PID;
        strncpy(pi->path, filepath, sizeof(pi->path)-1);

        //LOG_INFO("send_self_protect_data_to_user\n");
        if (filepathnew != NULL) {
            strncpy(pi->dst_path, filepathnew, sizeof(pi->dst_path)-1);
        }
#if 1 //zebra
        if (unlikely(get_process_path(CURRENT_PID, pi->comm, sizeof(pi->comm)) == -1)) {
            kfree(pi);
            return 0;
        }
#else
        strncpy(pi->comm, CURRENT_COMM_P, sizeof(pi->comm));
#endif
        switch(action) {
            case FILE_CREATE:
            {
                pi->type = 4700;
                break;
            }
            case FILE_MODIFY:
            {
                pi->type = 4702;
                break;
            }
            case FILE_RENAME:
            {
                pi->type = 4703;
                break;
            }
            case FILE_REMOTE:
            {
                pi->type = 4704;
                break;
            }
            default:
                pi->type = 4701;
                break;
        }
        send_nowait_nl_data(NL_POLICY_AV_SELF_PROTECTION_NOTIFY, pi, sizeof(struct av_self_protection_info));
        kfree(pi);
    }
    return nDeny;
}
#else

static inline int send_self_protect_data_to_user(
    const int action,
    pid_t pid,
    const char *filepath,
    const char *filepathnew,
    int which_path)
{
    int nDeny = 0;
    struct av_self_protection_info pi;
    memset(&pi, 0, sizeof(pi));

    pi.uid = CURRENT_UID;
    pi.pid = CURRENT_PID;

    if (!in_interrupt() && current->mm != NULL) {
        if (unlikely(get_process_executable_path(current, pi.comm,
                        sizeof(pi.comm) - 1) == -1)) {
            strncpy(pi.comm, CURRENT_COMM, sizeof(pi.comm) - 1);
        }
    } else {
        return 0;
    }

    const char *src_path = NULL;

    if (which_path == 0) {
        src_path = filepath;
    } else {
        src_path = filepathnew;
    }

    if (src_path && src_path[0] != '\0') {
        strncpy(pi.path, src_path, sizeof(pi.path) - 1);
    } else {
        strncpy(pi.path, pi.comm, sizeof(pi.path) - 1);
    }

    //LOG_INFO("self protect:%s\n",pi.path);
    switch (action) {
        case FILE_CREATE: pi.type = 4700; break;
        case FILE_MODIFY: pi.type = 4702; break;
        case FILE_RENAME: pi.type = 4703; break;
        case FILE_REMOTE: pi.type = 4704; break;
        default:          pi.type = 4701; break;
    }

    send_nowait_nl_data(
        NL_POLICY_AV_SELF_PROTECTION_NOTIFY,
        &pi,
        sizeof(struct av_self_protection_info));

    return nDeny;
}


#endif
int file_audit_filepath(const int action, pid_t pid, /*const*/ char * filepath, const size_t len, int is_dir, int is_cut_kpathname)
{


    int i;
    int retv = -1;
    if (unlikely(G_state_id_inc <= 1)) {
        return 0;
    }
    //LOG_INFO("in file_audit_filepath\n");
    if (unlikely(get_docker_pid_state(CURRENT_PPID) != 0)) {
        int _ppid = CURRENT_PPID;
        //LOG_INFO("is docker process pid:%d,ppid:%d\n",pid, _ppid);
        return 0;
    }

    if(is_self_process()) {
        return 0;
    }

    int haven_get_process_path = 0;
    char current_process_path[512];
    uint8_t process_md5[16];
    int rules_info = 0;
    dpi_result_t result ;
    memset(&result, 0, sizeof(dpi_result_t));
    result.is_dir = is_dir;
    result.is_cut_kpathname = is_cut_kpathname;
    if (_hook_lsm_on == 1) {
        if (*(uint16_t *)CURRENT_COMM == 0x766d)
        result.opt = 4;
        else
        result.opt = action;
    }

    if (file_acsmSearch3(filepath, len, &result) == -1) {
        return 0;
    }

    //LOG_INFO("file_audit_filepath  current[%s].pid:%d, action:%d, filepath:%s, is_dir[%d], is_cut_kpathname=%d\n", CURRENT_COMM, pid, action, filepath, is_dir, is_cut_kpathname);
    int nDeny = 0;
    
    if (unlikely(is_cut_kpathname == 1)) {
        filepath[len] = 0;
    }
    for (i = 0; i < 5 && i < result.cnt; i ++) {

        //LOG_INFO("file_audit_filepath i:%d, result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s,is_cut_kpathname:%d\n",i, result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath,is_cut_kpathname);
        switch(result.type[i]) {
            case 3:
                if (is_self_enable()) {
                    //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                    if (action == FILE_OPEN) {
                        //if (unlikely(strlen(CURRENT_COMM) == 2 && strncmp(CURRENT_COMM, "cp", 2) == 0)) 
                        switch(*(uint16_t *)CURRENT_COMM )
                        {
                            case 0x7063:
                                send_self_protect_data_to_user(FILE_CREATE,  pid, filepath, NULL, 0);
                                return 1;
                            case 0x766d:
                                send_self_protect_data_to_user(FILE_REMOTE,  pid, filepath, NULL, 0);
                                return 1;
                            default:
                                break;
                        }
                        //LOG_INFO("file_audit_filepath retv:%d, current[%s].pid:%d,  action:%d, filepath:%s\n",retv, CURRENT_COMM, pid, action, filepath);
                        return 0;
                    } else {
                        send_self_protect_data_to_user(action,  pid, filepath, NULL, 0);
                        return 1;
                    }
                }
                break;
            case 2://protect
            {
                if (!is_defense_enable()) {
                    break;
                    //return nDeny;
                }

#if 0
                   if (result.action[i] == 1) {
                       continue;
                } else if (result.action[i] == 2) {
                    return 1;
                }
#else
                switch(result.action[i]) {
                    case 0:
                    case 3:
                        {
                            break;
                        }
                    case 1:
                    case 2:
                        {
                            goto break_protect;
                        }
                }

#endif
                if (haven_get_process_path == 0) {
                    haven_get_process_path = 1;
                    if (!in_interrupt() && current->mm != NULL) {
                        if (unlikely(get_process_executable_path(current, current_process_path, sizeof(current_process_path) - 1) == -1)) {
                            strncpy(current_process_path, CURRENT_COMM, sizeof(current_process_path) -1);
                        } 
                    } else {
                        return 0;
                    }

                }
                if (result.tpnc[i] > 0) {

                    if (likely(get_process_md5(current_process_path, process_md5) == 0)) {

                        //return nDeny;
                        if(find_true_process(process_md5, result.tpnc[i], 88)) {
                            //LOG_INFO("%s[%*phN] hit true process\n", current_process_path, 16, process_md5);
                            break;
                            //return nDeny;
                        }
                    } else {
                        md5_rule_entry_t mre;
                        if (md5_calculate_file(current_process_path, mre.md5) != 0) {
                            return 0;
                        }
                        mre.type =  find_md5_action(mre.md5); 
                        //LOG_INFO("==[%s], type:%d, md5[%*phN]\n",current_process_path, mre.type, 16, mre.md5);
                        add_or_update_audit_process_info(current_process_path, mre.md5, mre.type); 

                        //return nDeny;
                        if(find_true_process(mre.md5, result.tpnc[i], 88)) {
                            //LOG_INFO("%s[%*phN] hit true process\n", current_process_path, 16, mre.md5);
                            break;
                            //return nDeny;
                        }

                    }
                }

                //nDeny += send_nl_data_to_user(2, is_file_protect_need_wait(), result.rule_idx[i], result.protect_rw[i],  action, pid, filepath,NULL, is_dir);
                nDeny += file_audit_kernel(2, is_file_protect_need_wait(), result.protect_rw[i], action, pid, current_process_path, filepath, NULL, is_dir,is_cut_kpathname);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s,wait=%d,is_dir=%d, is_cut_kpathname:%d, protect_rw:%x,nDeny=%d\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath, is_file_protect_need_wait(), is_dir, is_cut_kpathname, result.protect_rw[i], nDeny);
              break_protect:
                break;
            }
            case 1://lesuo
            {
                if (!is_defense_enable()) {
                    break;
                    //return nDeny;
                }
#if 0                
                if (result.action[i] == 1) {
                    continue;
                } else if (result.action[i] == 2) {
                    return 1;
                }
#endif
                if (haven_get_process_path == 0) {
                    haven_get_process_path = 1;

                    if (!in_interrupt() && current->mm != NULL) {
                        if (unlikely(get_process_executable_path(current, current_process_path, sizeof(current_process_path) - 1) == -1)) {
                            strncpy(current_process_path, CURRENT_COMM, sizeof(current_process_path) - 1);
                        }
                    } else {
                        return 0;
                    }


                }

                if (result.tpnc[i] > 0) {
                    int _retv = get_process_md5(current_process_path, process_md5);
                    if (likely(_retv == 0)) {
                        if(find_true_process(process_md5, result.tpnc[i], 99)) {
                            //LOG_INFO("%s[%*phN] hit true process\n", current_process_path, 16, process_md5);
                            break;
                            //return nDeny;
                        }
                    } else if (_retv == 1){

                        return 0;
                    }
                }


                //nDeny += send_nl_data_to_user(1, is_expoit_need_wait(), result.rule_idx[i], result.protect_rw[i],  action, pid, filepath, NULL, is_dir);
                nDeny += file_audit_kernel(1, is_expoit_need_wait(), result.protect_rw[i], action, pid, current_process_path, filepath, NULL, is_dir,is_cut_kpathname);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s, wait=%d\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath, is_expoit_need_wait());

                break;
            }
            case 0:
            default:
                return 0;
        }
    }

    return !!nDeny;
}

int file_audit_filepath_rename(const int action, pid_t pid, const char * filepath, const size_t len1, const char* filepathnew, const size_t len2, int is_dir)
{

    struct av_file_info *pi;
    int i = 0;
    int retv = 0;
    char current_process_path[512];

    if (unlikely(G_state_id_inc <= 1)) {
        return 0;
    }
    if(is_self_process()) {
        return 0;
    }
    int haven_get_process_path = 0;
    int rules_info = 0;
    uint8_t process_md5[16];
    dpi_result_t result;
    memset(&result, 0, sizeof(dpi_result_t));
    result.is_dir = is_dir;
    result.opt = 4;
    //LOG_INFO("file_audit_filepath  current[%s].pid:%d, action:%d, filepath:%s, filepathnew:%s is_dir[%d]\n", CURRENT_COMM, pid, action, filepath, filepathnew, is_dir);

    if (file_acsmSearch3(filepath, len1, &result) == -1) {
        return 0;
    }


    //LOG_INFO("file_audit_filepath  current[%s].pid:%d, action:%d, filepath:%s, filepathnew:%s is_dir[%d]\n", CURRENT_COMM, pid, action, filepath, filepathnew, is_dir);
    int nDeny = 0;
    for (i = 0; i < 5 && i < result.cnt; i ++) {
//        LOG_INFO("===result.type:%d====\n", result.type[i]); 
        switch(result.type[i]) {
            case 3:
                if (unlikely(!is_self_enable())) {
                    return nDeny;
                }
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                if (action != FILE_OPEN) {
                    send_self_protect_data_to_user(action,  pid, filepath, filepathnew, 0);
                    return 1;
                }
                break;
            case 2://protect
                {
                    if (unlikely(!is_defense_enable())) {
                        return nDeny;
                    }

#if 0
                    if (result.action[i] == 1) {
                        continue;
                    } else if (result.action[i] == 2) {
                        return 1;
                    }
#else
                    switch(result.action[i]) {
                        case 0:
                        case 3:
                            {
                                break;
                            }
                        case 1:
                        case 2:
                            {
                                goto lesuo_continue;
                            }
                    }

#endif
                    if (haven_get_process_path == 0) {
                        haven_get_process_path = 1;

                        if (!in_interrupt() && current->mm != NULL) {
                            if (unlikely(get_process_executable_path(current, current_process_path, sizeof(current_process_path) - 1) == -1)) {
                                strncpy(current_process_path, CURRENT_COMM, sizeof(current_process_path) - 1);
                            }
                        } else {
                            return 0;
                        }
                    }

                    if (result.tpnc[i] > 0) {
                        if (likely(get_process_md5(current_process_path, process_md5) == 0)) {
                            if(find_true_process(process_md5, result.tpnc[i], 88)) {
                                //LOG_INFO("%s[%*phN] hit true process\n", current_process_path, 16, process_md5);
                                //break;
                                //return nDeny;
                                goto lesuo_continue;
                            }
                        }
                    }
                    //nDeny += send_nl_data_to_user(2, is_file_protect_need_wait(), result.rule_idx[i], result.protect_rw[i], action, pid, filepath, filepathnew, is_dir);
                    nDeny += file_audit_kernel(2, is_file_protect_need_wait(), result.protect_rw[i], action, pid, current_process_path, filepath, filepathnew, is_dir, 0);
                    //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",\
                    result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                    goto lesuo_continue;
//continue_protect_1:
                    continue;
                }
            case 1://lesuo
            {
                if (unlikely(!is_defense_enable())) {
                    return nDeny;
                }

#if 0                
                if (result.action[i] == 1) {
                    continue;
                } else if (result.action[i] == 2) {
                    return 1;
                }
#endif
                if (haven_get_process_path == 0) {
                    haven_get_process_path = 1;

                    if (!in_interrupt() && current->mm != NULL) {
                        if (unlikely(get_process_executable_path(current, current_process_path, sizeof(current_process_path) - 1) == -1)) {
                            strncpy(current_process_path, CURRENT_COMM, sizeof(current_process_path) - 1);
                        } 
                    } else {
                        return 0;
                    }


                }
                if (result.tpnc[i] > 0) {
                    if (likely(get_process_md5(current_process_path, process_md5) == 0)) {
                        if(find_true_process(process_md5, result.tpnc[i], 99)) {
                            //LOG_INFO("%s[%*phN] hit true process\n", current_process_path, 16, process_md5);
                            //break;
                            //return nDeny;
                            goto lesuo_continue;
                        }
                    }
                }
                //nDeny += send_nl_data_to_user(1, is_expoit_need_wait(), result.rule_idx[i], result.protect_rw[i],  action, pid, filepath,filepathnew,is_dir);
                nDeny += file_audit_kernel(1, is_expoit_need_wait(), result.protect_rw[i], action, pid, current_process_path, filepath, filepathnew, is_dir, 0);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                goto lesuo_continue;
            }
            case 0:
            default:
                break;
        }
lesuo_continue:
     continue;

    }

    memset(&result, 0, sizeof(dpi_result_t));
    result.is_dir = is_dir;
    result.opt = 4;
    if (file_acsmSearch3(filepathnew, len2, &result) == -1) {
        return 0;
    }
    //nDeny = 0;

    for (i = 0; i < 5 && i < result.cnt; i ++) {
        switch(result.type[i]) {
            case 3:
                if (unlikely(!is_self_enable())) {
                    return nDeny;
                }
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                if (action != FILE_OPEN) {
                    send_self_protect_data_to_user(action,  pid, filepath, filepathnew, 1);
                    return 1;
                }
                break;
            case 2://protect
            {
                if (unlikely(!is_defense_enable())) {
                    return nDeny;
                }

#if 0
                    if (result.action[i] == 1) {
                        continue;
                    } else if (result.action[i] == 2) {
                        return 1;
                    }
#else
                    switch(result.action[i]) {
                        case 0:
                        case 3:
                            {
                                break;
                            }
                        case 1:
                        case 2:
                            {
                                goto break_protect_2;
                            }
                    }

#endif
                    
                    if (haven_get_process_path == 0) {
                        haven_get_process_path = 1;
                        if (!in_interrupt() && current->mm != NULL) {
                            if (unlikely(get_process_executable_path(current, current_process_path, sizeof(current_process_path) - 1) == -1)) {
                                strncpy(current_process_path, CURRENT_COMM, sizeof(current_process_path) - 1);
                            }
                        } else {
                            return 0;
                        }

                    }
                    if (result.tpnc[i] > 0) {
                        struct process_audit_info * a_rule =  get_process_audit_info(current_process_path); 
                        if (unlikely(a_rule == NULL)) {
                            break;
                            //return nDeny;
                        }
                        if(find_true_process(a_rule->md5, result.tpnc[i], 88)) {
                            //LOG_INFO("%s[%*phN] hit true process\n", current_process_path, 16, a_rule->md5);
                            //return nDeny;
                            break;
                        }
                    }

                //nDeny += send_nl_data_to_user(2, is_file_protect_need_wait(), result.rule_idx[i], result.protect_rw[i], action, pid, filepath, filepathnew, is_dir);
                //nDeny += file_audit_kernel(2, is_file_protect_need_wait(), result.protect_rw[i], action, pid, current_process_path, filepath, filepathnew, is_dir, 0);
                nDeny += file_audit_kernel(2, is_file_protect_need_wait(), result.protect_rw[i], action, pid, current_process_path, filepathnew, filepath, is_dir, 0);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s][%s].pid:%d, type:%d action:%d, filepath:%s\n",\
                result.cnt, CURRENT_COMM, current_process_path, pid, result.type[i], action, filepath);
break_protect_2:
                break;
            }
            case 1://lesuo
            {
                if (unlikely(!is_defense_enable())) {
                    return nDeny;
                }
#if 0                
                if (result.action[i] == 1) {
                    continue;
                } else if (result.action[i] == 2) {
                    return 1;
                }
#endif                
                    if (haven_get_process_path == 0) {
                        haven_get_process_path = 1;

                        if (!in_interrupt() && current->mm != NULL) {
                            if (unlikely(get_process_executable_path(current, current_process_path, sizeof(current_process_path) - 1) == -1)) {
                                strncpy(current_process_path, CURRENT_COMM, sizeof(current_process_path) - 1);
                            }
                        } else {
                            return 0;
                        }
                    }
                    if (result.tpnc[i] > 0) {
                        struct process_audit_info * a_rule =  get_process_audit_info(current_process_path); 
                        if (unlikely(a_rule == NULL)) {
                            break;
                            //return nDeny;
                        }
                        if(find_true_process(a_rule->md5, result.tpnc[i], 88)) {
                           // LOG_INFO("%s[%*phN] hit true process\n", current_process_path, 16, a_rule->md5);
                            //return nDeny;
                            break;
                        }
                    }


                //nDeny += send_nl_data_to_user(1, is_expoit_need_wait(), result.rule_idx[i], result.protect_rw[i],  action, pid, filepath,filepathnew,is_dir);
                //nDeny += file_audit_kernel(1, is_expoit_need_wait(), result.protect_rw[i], action, pid, current_process_path, filepath, filepathnew, is_dir, 0);
                nDeny += file_audit_kernel(1, is_expoit_need_wait(), result.protect_rw[i], action, pid, current_process_path, filepathnew, filepath, is_dir, 0);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);

                break;
            }
            case 0:
            default:
                return 0;
        }
    }

out:

    return nDeny;
}


const char* filter_process_array[] = {
    //"/usr/bin/sudo",
    "bin/sudo",
    //"/usr/lib/command-not-found",
    "/lib/command-not-found",
    "systemd-cgroups-agent",
    "/root/software/str/bin/",
    "/home/user/software/str/bin/",
    "/opt/osec/MagicArmor_cli",
    "/opt/osec/MagicArmor_0",
    //"/software/str/bin/",
    NULL
};


#if 0
//系统白名单过滤
const char* G_SYS_PROCEE_FILTER[] = {
    "/usr/bin/dbus-daemon",
    "/sbin/init",
    "/usr/sbin/NetworkManager",
    "/usr/sbin/lightdm",
    "/usr/sbin/alsactl",
    "/lib/systemd/systemd-journald",
    "/lib/systemd/systemd-udevd",
    "/lib/systemd/systemd-timesyncd",
    "/lib/systemd/systemd-logind",
    "/usr/lib/accountsservice/accounts-daemon",
    "/usr/lib/xorg/Xorg",
    "/usr/lib/policykit-1/polkitd",
    "/lib/systemd/systemd",
    "/usr/sbin/rsyslogd",
    "/bin/login",
    "/usr/bin/du",
    "/bin/dash",
    "/bin/run-parts",
    "/sbin/dhclient-script",
    "/usr/bin/sort",
    "/usr/bin/sudo",
    "/usr/bin/apt-get",
    "/usr/sbin/dpkg-preconfigure",
    "/usr/bin/dpkg-split",
    "/usr/bin/apt-extracttemplates",
    "/bin/stty",
    "/sbin/lsmod",
    "/sbin/rmmod",
    "/usr/bin/unzip",
//    "/usr/bin/dpkg",
//    "/usr/bin/rpm",
    "/usr/sbin/reboot",
    "/sbin/reboot",
    "/usr/bin/systemctl",
    "/usr/sbin/service",
    "/shutdown",
    "/halt",
    "/poweroff",
    "/systemd",
    "lsof",
    "awk",
    NULL
};
#else
const char* G_SYS_PROCEE_FILTER[] = {
    "/bin/dbus-daemon",
    "/sbin/init",
    "/sbin/NetworkManager",
    "/sbin/lightdm",
    "/sbin/alsactl",
    "/lib/systemd/systemd-journald",
    "/lib/systemd/systemd-udevd",
    "/lib/systemd/systemd-timesyncd",
    "/lib/systemd/systemd-logind",
    "/usr/lib/accountsservice/accounts-daemon",
    "/usr/lib/xorg/Xorg",
    "/usr/lib/policykit-1/polkitd",
    "/lib/systemd/systemd",
    "/usr/sbin/rsyslogd",
    "/bin/login",
    "bin/du",
    "bin/dash",
    "/bin/run-parts",
    "/sbin/dhclient-script",
    "bin/sort",
    "bin/sudo",
    "bin/apt-get",
    "bin/dpkg-preconfigure",
    "bin/dpkg-split",
    "bin/apt-extracttemplates",
    "bin/stty",
    "bin/lsmod",
    "bin/rmmod",
    "bin/unzip",
//    "/usr/bin/dpkg",
//    "/usr/bin/rpm",
    "bin/reboot",
    "/usr/bin/systemctl",
    "/usr/sbin/service",
    "/shutdown",
    "/halt",
    "/poweroff",
    "/systemd",
    "lsof",
    "awk",
    NULL
};
#endif


static uint8_t check_docker_pid(void)
{
    struct task_struct *task = current;
    uint8_t state = 0;

    while (task->parent && task->parent != task) {
        if (PID(task->parent) == 1) {
            return is_docker_pid(PID(task));
        }

        if (unlikely((state = is_docker_pid(PID(task))) != 0)) {
            return state;
        }
        task = task->parent; // 继续向上遍历
    }

    return state; 
}

static uint8_t check_root_docker_pid(void)
{
    struct task_struct *task = current;
    uint8_t state = 0;

    while (task->parent && task->parent != task) {
        if (PID(task->parent) == 1) {
            return is_docker_root_process(PID(task));
        }

        if (unlikely((state = is_docker_root_process(PID(task))) != 0)) {
            return state;
        }
        task = task->parent; // 继续向上遍历
    }

    return state; 
}

#if 0
#include <linux/delay.h> 
#include <linux/signal.h>
static int kill_process_by_pid(pid_t pid) {
    struct pid *pid_struct;
    struct task_struct *task;
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        LOG_ERROR("Invalid PID\n");
        return -ESRCH; // 错误：找不到 PID
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        LOG_ERROR("No such process with PID %d\n", pid);
        return -ESRCH;
    }

    // 发送 SIGKILL 信号来杀死进程
    pr_info("Killing process with PID %d\n", pid);
    send_sig(SIGKILL, task, 1); // 发送 SIGKILL 信号

    return 0;
}
#endif

int exe_audit_filepath(const char* filename, const uint32_t pathlen)
{
    int nDeny = 0;
    int i = 0;
    int action = 0;
    int sys_true_process = 0;
    if (unlikely(Process_G_state_id_inc <= 1)) {
        return 0;
    }

    if(is_self_process()) {
        return 0;
    }

    process_dpi_result_t result ;
    memset(&result, 0, sizeof(process_dpi_result_t));
    if (process_acsmSearch3(filename, pathlen, &result) == -1) {
        return 0;
    }
    //nDeny = 0;
    if (result.cnt >= 1) {
        switch(result.type[0]) {
            case 0:
            {
                //LOG_INFO("0---exe_audit_filepath process[%s] add pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
                return 0;
            }
            case 1:
                //LOG_INFO("1----exe_audit_filepath process[%s] add pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
                sys_true_process = 1;
                break;
            default:
            break;
            
        }
    }

    //LOG_INFO("exe_audit_filepath process[%s] add pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
    uint32_t pid = CURRENT_PID;
    uint32_t ppid = CURRENT_PPID;
    if (pathlen > 8) {
        switch(*(uint64_t *)(filename + pathlen - 8)) { //倒数第二个字符
            case 0x32762d636e75722d: //containerd-shim-runc-v2
            case 0x31762d636e75722d: //containerd-shim-runc-v1
                {

                    if (strstr(filename, docker_process_array[0])) { 
                        if (is_docker_root_process(ppid) == 0) {
                            set_docker_version(2);
                            set_docker_pid(pid);
                            //LOG_INFO("00===docker version %d process[%s] add pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", get_docker_version(), filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
                        } else { 
                            com_info_t com_info;
                            com_info.pid = pid;
                            com_info.ppid = ppid;
                            com_info.type = 1; //maybe delete docker pid
                            com_info.version = 2;
                            //LOG_INFO("11===docker version %d=process[%s] pid:%d,ppid:%d,type:%d,p_comm[%s],comm[%s]\n",get_docker_version(), filename, com_info.pid, com_info.ppid, com_info.type, CURRENT_COMM_P,CURRENT_COMM);
                            send_nowait_nl_data(NL_POLICY_INFO_KERN_TO_APP_NOTIFY, &com_info, sizeof(com_info_t));
                        }
                        return 0;
                    }

                    break;
                }
            case 0x6d6968732d647265: //containerd-shim 65 7264 2d73 6869 6d
                {

                    if (strstr(filename, docker_process_array[1])) { 
                        if (is_docker_root_process(ppid) == 1) {
                            set_docker_pid(pid);
                            set_docker_version(1);
                            start_docker_v1();
                            //LOG_INFO("00===docker version %d process[%s] add pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", get_docker_version(), filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
                        } else { 
                            com_info_t com_info;
                            com_info.type = 1;
                            com_info.pid = pid;
                            com_info.ppid = ppid;
                            com_info.version = 1;
                            //LOG_INFO("11===docker version %d=process[%s] pid:%d,ppid:%d,type:%d,p_comm[%s],comm[%s]\n",get_docker_version(), filename, com_info.pid, com_info.ppid, com_info.type, CURRENT_COMM_P,CURRENT_COMM);
                            send_nowait_nl_data(NL_POLICY_INFO_KERN_TO_APP_NOTIFY, &com_info, sizeof(com_info_t));
                        }
                        return 0;
                    }

                    break;
                }
            case 0x746e65727275632d:   //2d 6375 7272 656e 74
                {
                    if (strstr(filename, docker_process_array[4])) { 
                        if (is_docker_root_process(ppid) == 0) {
                            com_info_t com_info;
                            com_info.type = 1;
                            com_info.pid = pid;
                            com_info.ppid = ppid;
                            com_info.version = 1;
                            //LOG_INFO("11===docker version %d=process[%s] pid:%d,ppid:%d,type:%d,p_comm[%s],comm[%s]\n",get_docker_version(), filename, com_info.pid, com_info.ppid, com_info.type, CURRENT_COMM_P,CURRENT_COMM);
                            send_nowait_nl_data(NL_POLICY_INFO_KERN_TO_APP_NOTIFY, &com_info, sizeof(com_info_t));
                        }
                        return 0;
                    }

                    break;

                }
            //case 0x72656b636f642f6e:
            case 0x6c74637379732d64:
                {
                    //com_info_t com_info;
                    //com_info.type =0;
                    //com_info.pid = pid;
                    //com_info.ppid = ppid;
                    //LOG_INFO("===1process[%s] pid:%d,ppid:%d,type:%d,p_comm[%s],comm[%s]\n", filename, com_info.pid, com_info.ppid, com_info.type, CURRENT_COMM_P,CURRENT_COMM);
                    //send_nowait_nl_data(NL_POLICY_INFO_KERN_TO_APP_NOTIFY, &com_info, sizeof(com_info_t));
                    break;
                }

            case 0x6472656e6961746e:
                {
                    if (strlen(CURRENT_COMM_P) == 7 && strncmp(CURRENT_COMM_P, "systemd", 7) == 0) {
                        set_docker_root_pid(pid);
                        com_info_t com_info;
                        com_info.type = 3;
                        com_info.version = get_docker_version();
                        com_info.pid = pid;
                        com_info.ppid = ppid;
                        //LOG_INFO("===3process[%s] pid:%d,ppid:%d,type:%d,p_comm[%s],comm[%s]\n", filename, com_info.pid, com_info.ppid, com_info.type, CURRENT_COMM_P,CURRENT_COMM);
                        send_nowait_nl_data(NL_POLICY_INFO_KERN_TO_APP_NOTIFY, &com_info, sizeof(com_info_t));
                    }
                    //send_nowait_nl_data(NL_POLICY_INFO_KERN_TO_APP_NOTIFY, &com_info, sizeof(com_info_t));
                    return 0;
                }
            case 0x6472656b636f642f:
                if (ppid == 1) {
                    //clear_all_docker_pids();
                    //LOG_INFO("===clear all docker process[%s] pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
                }
                return 0;
            case 0x746e656761797474: //ttyagent
                if (strlen(CURRENT_COMM) == 6 && strncmp(CURRENT_COMM, "reboot", 6) ==0) {
                    turn_off_self();
                    proc_start_turn_off();
                    syslog_turn_off();
                    //LOG_INFO("===reboot system [%s] pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
                }
                //msleep(1000);
                //LOG_INFO("===reboot system [%s] pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
                //close_net_business = 1;
                break;
            case 0x746f6f6265722f6e:
                    turn_off_self();
                    proc_start_turn_off();
                    syslog_turn_off();
                    //LOG_INFO("===reboot system [%s] pid:%d,ppid:%d,p_comm[%s],comm[%s]\n", filename,CURRENT_PID, CURRENT_PPID, CURRENT_COMM_P,CURRENT_COMM);
                    break;
            case 0x687361622f6e6962: // bin/bash
            case 0x6e6f687479702f6e: // n/python
            case 0x336e6f687479702f: // /python3
            case 0x6c74636d65747379: // ystemctl
            default:
                break;
        }

    } else if (pathlen == 6 && (strncmp(filename, "/check", 6) == 0 || strncmp(filename, "/pause", 6) == 0)) {
        return 0;
    } else if (pathlen == 1) { //奇怪的进程，目前出现过一个 /， 不知道什么情况
        return 0;
    }


    if (unlikely(md5_in_load == 1)) {
        return 0;
    }
    int is_docker_process = 0;
    switch(get_docker_version()) {
        case 1:
        {
            if (is_start_docker_v1() == 1) 
            {
                //LOG_INFO("version 1 docker is enable[%s]\n");
                if (unlikely(check_root_docker_pid() != 0)) {
                    //uint8_t md5[16];
                    //md5_calculate_file(filename, md5);
                    //LOG_INFO("is docker process[%s] , pid:%d,ppid:%d\n", filename,  pid, ppid);
                    is_docker_process = 1;
                }
            }
            break;
        }
        case 2:
        {
            if (is_start_docker() == 1) {
               // LOG_INFO("version 2 docker is enable\n");
                if (unlikely(check_docker_pid() != 0)) {
                    //LOG_INFO("is docker process[%s], pid:%d,ppid:%d\n", filename,pid, ppid);
                    is_docker_process = 1;
                } 
            }
            break;
        }
        default:
            break;

    }

    uint8_t md5[16];
    uint8_t rule_mode = 0, is_access_interval_gt_5s = 1;
    char *md5_ptr;
    if (likely(is_docker_process == 0)) {
        switch (get_process_rule_mode_and_interval(filename, &rule_mode, &md5_ptr, &is_access_interval_gt_5s)) {
            case 0:
                {
                    md5_rule_entry_t mre;
                    if (md5_calculate_file(filename, mre.md5) != 0) {
                        return 0;
                    }
                    mre.type =  find_md5_action(mre.md5); 
                    //LOG_INFO("==[%s], type:%d, md5[%*phN]\n",filename, mre.type, 16, mre.md5);
                    rule_mode = mre.type; 
                    switch (mre.type) 
                    {
                        case 1:
                            {
                                if (sys_true_process == 1) {
                                    mre.type = 0; 
                                }
                                break;
                            }
                        default:
                            break;
                    } 
                    add_or_update_audit_process_info(filename, mre.md5, mre.type); 
                    //LOG_INFO("add get==[%s],  md5[%*phN]\n",filename,16, mre.md5);
                    break;
                }
            case 2:
                {
                    md5_rule_entry_t mre;
                    memcpy(mre.md5, md5_ptr,16);
                    mre.type =  find_md5_action(mre.md5); 
                    //LOG_INFO("==[%s], type:%d, md5[%*phN]\n",filename, mre.type, 16, mre.md5);
                    rule_mode = mre.type; 
                    switch (mre.type) 
                    {
                        case 1:
                            {
                                if (sys_true_process == 1) {
                                    mre.type = 0; 
                                }
                                break;
                            }
                        default:
                            break;
                    } 
                    add_or_update_audit_process_info(filename, mre.md5, mre.type); 
                    //LOG_INFO("update add get==[%s],  md5[%*phN]\n",filename,16, mre.md5);
                }

        }
    } else { //docker process
       
        if (is_proc_start_enable() == 0) {
            return 0;
        }

        if (md5_calculate_file(filename, md5) != 0) {
            return 0;
        }
        rule_mode =  find_md5_action(md5); 
        //LOG_INFO("docker: [%s], type:%d, md5[%*phN] is sys_process:%d\n",filename, rule_mode, 16, md5, sys_true_process);
        switch (rule_mode) 
        {
            case 0:
                return 0;
               // break;
            case 1:
                {
                    if (sys_true_process == 1) {
                        return 0;
                    }
                    break;
                }
            default:
                break;
        }

    }

    if (is_proc_start_enable() == 0 &&  is_syslog_enable() == 0) {
        return 0;
    }

    //if (is_process_enable() || is_syslog_enable()) 
    {
        //if (rule_mode == 0 && is_proc_start_enable() == 0) 
        if (rule_mode == 0 && is_syslog_enable() == 0) 
        {
            return 0;
        }

        if (zero_copy_load_succeed & PROCESS_AUDIT_ENABLE) {
            struct av_process_info *pi;
            uint32_t idx = get_process_audit_data(&pi);
            memset(pi->path, 0, sizeof(pi->path));
            if (likely(is_docker_process == 0)) {
                pi->uid = CURRENT_UID;
                pi->pid = pid;
                pi->ppid = ppid;
                pi->is_docker_process = 0;
            } else {
                memcpy(pi->md5, md5, 16);
                pi->is_docker_process = 1;
            }
            //pi->timestamp = jiffies / HZ;
            //pi->param_pos = 0;
            //memcpy(pi->comm, CURRENT_COMM, sizeof(pi->comm));
            //get_process_path(CURRENT_PPID, pi->comm, sizeof(pi->comm));
            //memcpy(pi->comm_p, CURRENT_COMM_P, sizeof(pi->comm_p));
            strncpy(pi->path, filename, sizeof(pi->path)-1);
            if (pathlen < MAX_PROCESS_PATH - 20  && is_proc_start_enable()) {
                strncpy(pi->path + pathlen, ";", 1);
#if 1 //zebra                
#if 0
                if (unlikely(get_process_path(ppid, pi->path + pathlen + 1, MAX_PROCESS_PATH - pathlen -1) == -1)) {
                    strncpy(pi->path + pathlen + 1, CURRENT_COMM_P, MAX_PROCESS_PATH - pathlen -1);
                    //pi->path[pathlen] = '\0';
                }
#else

                if (!in_interrupt() && current->mm != NULL) {
                    struct task_struct *p_task = current->parent;
                    if (likely(p_task != NULL)) {
                        if (unlikely(get_process_executable_path(p_task, pi->path + pathlen + 1, MAX_PROCESS_PATH - pathlen -1) == -1)) {
                            strncpy(pi->path + pathlen + 1, CURRENT_COMM_P, MAX_PROCESS_PATH - pathlen -1);
                        }
                    } else {
                        pi->path[pathlen] = '\0';
                    }
                }
#endif
#else
                strncpy(pi->path + pathlen + 1, CURRENT_COMM_P, MAX_PROCESS_PATH - pathlen -1);
#endif
//                LOG_INFO("==================[%s], ppid:%d\n",pi->path, ppid);
            }

            switch(rule_mode) {
                case 0: //白名单
                    pi->type = 0;
                    break;
                case 1:
                    {

                        if (is_process_need_wait()) {
                        
                            if (sys_true_process == 0) {
                                nDeny = 1;
                            }
                            //保护模式 匹配到黑名单
                            pi->type = 1102;
                            pi->level = 3;

                        } else {
                            nDeny = 0;
                            //监控模式 匹配到黑名单
                            pi->type = 1002;
                            pi->level = 2;
                        }
                        break;
                    }
                case 2:
                    {
                        if (is_process_need_wait()) {
                            if (sys_true_process == 0) {
                                nDeny = 1;
                            }
                            //保护模式 黑，白都没有匹配到
                            pi->type = 1101;
                            pi->level = 3;

                        } else {
                            //监控模式 黑，白都没有匹配到
                            pi->type = 1001;
                            pi->level = 2;
                            nDeny = 0;
                        }
                        break;
                    }
                default:
                    return 0;

            }
            //LOG_DEBUG("netdos_tcp_in ......");
            //LOG_INFO("exe_audit_filepath filename :%s, full path[%s]rule_mode:%d nDeny:%d,level:%d, type[%d]idx:%d, is_docker_process:%d,process_audit_data_count:%d\n", \
            filename, pi->path,rule_mode, nDeny,pi->level, pi->type,idx, pi->is_docker_process,process_audit_data_count);
            //debug_print_av_process_info("debug", pi);
            struct netlink_netlog netlog_msg;
            if (idx >= process_audit_data_count - 1) {
                uint32_t prev_idx = 0;
                netlog_msg.max_idx = get_process_audit_idx(&prev_idx, &idx);
                netlog_msg.start_idx = prev_idx;
                netlog_msg.end_idx = process_audit_data_count - 1;
                //LOG_INFO("process audit idx=%d start idx:%d, end idx:%d......\n",idx, netlog_msg.start_idx, netlog_msg.end_idx);
                send_nl_data(NL_POLICY_AV_PROCESS_EXEC_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
            }

        } else {
            struct av_process_info pi;
            //pi->param_pos = 0;
            //memcpy(pi.comm, CURRENT_COMM, sizeof(pi.comm));
            //memcpy(pi.comm_p, CURRENT_COMM_P, sizeof(pi.comm_p));
            strncpy(pi.path, filename, sizeof(pi.path)-1);
            pi.is_docker_process = !!is_docker_process;
            if (likely(is_docker_process == 0)) {
                pi.uid = CURRENT_UID;
                pi.pid = pid;
                pi.ppid = ppid;
            } else {
                memcpy(pi.md5, md5, 16);
            }


            switch(rule_mode) {
                case 0: //白名单
                    break;
                    //return 0;
                case 1:
                    {
                        if (is_process_need_wait()) {
                            if (sys_true_process == 0) {
                                nDeny = 1;
                            }
                            //保护模式 匹配到黑名单
                            pi.type = 1102;
                            pi.level = 3;

                        } else {
                            nDeny = 0;
                            //监控模式 匹配到黑名单
                            pi.type = 1002;
                            pi.level = 2;


                        }
                        break;
                    }
                case 2:
                    {
                        if (is_process_need_wait()) {
                            if (sys_true_process == 0) {
                                nDeny = 1;
                            }
                            //保护模式 黑，白都没有匹配到
                            pi.type = 1101;
                            pi.level = 3;

                        } else {
                            //监控模式 黑，白都没有匹配到
                            pi.type = 1001;
                            pi.level = 2;
                            nDeny = 0;
                        }
                        break;
                    }
                default:
                    return 0;

            }

            //pi->is_monitor_mode = 1;
            send_nowait_nl_data(NL_POLICY_AV_PROCESS_EXEC_NOTIFY, &pi, sizeof(struct av_process_info));
            //LOG_INFO("exe_audit_filepath filename :%s, nDeny:%d,comm[%s],comm_p[%s]\n", filename, nDeny, pi.comm, pi.comm_p);
        }
    }
    return nDeny;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static void file_audit_timer_function(struct timer_list *timer)
#else
static void file_audit_timer_function(unsigned long unused)
#endif
{
    uint32_t idx = 0, prev_idx = 0;
    struct netlink_netlog netlog_msg;
    if (unlikely(!atomic_is_timer_status_set(FILE_AUDIT_TIMER_ON))) {
        return;
    }

    netlog_msg.max_idx = get_file_audit_idx(&prev_idx, &idx);
    if (idx > prev_idx) {
        netlog_msg.start_idx = prev_idx;
        netlog_msg.end_idx = idx;
        //LOG_INFO("timer file audit start idx:%d, end idx:%d......\n",netlog_msg.start_idx, netlog_msg.end_idx);
        send_nl_data(NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
    }
    //LOG_INFO("in file_audit_timer_function");
    if (likely(atomic_is_timer_status_set(FILE_AUDIT_TIMER_ON))){
        mod_timer(&file_audit_timer, jiffies + 60 * HZ);  
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static void process_audit_timer_function(struct timer_list *timer)
#else
static void process_audit_timer_function(unsigned long unused)
#endif
{
    uint32_t idx = 0, prev_idx = 0;
    struct netlink_netlog netlog_msg;
    if (unlikely(!atomic_is_timer_status_set(PROCESS_AUDIT_TIMER_ON))) {
        return;
    }

    netlog_msg.max_idx = get_process_audit_idx(&prev_idx, &idx);
    if (idx > prev_idx) {
        netlog_msg.start_idx = prev_idx;
        netlog_msg.end_idx = idx;
        //LOG_INFO("timer process audit start idx:%d, end idx:%d......\n",netlog_msg.start_idx, netlog_msg.end_idx);
        send_nl_data(NL_POLICY_AV_PROCESS_EXEC_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
    }
    //LOG_INFO("in process_audit_timer_function");
    if (likely(atomic_is_timer_status_set(PROCESS_AUDIT_TIMER_ON))){
        mod_timer(&process_audit_timer, jiffies + 60 * HZ);  
    }
}

#include <linux/printk.h>
/*
void print_layout(void) {
    struct osec_network_report r;
    LOG_INFO("sizeof(osec_network_report): %zu\n", sizeof(r));
    LOG_INFO("src offset: %zu\n", offsetof(struct osec_network_report, src));
    LOG_INFO("src_port offset: %zu\n", offsetof(struct osec_network_report, src_port));
    LOG_INFO("dst offset: %zu\n", offsetof(struct osec_network_report, dst));
    LOG_INFO("dest_port offset: %zu\n", offsetof(struct osec_network_report, dest_port));
    LOG_INFO("pid offset: %zu\n", offsetof(struct osec_network_report, pid));
    LOG_INFO("comm offset: %zu\n", offsetof(struct osec_network_report, comm));
}
*/
void print_layout(void) {
    struct av_file_info r;
    LOG_INFO("sizeof(av_file_info): %zu\n", sizeof(r));
    LOG_INFO("pid offset: %zu\n", offsetof(struct av_file_info, pid));
    LOG_INFO("ppid offset: %zu\n", offsetof(struct av_file_info, ppid));
    LOG_INFO("uid offset: %zu\n", offsetof(struct av_file_info, uid));
    LOG_INFO("comm offset: %zu\n", offsetof(struct av_file_info, comm));
    LOG_INFO("comm_p offset: %zu\n", offsetof(struct av_file_info, comm_p));
    LOG_INFO("path offset: %zu\n", offsetof(struct av_file_info, path));
    LOG_INFO("dst_path offset: %zu\n", offsetof(struct av_file_info, dst_path));
    LOG_INFO("log_type offset: %zu\n", offsetof(struct av_file_info, log_type));
}
static int paz_init = 0;

int process_audit_zero_copy_init(void)
{
    int err = 0;

    if (paz_init) {
        return err;
    }

    LOG_INFO("process_audit_zero_copy_init zero_copy_load_succeed=[%x]\n", zero_copy_load_succeed);
    //print_layout();
    start_file_audit_timer();
    paz_init = 1;
    LOG_INFO("DRIVER PROCESS AUDIT INIT ZCOPY MODULE, close_net_business=%d\n", is_close_net_business());
    return err;
}

int process_audit_zero_copy_exit(void)
{
    if (paz_init == 0) {
        return 0;
    }

    stop_file_audit_timer();
    stop_process_audit_timer();
    LOG_INFO("DRIVER PROCESS AUDIT EXIT MODULE\n");
    paz_init = 0;
    return 0;
}

void start_process_audit_timer(void)
{
    if (zero_copy_load_succeed & PROCESS_AUDIT_ENABLE) {
        if (atomic_test_and_set_timer_status(PROCESS_AUDIT_TIMER_ON)) {
            LOG_INFO("process_audit timer already started, skipping...\n");
            return;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
         timer_setup(&process_audit_timer, process_audit_timer_function, 0);
#else
         setup_timer(&process_audit_timer, process_audit_timer_function, 0);
#endif
         mod_timer(&process_audit_timer, jiffies + 30 * HZ);  
        LOG_INFO("start process_audit timer===============================\n");
    }

}
void stop_process_audit_timer(void)
{
    if (atomic_test_and_clear_timer_status(PROCESS_AUDIT_TIMER_ON)) {
        del_timer_sync(&process_audit_timer); 
        LOG_INFO("stop process_audit timer===============================\n");
    }
}
void start_file_audit_timer(void)
{
    if (zero_copy_load_succeed & FILE_AUDIT_ENABLE) {
        if (atomic_test_and_set_timer_status(FILE_AUDIT_TIMER_ON)) {
            LOG_INFO("file_audit timer already started, skipping...\n");
            return;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
         timer_setup(&file_audit_timer, file_audit_timer_function, 0);
#else
         setup_timer(&file_audit_timer, file_audit_timer_function, 0);
#endif
         mod_timer(&file_audit_timer, jiffies + 30 * HZ);  
        LOG_INFO("start file_audit timer===============================\n");
    }

}
void stop_file_audit_timer(void)
{
    if (atomic_test_and_clear_timer_status(FILE_AUDIT_TIMER_ON)) {
        del_timer_sync(&file_audit_timer); 
        LOG_INFO("stop file_audit timer===============================\n");
    }
}




#include <linux/kernel.h>
#include <linux/string.h>
//#include <stddef.h> 

void debug_print_av_process_info(const char *tag, struct av_process_info *info)
{
    if (!info) {
        printk(KERN_ERR "debug_print_av_process_info: info is NULL\n");
        return;
    }

    printk(KERN_INFO "=== %s (layout: sizeof=%zu, path_offset=%zu) ===\n",
           tag,
           sizeof(struct av_process_info),
           offsetof(struct av_process_info, path));

    printk(KERN_INFO "pid: %d\n", info->pid);
    printk(KERN_INFO "ppid: %d\n", info->ppid);
    printk(KERN_INFO "uid: %d\n", info->uid);
    printk(KERN_INFO "type: %d\n", info->type);
    printk(KERN_INFO "flags (raw): %u (0x%08x)\n", info->flags_raw, info->flags_raw);
    printk(KERN_INFO "is_dir: %u\n", info->is_dir);
    printk(KERN_INFO "deny: %u\n", info->deny);
    printk(KERN_INFO "param_pos: %u\n", info->param_pos);
    printk(KERN_INFO "level: %u\n", info->level);
    printk(KERN_INFO "is_monitor_mode: %u\n", info->is_monitor_mode);
    printk(KERN_INFO "is_docker_process: %u\n", info->is_docker_process);
    printk(KERN_INFO "path: '%s'\n", info->path);

    printk(KERN_INFO "path[0..16] (hex):");
    int i;
    for (i = 0; i < 16 && info->path[i] != '\0'; i++) {
        printk(" %02x", (unsigned char)info->path[i]);
    }
    printk("\n");

    printk(KERN_INFO "struct raw (32 bytes):");
    const unsigned char *raw = (const unsigned char *)info;
    for (i = 0; i < 32; i++) {
        printk(" %02x", raw[i]);
    }
    printk("\n");
    printk(KERN_INFO "=== end %s ===\n", tag);
}
