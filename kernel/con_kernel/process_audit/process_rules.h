#ifndef __PROCESS_AUDIT_PROCESS_RULES_H
#define __PROCESS_AUDIT_PROCESS_RULES_H

#define MAX_PATH_LEN 256
#define MAX_MD5_LEN 16

// 进程审计信息结构
struct process_audit_info {
    char path[PATH_MAX];
    char md5[MAX_MD5_LEN];
    uint8_t rule_mode:3, // 黑白名单属性
            is_access_interval_gt_5s:1;
    uint64_t mtime;
    unsigned long timestamp;
    unsigned long process_black_white_last_update_timestamp;
    struct hlist_node hnode; // 哈希链表节点
    atomic_t refcount;       // 引用计数
};



int process_audit_init(struct proc_dir_entry *proc_parent); 
void process_audit_exit(struct proc_dir_entry *proc_parent);
struct process_audit_info *get_process_audit_info(const char *path); 
int add_or_update_audit_process_info(const char *path, const uint8_t *md5, uint8_t rule_mode); 
//int get_process_rule_mode_and_interval(const char *path, uint8_t *rule_mode, uint8_t *is_access_interval_gt_5s); 
int get_process_rule_mode_and_interval(const char *path, uint8_t *rule_mode, char **md5, uint8_t *is_access_interval_gt_5s);
int get_process_md5(const char *path, uint8_t *md5);
#endif
