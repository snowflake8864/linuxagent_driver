#ifndef __PROCESS_AUDIT_DOCKER_RULES_H
#define __PROCESS_AUDIT_DOCKER_RULES_H
int is_docker_pid(uint32_t pid); 
void set_docker_pid(uint32_t pid);
int get_docker_pid_state(uint32_t pid);
void clear_all_docker_pids(void); 
void set_docker_root_pid(uint32_t pid); 
int is_docker_root_process(uint32_t pid); 
int is_start_docker(void);
int is_start_docker_v1(void);
void start_docker_v1(void);
int docker_audit_init(struct proc_dir_entry *proc_parent); 
void docker_audit_exit(struct proc_dir_entry *proc_parent);
uint8_t get_docker_version(void);
void set_docker_version(uint8_t ver);
#endif
