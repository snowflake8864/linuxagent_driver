#ifndef __PROCESS_DPI_RULES_TBL_H__
#define __PROCESS_DPI_RULES_TBL_H__
#include <linux/types.h>

#define PROCESS_DPI_RULE_NAME 32
#define PROCESS_DPI_RULES_MAX_COUNT 64

typedef struct {
    char name[PROCESS_DPI_RULE_NAME];
    uint32_t action:4,
            type:4,
            level:4;
    int16_t rule_idx;    
    uint32_t id;
    uint8_t ref;
}process_dpi_rule_entry_t;

typedef struct process_dpi_rules_s{
    process_dpi_rule_entry_t *entrys;
	struct rw_semaphore rwsem;
	const char *proc_name;
	struct proc_dir_entry *proc_parent;
    uint32_t id; 
	unsigned long (*fn_get_edata)(const char *extra_str);
	void (*fn_show_edata)(unsigned long edata, char *buf);
	void (*fn_clear)(struct process_dpi_rules_s *rules);
    int (*fn_rules_parse)(struct process_dpi_rules_s *rules, char *cmd);
}process_dpi_rules_t;

process_dpi_rule_entry_t * get_process_dpi_rules_rcu_lock(void);
int process_dpi_rules_init(struct proc_dir_entry *proc_parent);
int process_dpi_rules_exit(struct proc_dir_entry *proc_parent);
#endif
