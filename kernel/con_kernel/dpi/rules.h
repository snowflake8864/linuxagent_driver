#ifndef __DPI_RULES_TBL_H__
#define __DPI_RULES_TBL_H__
#include <linux/types.h>

#define DPI_RULE_NAME 32
#define DPI_RULES_MAX_COUNT 64
typedef struct {
    char name[DPI_RULE_NAME];
    uint32_t action:4,
            type:4,
            level:4,
            isnot_extend:1,
            protect_rw:6,
			is_file:2;    
    int16_t rule_idx;    
    uint8_t tpnc;    
    //int32_t protect_rw;    
    uint32_t id;
    uint8_t ref;
}rule_entry_t;

typedef struct dpi_rules{
    rule_entry_t *entrys;
	struct rw_semaphore rwsem;
	const char *proc_name;
	struct proc_dir_entry *proc_parent;
    uint32_t id; 
	unsigned long (*fn_get_edata)(const char *extra_str);
	void (*fn_show_edata)(unsigned long edata, char *buf);
	void (*fn_clear)(struct dpi_rules *rules);
    int (*fn_rules_parse)(struct dpi_rules *rules, char *cmd);
}dpi_rules_t;

rule_entry_t * get_rules_rcu_lock(void);
int dpi_rules_init(struct proc_dir_entry *proc_parent);
int dpi_rules_exit(struct proc_dir_entry *proc_parent);
#endif
