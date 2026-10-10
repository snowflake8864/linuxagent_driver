#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
 #include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "utils/utils.h"
#include "acsm/acsmx2.h"
#include "process_pattern_rules.h"
#include "gnHead.h"
#define PROCESS_PATTERN_MAX 20
struct proc_dir_entry *proc_osec_process_pattern = NULL;
static pattern_t *pattern_arrays;
static struct acsm_rules process_pattern_rules;

static int init_acsm(struct acsm_rules *rules)
{

    rules->acsm = acsmNew2();
    if (rules->acsm == NULL) {
        //kfree(pattern_arrays);
        LOG_INFO("alloc acsm fail\n");
        return -1;
    }
    return 0;
}



int process_pattern_init(struct proc_dir_entry *proc_parent)
{
    int retv = 0;
    pattern_arrays = kmalloc(PROCESS_PATTERN_MAX * sizeof(pattern_t), GFP_ATOMIC | __GFP_ZERO);
    if (pattern_arrays == NULL) {
        return -1;
    }

    process_pattern_rules.acsm = acsmNew2();
    if (process_pattern_rules.acsm == NULL) {
        kfree(pattern_arrays);
        LOG_INFO("alloc acsm fail\n");
        return -1;
    }
    process_pattern_rules.pattern = pattern_arrays;
    process_pattern_rules.pattern_size = sizeof(pattern_t);
    process_pattern_rules.fn_init_acsm = init_acsm;
    process_pattern_rules.have_build = 0;
    acsm_rules_init(&process_pattern_rules, "process_patterns", proc_parent);
    return retv;
}

void process_pattern_exit(struct proc_dir_entry *proc_parent)
{

    acsm_rules_purge(&process_pattern_rules);
    //remove_proc_entry("process_pattern", proc_parent);
    kfree(pattern_arrays);
}

static int deal_hit_key(void * _pattern, int offset, void * data, void * arg)
{   
    pattern_t * pattern = (pattern_t *)_pattern;

    LOG_INFO("Hit pattern[%s]\n", pattern->name);
    switch (pattern->action)  {
        case CONTINUE_RUN:
            *(int *)arg = 2;
            break;
        case PASS_RETURN:
            *(int *)arg = 0;
            break;
        case BLOCK_RETURN:
            *(int *)arg = 1;
            break;
    }
    return 0;
}
int process_acsmSearch(const char *str, int str_len)
{
    int result = 0;
    if (process_pattern_rules.have_build == 0) {
        return result;
    }
    acsmSearch2(process_pattern_rules.acsm, str, str_len, deal_hit_key, NULL, &result);
    return result;
}

