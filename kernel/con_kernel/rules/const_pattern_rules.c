#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
 #include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "utils/utils.h"
#include "acsm/acsmx2.h"
#include "const_pattern_rules.h"
#include "pattern.h"
#include "gnHead.h"
#define CONST_PATTERN_MAX 20
struct proc_dir_entry *proc_osec_const_pattern = NULL;
static pattern_t *pattern_arrays;
static struct acsm_rules const_pattern_rules;
enum PATTERN_ACTION {
    CONTINUE_RUN,
    PASS_RETURN,
    BLOCK_RETURN
};

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

static void set_pattern(uint32_t id, uint8_t action, const char *name, const char *extra_key)
{
    if (id > 19) {
        return;
    }
    pattern_t *pattern = pattern_arrays + id;
    strncpy(pattern->name, name, sizeof(pattern->name) - 1);
    pattern->action = action&0x3;
}

int const_pattern_init(struct proc_dir_entry *proc_parent)
{
    int retv = 0;
    pattern_arrays = kmalloc(CONST_PATTERN_MAX * sizeof(pattern_t), GFP_ATOMIC | __GFP_ZERO);
    if (pattern_arrays == NULL) {
        return -1;
    }

    const_pattern_rules.acsm = acsmNew2();
    if (const_pattern_rules.acsm == NULL) {
        kfree(pattern_arrays);
        LOG_INFO("alloc acsm fail\n");
        return -1;
    }
    const_pattern_rules.pattern = pattern_arrays;
    const_pattern_rules.pattern_size = sizeof(pattern_t);
    const_pattern_rules.fn_init_acsm = init_acsm;
    const_pattern_rules.have_build = 0;
    const_pattern_rules.fn_set_pattern = set_pattern;

    if((proc_osec_const_pattern = proc_mkdir("const_pattern", proc_parent)) == NULL)
    {   
        printk(KERN_ERR "conn_block: creating proc_fs directory failed.\n");
        kfree(pattern_arrays);
        return -1;
    }   

    acsm_rules_init(&const_pattern_rules, "const_patterns", proc_osec_const_pattern);
    return retv;
}

void const_pattern_exit(struct proc_dir_entry *proc_parent)
{

    acsm_rules_purge(&const_pattern_rules);
    remove_proc_entry("const_pattern", proc_parent);
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
int const_acsmSearch(const char *str, int str_len)
{
    int result = 0;
    if (const_pattern_rules.have_build == 0) {
        return result;
    }
    acsmSearch2(const_pattern_rules.acsm, str, str_len, deal_hit_key, NULL, &result);
    return result;
}

