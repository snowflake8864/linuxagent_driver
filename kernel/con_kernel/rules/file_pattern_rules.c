#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
 #include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "utils/utils.h"
#include "acsm/acsmx2.h"
#include "file_pattern_rules.h"
#include "gnHead.h"
#define FILE_PATTERN_MAX 50
struct proc_dir_entry *proc_osec_file_pattern = NULL;
static pattern_t *pattern_arrays;
static struct acsm_rules file_pattern_rules;
static int pattern_cmd_parse(struct acsm_rules *rules, char *cmd, char **key, int *key_len);
static int init_acsm(struct acsm_rules *rules)
{

    memset(rules->pattern, 0, (FILE_PATTERN_MAX * sizeof(pattern_t)));
    rules->acsm = acsmNew2();
    if (rules->acsm == NULL) {
        //kfree(pattern_arrays);
        LOG_INFO("alloc acsm fail\n");
        return -1;
    }
    LOG_INFO("init acsm and clear patterns\n");
    rules->id = 0;
    return 0;
}
#if 0
static void set_pattern(uint32_t id, uint32_t action, const char *name, const char *extra_key)
{
    if (id > 19) {
        return;
    }
    pattern_t *pattern = pattern_arrays + id;
    strncpy(pattern->name, name, sizeof(pattern->name) - 1);
    pattern->pattern_len = strlen(name);
    LOG_INFO("pattern name:[%s], id=%d\n",pattern->name, id);
    pattern->action = action&0xF;
}
#endif
int file_pattern_init(struct proc_dir_entry *proc_parent)
{
    int retv = 0;
    pattern_arrays = kmalloc(FILE_PATTERN_MAX * sizeof(pattern_t), GFP_ATOMIC | __GFP_ZERO);
    if (pattern_arrays == NULL) {
        return -1;
    }

    file_pattern_rules.acsm = acsmNew2();
    if (file_pattern_rules.acsm == NULL) {
        kfree(pattern_arrays);
        LOG_INFO("alloc acsm fail\n");
        return -1;
    }
    file_pattern_rules.pattern = pattern_arrays;
    file_pattern_rules.pattern_size = sizeof(pattern_t);
    file_pattern_rules.fn_init_acsm = init_acsm;

    file_pattern_rules.have_build = 0;
    file_pattern_rules.fn_pattern_parse = pattern_cmd_parse;
    acsm_rules_init(&file_pattern_rules, "file_patterns", proc_parent);
    return retv;
}

void file_pattern_exit(struct proc_dir_entry *proc_parent)
{

    acsm_rules_purge(&file_pattern_rules);
    //remove_proc_entry("file_patterns", proc_parent);
    kfree(pattern_arrays);
}

static int deal_hit_key(void * _pattern, int offset, void * data, void * arg)
{   
    pattern_t * pattern = (pattern_t *)_pattern;
//    size_t extra_data_len = 0;
//    size_t current_comm_len = 0;    
    char *str = (char *)data;
    char *sp;
    size_t str_len = strlen(str);


    if (pattern->match_full_path == 1) {
        if (!(offset == 0 && pattern->pattern_len == str_len)) {
            return 0;
        }
    } else {
        if (pattern->offset >= 0) {
            if (pattern->offset != offset)
                return 0;
        } else if (pattern->offset ==-1)  {
            if (str_len != offset + pattern->pattern_len) { 
                return 0;
            }
            //LOG_INFO("str[%s]\n",str);
        }
    }
#if 0
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
        case SELF_PROTECTION:
            *(int *)arg = 3;
            #if 0
            extra_data_len = strlen(pattern->extra_data);
            current_comm_len = strlen(CURRENT_COMM);
            if (extra_data_len == current_comm_len && strncmp(pattern->extra_data, CURRENT_COMM, current_comm_len) == 0) {
                *(int *)arg = 3;
            }
            #endif
            break;
    }
#else
    //*(int *)arg = pattern->action;
    *(int *)arg = (pattern->rid << 8)|(pattern->type << 4)|pattern->action;
    //LOG_INFO("Hit pattern[%s], offset=%d, action:%d, isnot_extend:%d, [%s]\n", pattern->name, offset, pattern->action, pattern->isnot_extend, (char *)data);
    if (pattern->isnot_extend == 1) {
        if (str_len > pattern->pattern_len + 1) {
            if((sp = strchr(str + pattern->pattern_len + 1, '/'))) {
                if (strlen(sp) > 1) {
                    *(int *)arg = 0;
                }
                //LOG_INFO("Hit pattern[%s], offset=%d, action:%d,[%s]\n", pattern->name, offset, pattern->action,(char *)data);
            }
        } else {
            //*(int *)arg = 0;
        }

    }
//    LOG_INFO("Hit pattern[%s], offset:%d,type:%d isnot_extend:%d, action:%d,[%s]\n", pattern->name, offset, pattern->type, pattern->isnot_extend, *(int *)arg ,(char *)data);
#endif
    return 0;
}

int file_acsmSearch(const char *str, int str_len)
{
    int result = 255;
    if (file_pattern_rules.have_build == 0) {
        return result;
    }
    ACSM_STRUCT2 *acsm;
	rcu_read_lock();
	acsm = rcu_dereference(file_pattern_rules.acsm);
    acsmSearch2(acsm, str, str_len, deal_hit_key, (void *)str, &result);
	rcu_read_unlock();
    return result;
}

enum pattern_field_item {
    PATTERN_NAME_ITEM = 0, KEY_LEN_ITEM, KEY_ITEM, ACTION_ITEM, NOCASE_ITEM, 
    OFFSET_ITEM,  DEPTH_ITEM, TYPE_ITEM, RID_ITEM, ISNOT_EXTEND_ITEM, 
    MATCH_FULL_PATH_ITEM, EXTRA_DATA_ITEM, MAX_PATTERN_FIELD_ITEM
};
static const char *pattern_field[] = {
    "name", "keylen", "key", "action","nocase", 
    "offset", "depth", "type", "rid","isnot_extend",
    "match_full_path", "extradata"
};


static int __pattern_cmd_parse(uint32_t id, pattern_t *pattern, char *cmd)
{
    int i;
    char *p;
    char *s_start = cmd;
    if((p = strchr(s_start, '=')) == NULL) {
        return -1;
    }
    *p = '\0';
    p++;
    trim(s_start);
    //LOG_INFO("field:%s, value:%s\n", s_start, p);
    for (i = 0; i < MAX_PATTERN_FIELD_ITEM; i++) {
        int cmp_len = strlen(pattern_field[i]) > strlen(s_start) ? strlen(pattern_field[i]) : strlen(s_start);
        if (!strncmp(s_start, pattern_field[i], cmp_len)) {
            break;
        }
    }
    if (i >= MAX_PATTERN_FIELD_ITEM)
        return -1;

    switch(i) {
        case PATTERN_NAME_ITEM:
        {
            trim(p);
            snprintf(pattern->name,32, "%s_%d", p, id);
            //LOG_INFO("pattern name[%s]\n",pattern->name);
            break;
        }
        case KEY_ITEM:
        {
            trim(p);
            strncpy(pattern->pattern, p, sizeof(pattern->pattern) - 1); 
            pattern->pattern_len = strlen(pattern->pattern);
            //LOG_INFO("pattern key[%s]\n",pattern->pattern);
            break;
        }
        case EXTRA_DATA_ITEM:
        {
            trim(p);
            strncpy(pattern->extra_data, p, sizeof(pattern->extra_data) - 1); 
            //LOG_INFO("extra_data[%s]\n",pattern->extra_data);
            break;
        }

        case ACTION_ITEM:
        {
            uint32_t action;
            trim(p);
            sscanf(p, "%u", &action);
            pattern->action = (action & 0x0F);
            //LOG_INFO("action=%d\n",pattern->action);
            break;
        }
        case OFFSET_ITEM:
        {
            int16_t offset;
            trim(p);
            sscanf(p, "%d", &offset);
            pattern->offset = offset;
            //LOG_INFO("offset=%d\n",pattern->offset);
            break;
        }
        case NOCASE_ITEM:
        {
            uint16_t nocase;
            trim(p);
            sscanf(p, "%d", &nocase);
            pattern->nocase = !!nocase;
            LOG_INFO("depth=%d\n",pattern->nocase);
            break;
        }
        case ISNOT_EXTEND_ITEM:
        {
            uint16_t isnot_extend;
            trim(p);
            sscanf(p, "%d", &isnot_extend);
            pattern->isnot_extend = !!isnot_extend;
            LOG_INFO("isnot_extend=%d\n",pattern->isnot_extend);
            break;
        }
        case MATCH_FULL_PATH_ITEM:
        {
            uint16_t match_full_path;
            trim(p);
            sscanf(p, "%d", &match_full_path);
            pattern->match_full_path = !!match_full_path;
            LOG_INFO("match_full_path=%d\n",pattern->match_full_path);
            break;
        }
        case DEPTH_ITEM:
        {
            uint16_t depth;
            trim(p);
            sscanf(p, "%d", &depth);
            pattern->depth = depth;
            LOG_INFO("depth=%d\n",pattern->depth);
            break;
        }
        case RID_ITEM:
        {
            uint16_t rid;
            trim(p);
            sscanf(p, "%d", &rid);
            pattern->rid = rid;
            LOG_INFO("rid=%d\n",pattern->rid);
            break;
        }
        case TYPE_ITEM:
        {
            uint16_t type;
            trim(p);
            sscanf(p, "%d", &type);
            pattern->type = (type & 0x3);
            LOG_INFO("type=%d\n",pattern->type);
            break;
        }

    }
    return 0;
}

static int pattern_cmd_parse(struct acsm_rules *rules, char *cmd, char **key, int *key_len)
{
    int retv = 0;
    char *sp, *s_start;
    pattern_t pattern;  
    if (rules->id >= FILE_PATTERN_MAX) {
        return -1;
    }
    memset(&pattern, 0, sizeof(pattern_t));
    uint32_t id = rules->id; 
    for(s_start = cmd; (sp = strchr(s_start, ',')); s_start = sp + 1){
        *sp = '\0';
        retv = __pattern_cmd_parse(id, &pattern, s_start);
    }
    if (s_start && strlen(s_start) > 4) {
        retv = __pattern_cmd_parse(id, &pattern, s_start);
    }
    pattern_t *pattern_p = pattern_arrays + id;
    memcpy(pattern_p, &pattern, sizeof(pattern_t));
    LOG_INFO("name:%s,id:%d, key[%s] isnot_extend:%d,match_full_path:%d,action:%d\n",\
    pattern_p->name,pattern_p->id, pattern_p->pattern, pattern_p->isnot_extend, pattern_p->match_full_path,pattern_p->action);
    *key = pattern_p->pattern;
    *key_len = pattern_p->pattern_len;
    return retv;
}

