#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/ctype.h> //toupper,isprint
#include <linux/slab.h>  //kmalloc,kfree
#include <linux/proc_fs.h>
#include "pattern_tbl.h"
#include "acsm/acsmx2.h"
#include "gnHead.h"
#include "rules.h"
#include "defense/defense_inner.h"
#include "utils/utils.h"

#define PATTERN_MAX_COUNT 128
extern int _hook_lsm_on;
struct state_array *DPI_State_TBL;
int *DPI_State_Flag_TBL;
uint16_t G_state_id_inc = 1;
static pattern_t *pattern_arrays;
static struct acsm_rules file_pattern_rules;
static int pattern_cmd_parse(struct acsm_rules *rules, char *cmd, char **key, int *key_len);
static int init_acsm(struct acsm_rules *rules)
{

    memset(rules->pattern, 0, (PATTERN_MAX_COUNT * sizeof(pattern_t)));
    rules->acsm = acsmNew2();
    if (rules->acsm == NULL) {
        LOG_INFO("alloc acsm fail\n");
        return -1;
    }

    G_state_id_inc = 1;
//    LOG_INFO("init acsm and clear patterns\n");
    rules->id = 0;
    return 0;
}

int pattern_init(struct proc_dir_entry *proc_parent)
{
    int retv = 0;
    pattern_arrays = kmalloc(PATTERN_MAX_COUNT * sizeof(pattern_t), GFP_ATOMIC | __GFP_ZERO);
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

void pattern_exit(struct proc_dir_entry *proc_parent)
{
    acsm_rules_purge(&file_pattern_rules);
    kfree(pattern_arrays);
}

enum pattern_field_item {
    PATTERN_NAME_ITEM = 0, KEY_LEN_ITEM, KEY_ITEM, ACTION_ITEM, NOCASE_ITEM, 
    OFFSET_ITEM,  DEPTH_ITEM, TYPE_ITEM, PKT_LEN_ITEM, 
    MATCH_FULL_PATH_ITEM, ISNOT_EXTEND_ITEM, 
	IS_FILE_ITEM, CASE_OFFSET_ITEM, MAX_PATTERN_FIELD_ITEM
};
static const char *pattern_field[] = {
    "name", "keylen", "key", "action","nocase", 
    "offset", "depth", "type", "pkt_len",
    "match_full_path", "isnot_extend", "is_file", 
    "case_offset"
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
            snprintf(pattern->name, 31, "%s", p);
            LOG_INFO("pattern name[%s]\n",pattern->name);
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
            LOG_INFO("nocase=%d\n",pattern->nocase);
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
        case PKT_LEN_ITEM:
        {
            int32_t pkt_len;
            trim(p);
            sscanf(p, "%d", &pkt_len);
            pattern->pkt_len = pkt_len;
            LOG_INFO("pkt_len=%d\n",pattern->pkt_len);
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
        case ISNOT_EXTEND_ITEM:
        {
            uint16_t isnot_extend;
            trim(p);
            sscanf(p, "%d", &isnot_extend);
            pattern->isnot_extend = !!isnot_extend;
            LOG_INFO("isnot_extend=%d\n",pattern->isnot_extend);
            break;
        }
       case IS_FILE_ITEM:
        {
            int8_t is_file;
            trim(p);
            sscanf(p, "%d", &is_file);
            pattern->is_file = (is_file & 0x3);
            LOG_INFO("pattern is_file=%d\n",pattern->is_file);
            break;
        }

        case CASE_OFFSET_ITEM:
        {
            int32_t case_offset;
            trim(p);
            sscanf(p, "%d", &case_offset);
            pattern->case_offset = !!case_offset;
            LOG_INFO("case_offset=%d\n",pattern->case_offset);
            break;
        }


        default:
            break;

    }
    return 0;
}

static int pattern_cmd_parse(struct acsm_rules *rules, char *cmd, char **key, int *key_len)
{
    int retv = 0;
    char *sp, *s_start;
    uint32_t id ; 
    pattern_t *pattern; 

    if (rules->id >= PATTERN_MAX_COUNT) {
        return -1;
    }
    id = rules->id; 
    pattern = pattern_arrays + id;
    for(s_start = cmd; (sp = strchr(s_start, ',')); s_start = sp + 1){
        *sp = '\0';
        if ((retv = __pattern_cmd_parse(id, pattern, s_start)) != 0) {
            return retv;
        }
    }
    if (s_start && strlen(s_start) > 4) {
        if ((retv = __pattern_cmd_parse(id, pattern, s_start)) != 0) {
            return retv;
        }
    }
    pattern->id = id;
    /* LOG_INFO("name:%s,id:%d, key[%s],match_full_path:%d,action:%d, rules id:%d\n",\
    pattern->name,pattern->id, pattern->pattern, pattern->match_full_path,pattern->action, rules->id);
    */
    *key = pattern->pattern;
    *key_len = pattern->pattern_len;
    return retv;
}

pattern_t *get_pattern_by_name(const char * name)
{
    int i;
    int len = strlen(name);
    int pattern_name_len;
    for (i = 0; i < PATTERN_MAX_COUNT && pattern_arrays[i].name[0] != '\0'; i ++) {
        pattern_name_len = strlen(pattern_arrays[i].name);
        if (pattern_name_len == len &&strncmp(pattern_arrays[i].name, name, len) == 0) {
            return pattern_arrays + i;
        }
    }
    return NULL;
}

static inline int is_file_type(const char* path, const uint8_t is_cut_kpathname) 
{
    struct path file_path;
    int is_file = 0;
    if (is_cut_kpathname == 1) {
        return 1;
    }
    // 获取文件路径对应的inode
    if (unlikely(kern_path(path, 0, &file_path) != 0)) {
        //LOG_INFO("Failed to get inode for path: %s\n", path);
        return 1;
    }

    //struct inode* inode = file_path.dentry->d_inode;
    //LOG_INFO("=========[%u] S_IFDIR[%d]====is file[%d]\n",  (inode->i_mode & S_IFMT), S_IFDIR, ((inode->i_mode & S_IFMT) != S_IFDIR));
    // 获取文件类型

    is_file = ((file_path.dentry->d_inode->i_mode & S_IFMT) != S_IFDIR);
    // 释放 file_path 的引用
    path_put(&file_path);
    return is_file;

}

static inline int check_pattern(pattern_t * pattern ,int offset, char *payload, uint16_t payload_len, uint16_t is_dir)
{
#if 0
	if (unlikely(is_dir == 512 && pattern->is_file == 1)) {
		LOG_INFO("pattern[%s] is_file[%d], is dir[%d], file[%s]\n",pattern->name, pattern->is_file, is_dir, payload);
		return -1;
	}
    if (pattern->case_offset == 1) {
        if (offset != pattern->offset) {
            return -1;
        }
    } 

#endif
    //if (_hook_lsm_on == 1 ) {
    
    //}
    if (pattern->pkt_len == -1) {
        if (offset + pattern->pattern_len != payload_len) {
            return -1;
        }
    } 

    if(pattern->offset)
    {
        if(pattern->offset > 0)
        {
            if(offset != pattern->offset)
            {
                return -1;
            }
        }
        else
        {
            //LOG_INFO("==offset=<%d,%d>\n",offset, payload_len + pattern->offset);
            if(offset != payload_len + pattern->offset)
            {
                return -1;
            }
        }
    } else if (pattern->case_offset == 1){
        if (offset != pattern->offset) {
            return -1;
        }

    }


    if(pattern->depth > 0)
    {
        if(offset + pattern->pattern_len > pattern->depth)
            return -1;
    }
    if (pattern->isnot_extend && offset + pattern->pattern_len < payload_len) {
        int pos = offset + pattern->pattern_len + 1;
        for (; pos < payload_len; ++ pos ) {
            if (payload[pos] != '/')
                break;
        }
        for (; pos < payload_len; ++ pos ) {
            if (payload[pos] == '/')
                break;
        }
        for (; pos < payload_len; ++ pos ) {
            if (payload[pos] != '/')
                break;
        }
        if (pos < payload_len) {
            //LOG_INFO("Hit true dir  no exten dir\n");
            return -1;
        }
    }
    //LOG_INFO("hit===pattern[%s]\n",pattern->pattern);
    return 0;
}



static int iter_dpi_stata(int *state_cnt, uint16_t *dpi_state_id_list, uint32_t *rule_ids, int *rule_cnt, uint16_t pattern_id, int *offsets, int offset, uint32_t *pattern_lens, uint32_t pattern_len)
{
    int cnt; 
    uint16_t next_state_id;
    uint16_t *id_list;
    int _rule_cnt;
    int i;

    cnt = *state_cnt;
    id_list = dpi_state_id_list;
    _rule_cnt = *rule_cnt;
    for(i = 0; i < *state_cnt; i++)//
    {
        next_state_id = DPI_State_TBL[id_list[i]].pattern[pattern_id].nextstate_id;

        if(0 == next_state_id)
        {
            continue;
        }

        if(DPI_State_Flag_TBL[next_state_id] & 0x1)//final state
        {
            rule_ids[_rule_cnt] = DPI_State_TBL[next_state_id].type_id;
            offsets[_rule_cnt] = offset;
            pattern_lens[_rule_cnt] =  pattern_len;
            *rule_cnt = _rule_cnt + 1;
            //LOG_INFO("hit rule i=%d,state_cnt:%d id:%d, pattern id:%d\n",i, *state_cnt, DPI_State_TBL[next_state_id].type_id, pattern_id);

        }
        id_list[cnt] = next_state_id;

        cnt++;
        if(cnt >= 5)
        {
            return -1;
        }
    }//for loop
    *state_cnt = cnt;
    return 0;
}

static int deal_hit_key(void ** _patterns, int *offsets, int cnt,void * data, int data_len, void * arg)
{   
    pattern_t ** patterns = (pattern_t **)_patterns;
    dpi_result_t *result = (dpi_result_t *)arg;
    rule_entry_t *rules, *rule;

    char *str = (char *)data;
    char *sp;
    uint16_t str_len = (uint16_t)data_len;
    int i;
    int state_cnt = 1;
    uint16_t dpi_state_id_list[5] = {0};
    uint32_t rule_ids[5] = {0};
    uint32_t hit_pattern_lens[5] = {0};
    int hit_offsets[5] = {0};
    int rule_cnt = 0;
    int protect_cnt = -1, lesuo_cnt = -1;
    for (i = 0; i < cnt; i++) {
        //LOG_INFO("str[%s],is_dir:%d, id:%d, cnt:%d, pattern<name:%s, offset:%d>, offset:%d, pkt_len:%d, payload_len:%d\n",\
        str, result->is_dir, patterns[i]->id, cnt, patterns[i]->name,patterns[i]->offset, offsets[i], patterns[i]->pkt_len, str_len);
        if (check_pattern(patterns[i], offsets[i], str, str_len, result->is_dir) == -1) {
            continue;
        }
        iter_dpi_stata(&state_cnt, dpi_state_id_list, rule_ids, &rule_cnt, patterns[i]->id, hit_pattern_lens, patterns[i]->pattern_len, hit_offsets, offsets[i]);
 //       LOG_INFO("opt[%d], 111111str[%s],id:%d, cnt:%d, rule_cnt:%d, pattern<name:%s, offset:%d>, offset:%d, pkt_len:%d, payload_len:%d\n",result->opt,\
        str, patterns[i]->id, cnt, rule_cnt, patterns[i]->name,patterns[i]->offset, offsets[i], patterns[i]->pkt_len, str_len);
    }
    rules = get_rules_rcu_lock();

    for (i = 0; i < rule_cnt; i ++) {
        rule = rules + rule_ids[i];
        //LOG_INFO("hit cnt:%d, type:%d, rule id:%d, level:%d, action:%d\n",rule_cnt, rule->type,rule_ids[i],rule->level, rule->action);
        switch (rule->type) {
            case 0://TrueDir
            {
                //LOG_INFO("True dir..\n"); 
                int hit_end_pos =  hit_offsets[i] + hit_pattern_lens[i];
                if (str_len > hit_end_pos) {
                    //LOG_INFO("===[%c] strlen=%d ===[%d] +[%d]= [%d]\n", str[hit_end_pos], str_len, hit_offsets[i], hit_pattern_lens[i],  hit_offsets[i] + hit_pattern_lens[i]);
                    if (unlikely(str[ hit_end_pos ] != '/')) {
                        break;
                    }
                }

                result->type[0] = 0;
                //result->protect_rw[0] = rule->protect_rw;
                result->cnt = 1;
                rcu_read_unlock();
                return 0;
            }
            case 1://lesuo
            {

                if (is_expoit_enable() == 0) {
                    break;
                }
                switch(rule->action) {
                    case 0://include dir
                        {
                            if (lesuo_cnt == -1) {

                                int hit_end_pos =  hit_offsets[i] + hit_pattern_lens[i];
                                if (str_len > hit_end_pos) {
                                    //LOG_INFO("===[%c] strlen=%d ===[%d] +[%d]= [%d]\n", str[hit_end_pos], str_len, hit_offsets[i], hit_pattern_lens[i],  hit_offsets[i] + hit_pattern_lens[i]);
                                    if (unlikely(str[ hit_end_pos ] != '/')) {
                                        break;
                                    }
                                }

                                lesuo_cnt = result->cnt ++;
                                result->action[lesuo_cnt] = rule->action;
                                result->type[lesuo_cnt] = 1;
                                result->rule_idx[lesuo_cnt] = rule->rule_idx;
                                result->tpnc[lesuo_cnt] = rule->tpnc;
                            }
                            break;
                        }
                    case 3://include file
                        {
                            if (lesuo_cnt == -1 && result->is_dir == 0) {
                                if(likely(result->is_cut_kpathname == 1||is_file_type(str, result->is_cut_kpathname) == 1)) 
                                {

                                    lesuo_cnt = result->cnt ++;
                                    result->action[lesuo_cnt] = rule->action;
                                    result->type[lesuo_cnt] = 1;
                                    result->rule_idx[lesuo_cnt] = rule->rule_idx;
                                    result->tpnc[lesuo_cnt] = rule->tpnc;
                                    result->protect_rw[lesuo_cnt] = rule->protect_rw;
                                }
                            }
                            break;
                        }

                }

//                LOG_INFO("lesuo id:%d, action :%d, level:%d cnt:%d\n", rule->id, rule->action, rule->level, result->cnt); 
                break;
            }
            case 2://protect
            {
                if (unlikely(is_file_enable() == 0)) {
                    break;
                }
                switch(rule->action) {
                    case 0://include dir
                        {
                           if (protect_cnt == -1) {
                               int hit_end_pos =  hit_offsets[i] + hit_pattern_lens[i];
                                   //LOG_INFO("===[%c] strlen=%d ===[%d] +[%d]= [%d]\n", str[hit_end_pos], str_len, hit_offsets[i], hit_pattern_lens[i],  hit_offsets[i] + hit_pattern_lens[i]);
                                   //LOG_INFO("===[%s] strlen=%d ===[%d] +[%d]= [%d]\n", str, str_len, hit_offsets[i], hit_pattern_lens[i],  hit_offsets[i] + hit_pattern_lens[i]);

                               //if (_hook_lsm_on == 1 &&  result->opt == FILE_CREATE &&hit_offsets[i] == 0 && str_len == hit_pattern_lens[i]) 
                               if (_hook_lsm_on == 1 &&  result->opt == FILE_CREATE &&hit_offsets[i] == 0 && is_file_type(str, result->is_cut_kpathname) == 0) 
                               { //lsm下， 可能会先进入前级目录
                                    break;
                               }

                               if (str_len > hit_end_pos) { 
                                   //LOG_INFO("===[%c] strlen=%d ===[%d] +[%d]= [%d]\n", str[hit_end_pos], str_len, hit_offsets[i], hit_pattern_lens[i],  hit_offsets[i] + hit_pattern_lens[i]);
                                    if (unlikely(str[ hit_end_pos ] != '/')) {
                                        break;
                                    }
                               }
                                protect_cnt = result->cnt ++;
                                result->action[protect_cnt] = rule->action;
                                result->type[protect_cnt] = 2;
                                result->rule_idx[protect_cnt] = rule->rule_idx;
                                result->tpnc[protect_cnt] = rule->tpnc;
                                result->protect_rw[protect_cnt] = rule->protect_rw;
                            }
                            break;
                        }
                    case 1://exclude dir
                    {
                        if (protect_cnt == -1) {
                            protect_cnt = result->cnt ++;
                            result->action[protect_cnt] = rule->action;
                            result->type[protect_cnt] = 2;
                            result->rule_idx[protect_cnt] = rule->rule_idx;
                            result->tpnc[protect_cnt] = 0;
                        }else {
                            result->action[protect_cnt] = rule->action;
                            result->type[protect_cnt] = 2;
                            result->rule_idx[protect_cnt] = rule->rule_idx;
                            result->tpnc[protect_cnt] = 0;
                        }
                        break;
                    }
                    case 2://exclude file
                    {
                        if (protect_cnt == -1) {
                            protect_cnt = result->cnt ++;
                            result->action[protect_cnt] = rule->action;
                            result->type[protect_cnt] = 2;
                            result->rule_idx[protect_cnt] = rule->rule_idx;
                            result->tpnc[protect_cnt] = 0;
                        }else {
                            result->action[protect_cnt] = rule->action;
                            result->type[protect_cnt] = 2;
                            result->rule_idx[protect_cnt] = rule->rule_idx;
                            result->tpnc[protect_cnt] = 0;
                        }
                        break;
                    }
                    case 3://include file
                    {
                        if (protect_cnt == -1 && result->is_dir == 0) {
                            if(likely(result->is_cut_kpathname == 1||is_file_type(str, result->is_cut_kpathname) == 1)) { 
                                protect_cnt = result->cnt ++;
                                result->action[protect_cnt] = rule->action;
                                result->type[protect_cnt] = 2;
                                result->rule_idx[protect_cnt] = rule->rule_idx;
                                result->tpnc[protect_cnt] = rule->tpnc;
                                result->protect_rw[protect_cnt] = rule->protect_rw;
                            }
                        }
                        break;
                    }

                }
    //        LOG_INFO("[%s]protect[%s] rule_idx:%d, action :%d, level:%d cnt:%d, is_file:%d,is_dir:%d, is_cut_kpathname:%d\n", \
            data, rule->name, rule->rule_idx, rule->action, rule->level, result->cnt,rule->is_file, result->is_dir, result->is_cut_kpathname); 

                break;
            }
            case 3: //自保
            {
                result->type[0] = 3;
                result->cnt = 1;
                rcu_read_unlock();
                return 0;
            }
        }

    }
//out:
    rcu_read_unlock();
    return 0;
}

int file_acsmSearch3(const char *str, int str_len,  dpi_result_t *result)
{
    ACSM_STRUCT2 *acsm;
    if (unlikely(file_pattern_rules.have_build == 0)) {
        return -1;
    }
	rcu_read_lock();
	acsm = rcu_dereference(file_pattern_rules.acsm);
    if (likely(acsm)) {
        acsmSearch3(acsm, (unsigned char *)str, str_len,deal_hit_key, (void *)str, result);
    }
	rcu_read_unlock();
    return 0;
}
