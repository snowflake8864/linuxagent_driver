#include <linux/slab.h>  //kmalloc,kfree
#include <linux/string.h> //memcpy
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/ctype.h> //toupper,isprint
#include "pattern_tbl.h"
#include "acsm/acsmx2.h"
#include "gnHead.h"
#include "utils/utils.h"
#include "utils/mstring.h"
#include "rules.h"
#include "pattern_tbl.h"
#include "defense/defense_inner.h"
static int rules_init_finish = 0;
struct proc_dir_entry *proc_rules = NULL;

/* --------- /proc interface part --------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
#define GET_DPI_RULES_DATA(inode) pde_data(inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define GET_DPI_RULES_DATA(inode) PDE_DATA(inode)
#else
#define GET_DPI_RULES_DATA(inode) PDE(inode)->data
#endif

static int check_rule_by_name(dpi_rules_t *rules,const char *name)
{
    int i, retv = 0;
    int len = strlen(name);
    int entry_len;
    rule_entry_t *entrys = NULL;
    rcu_read_lock();
    entrys = rcu_dereference(rules->entrys);
    for (i = 0; i < DPI_RULES_MAX_COUNT && entrys[i].name[0] != '\0'; i++) {
        entry_len = strlen(entrys[i].name);
        if (entry_len == len &&strncmp(entrys[i].name, name, len) == 0) {
            retv = 1;
        }
    }
    rcu_read_unlock();
    return retv;
}
static int get_rule_id_by_name(rule_entry_t *entrys,const char *name)
{
    int i, retv = -1;
    int len = strlen(name);
    int entry_len;
    for (i = 0; i < DPI_RULES_MAX_COUNT && entrys[i].name[0] != '\0'; i++) {
        entry_len = strlen(entrys[i].name);
        if (entry_len == len &&strncmp(entrys[i].name, name, len) == 0) {
            retv = i;
        }
    }
    return retv;
}
static int build_state_table(int state_array_id,int pattern_id,int first,int endflag, uint32_t type_id)
{
    uint16_t id;
    if(state_array_id < 0)
    {
        return -1;
    }

    if(G_state_id_inc >= DPI_STATE_TBL_MAX)
    {
            LOG_INFO("no room for more state node.[%d,%d]\n",G_state_id_inc,DPI_STATE_TBL_MAX);
        return -1;
    }

    if(pattern_id >= (DPI_PATTERN_MAX -1))
    {
            LOG_INFO("no room for more pattern node.[%d,%d]\n", pattern_id,DPI_PATTERN_MAX);
        return -1;
    }

    //DPI_State_TBL[state_array_id].enable = 1;
    if(DPI_State_TBL[state_array_id].pattern[pattern_id].nextstate_id == 0)
    {
        DPI_State_TBL[state_array_id].pattern[pattern_id].nextstate_id = G_state_id_inc;
        id = G_state_id_inc;
        G_state_id_inc++;
    }
    else
    {
        id = DPI_State_TBL[state_array_id].pattern[pattern_id].nextstate_id;
    }
    if(endflag == 1)
    {
        DPI_State_Flag_TBL[id] |= 0x1;
        DPI_State_TBL[id].type_id = type_id;
    //    if (strcmp(pattern_name, "content_type_app_octet_stream") == 0)
             LOG_INFO("state_array_id:%d is final state,type_id:%02x\n",id,type_id);
    }
    if(first)
    {
        DPI_State_Flag_TBL[id] |= 0x2;
    }

    return id;
}

static int  load_rule(rule_entry_t *rule, const char *pattern_list, const uint32_t id)
{
    int retv = 0;
    int state_array_id = 0;
    int endflag = 0;
    pattern_t *pattern = NULL;
    char **toks;
    int num_toks;
    int i;

    //target_id =  app_class->type_id;
    toks = mSplit(pattern_list, ">", 12, &num_toks, 0);
    LOG_INFO("pattern_list[%s],id:%d, num_toks:%d\n",pattern_list, id, num_toks);
    if(unlikely(num_toks == 0)) {
        retv = -1;
        LOG_INFO("no pattern list\n");
        goto out;
    }
    for (i = 0; i < num_toks; i++) {
        str_trim(toks[i]);
        if ((pattern = get_pattern_by_name(toks[i])) == NULL) {
            LOG_INFO("invalid pattern[%s]\n", toks[i]);
            goto out;
        }
        LOG_INFO("===================================\n");
        if(i == 0)
            pattern->first = 1;
        if(i == (num_toks - 1))
            endflag = 1;
        LOG_INFO("state_array_id:%d, pattern id[%d], id:%d\n",state_array_id,pattern->id,id);
        state_array_id = build_state_table(state_array_id,pattern->id,pattern->first,endflag, id);

    }
out:
    mSplitFree(&toks, num_toks);

    return retv;
}
enum rules_field_item {
    RULES_NAME_ITEM = 0, ACTION_ITEM, TYPE_ITEM,
    PATTERN_LIST_ITEM, ISNOT_EXTEND_ITEM, 
    LEVEL_ITEM, RULE_IDX_ITEM, PROTECT_RW_ITEM, 
    IS_FILE_ITEM,  TPNC_ITEM, MAX_RULES_FIELD_ITEM
};
static const char *rules_field[] = {
    "target", "action", "type", "pattern", "isnot_extend", "level", "rule_idx","protect_rw", "is_file", "TPNC"
};


static int __rules_cmd_parse(dpi_rules_t *rules, rule_entry_t *rule, uint32_t id, char *cmd)
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
    LOG_INFO("field:%s, value:%s\n", rule->name, s_start, p);
    for (i = 0; i < MAX_RULES_FIELD_ITEM; i++) {
        int cmp_len = strlen(rules_field[i]) > strlen(s_start) ? strlen(rules_field[i]) : strlen(s_start);
        if (!strncmp(s_start, rules_field[i], cmp_len)) {
            break;
        }
    }
    if (i >= MAX_RULES_FIELD_ITEM)
        return -1;

    switch(i) {
        case RULES_NAME_ITEM:
        {
            trim(p);
            if (check_rule_by_name(rules,p) == 1) {
                return -1;
            }
            strncpy(rule->name, p, sizeof(rule->name));
            LOG_INFO("rule name[%s]\n",rule->name);
            break;
        }
       case TYPE_ITEM:
        {
            uint32_t type;
            trim(p);
            sscanf(p, "%u", &type);
            rule->type = (type & 0x0F);
            LOG_INFO("rule type=%d\n",rule->type);
            break;
        }
       case LEVEL_ITEM:
        {
            uint32_t level;
            trim(p);
            sscanf(p, "%u", &level);
            rule->level = (level & 0x0F);
            LOG_INFO("rule level=%d\n",rule->level);
            break;
        }
       case RULE_IDX_ITEM:
        {
            int32_t rule_idx;
            trim(p);
            sscanf(p, "%d", &rule_idx);
            rule->rule_idx = rule_idx;
            LOG_INFO("rule rule_idx=%d\n",rule->rule_idx);
            break;
        }
       case PROTECT_RW_ITEM:
        {
            int32_t protect_rw;
            trim(p);
            sscanf(p, "%d", &protect_rw);
            rule->protect_rw = protect_rw;
            LOG_INFO("rule protect_rw=%x\n",rule->protect_rw);
            break;
        }

       case ACTION_ITEM:
        {
            uint32_t action;
            trim(p);
            sscanf(p, "%u", &action);
            rule->action = (action & 0x0F);
            LOG_INFO("rule action=%d\n",rule->action);
            break;
        }
        case PATTERN_LIST_ITEM:
        {
            trim(p);
            load_rule(rule, p, id);
            break;
        }
        case ISNOT_EXTEND_ITEM:
        {
            uint16_t isnot_extend;
            trim(p);
            sscanf(p, "%d", &isnot_extend);
            rule->isnot_extend = !!isnot_extend;
            LOG_INFO("isnot_extend=%d\n",rule->isnot_extend);
            break;
        }
       case IS_FILE_ITEM:
        {
            int8_t is_file;
            trim(p);
            sscanf(p, "%d", &is_file);
            rule->is_file = (is_file & 0x3);
            LOG_INFO("rule is_file=%d\n",rule->is_file);
            break;
        }
        case TPNC_ITEM:
        {
            uint8_t tpnc;
            trim(p);
            sscanf(p, "%d", &tpnc);
            rule->tpnc = tpnc;
            LOG_INFO("rule tpnc=%d\n",rule->tpnc);
 
            break;
        }
    }
    return 0;
}

static int rules_cmd_parse(dpi_rules_t *rules, char *cmd)
{
    int retv = 0;
    int state_array_id = 0;
    int endflag = 0;
    pattern_t *pattern = NULL;
    char **toks;
    int num_toks;
    int i;
    LOG_INFO("cmd[%s]\n",cmd);

    //target_id =  app_class->type_id;
    toks = mSplit(cmd, ",", 7, &num_toks, 0);
    if(unlikely(num_toks == 0)) {
        retv = -1;
        LOG_INFO("no pattern list\n");
        goto out;
    }
    i = 0;
    str_trim(toks[i]);
    if (strncmp(toks[i], "target=", 7) != 0) {
        retv = -1;
        LOG_INFO("invalid rules\n");
        goto out;
    }
    char *sp = strchr(toks[i], '=');
    if (sp == NULL) {
        retv = -1;
        LOG_INFO("invalid rules\n");
        goto out;
    }
    *sp = '\0';
    sp ++;
    str_trim(sp);
    int rule_id, flag = -1;

	rcu_read_lock();
	rule_entry_t *rule_entrys = rcu_dereference(rules->entrys);

    if ((rule_id = get_rule_id_by_name(rule_entrys,sp)) == -1) {
        rule_id = rules->id;
        flag = 1;
    }
    rule_entry_t *entry_p = rule_entrys + rule_id;
    if (flag == 1) {
        strncpy(entry_p->name, sp, sizeof(entry_p->name));
        entry_p->ref = 0;
        entry_p->id = rules->id;
    }
    entry_p->ref ++;
    LOG_INFO("rule name[%s], ref:%d, rule_id:%d\n",entry_p->name, entry_p->ref, rule_id);
    for (i = 1; i < num_toks; i++) {
        str_trim(toks[i]);
        if ((retv = __rules_cmd_parse(rules, entry_p, rule_id, toks[i])) == -1) {
	        rcu_read_unlock();
            goto out;
        }

    }
    if (flag == 1)
        rules->id ++;
	rcu_read_unlock();
    LOG_INFO("name:%s,id:%d, action:%d\n",\
    entry_p->name,rule_id, entry_p->action);
out:
    mSplitFree(&toks, num_toks);
    return retv;
}

static dpi_rules_t dpi_rules = {
    .fn_rules_parse = rules_cmd_parse,
    //.rwsem = {.count = 1},
};

struct dpi_rules_proc
{
#define DPI_RULES_PROC_WBUF_SZ  1024
	char    wbuf[DPI_RULES_PROC_WBUF_SZ + 20];
	size_t  wbuf_sz;
	size_t  wpos;
	/* Length of the output string */
	char   *rbuf;
	size_t  rbuf_len;
	size_t  rpos;
};
/**
 * Structure for printing rule table.
 */
struct buffer_s
{
	char   line[512];
	size_t len;
	struct buffer_s *next;
};

static inline void dpi_rules_clean_rcu(dpi_rules_t *rules)
{
    rule_entry_t *entrys = rules->entrys;
    rcu_assign_pointer(entrys, NULL);
    synchronize_rcu();
    memset(rules->entrys, 0, DPI_RULES_MAX_COUNT * sizeof(rule_entry_t));
}


bool dpi_rules_check(dpi_rules_t *rules, const char *key, unsigned long *edata)
{
	bool retv = false;
	unsigned long __edata = 0;
	int entry_len = 0;
    int i = 0;

    rule_entry_t *entrys = NULL;
	rcu_read_lock();
	entrys = rcu_dereference(rules->entrys);
    int len = strlen(key);
    for (i = 0; i < DPI_RULES_MAX_COUNT && entrys[i].name[0] != '\0'; i++) {
        entry_len = strlen(entrys[i].name);
        if (entry_len == len &&strncmp(entrys[i].name, key, len) == 0) {
            retv = true;
            __edata = entrys + i;
            goto to_exit;
        }

    }
    
	/* It won't actually get here */
	rcu_read_unlock();
    LOG_INFO("test %s failt\n", key);
	return false;

to_exit:
	rcu_read_unlock();
    LOG_INFO("test %s ok\n", key);
	if(edata)
		*edata = __edata;
	return retv;
}

static int dpi_rules_cmd_parse(dpi_rules_t *rules, char *cmd, struct dpi_rules_proc *proc)
{
	char *a1 = NULL, *a2 = NULL;
	char *sep;
	char sc;
	int n = 32;
	// -------------------------------
	unsigned long data = 0;
	// -------------------------------
    //LOG_INFO("rules:%p\n",rules);
    LOG_INFO("cmd:%s\n",cmd);

	if(strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0)
	{
		/* Case 1: 'clear' command. */
		/* ------------------------------------ */
        //LOG_INFO("rwsem=%p, count:%d\n", &rules->rwsem, rules->rwsem.count);
		down_write(&rules->rwsem);

		dpi_rules_clean_rcu(rules);
        rules->id = 0;
        memset(DPI_State_TBL, 0, sizeof(struct state_array)*DPI_STATE_TBL_MAX);
        memset(DPI_State_Flag_TBL, 0, sizeof(int)*DPI_STATE_TBL_MAX );
        //rules->have_build = 0;
	    proc->rbuf_len = proc->rpos = 0;
		proc->wbuf_sz =  proc->wpos = 0;
		up_write(&rules->rwsem);
		/* ------------------------------------ */
		return 0;
    }
	else if(strncmp(cmd, "t ", 2) == 0)
	{
		/* Case 2: 't' command (test method). */
		a1 = cmd + 2;
		if(dpi_rules_check(rules, a1, NULL))
			return 0;
		else
			return -EINVAL;
	} 

    if (rules->fn_rules_parse == NULL) {
        return 0;
    }
    char *sp,*ln_start, *key_str = NULL, *action_str = NULL, *action_end_str = NULL, *extra_key_str = NULL;
    uint32_t action = 0;  
    for(ln_start = cmd; (sp = strchr(ln_start, '\n')); ln_start = sp + 1)
    {   
        *sp = '\0';
        trim(ln_start);
        if (ln_start[0] == '#')
            continue;
        if (rules->fn_rules_parse(rules, ln_start) == 0) {

        }
    }
    if (ln_start != NULL) {
        trim(ln_start);
        if (rules->fn_rules_parse(rules, ln_start) == 0) {
        }
    }

	return 0;
}

static ssize_t dpi_rules_proc_write(struct file *file, const char __user *data, size_t count, loff_t *f_pos)
{
    if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) !=0) {
		return -EINVAL;
    }

	struct inode *inode = file->f_path.dentry->d_inode;
	dpi_rules_t *rules = (dpi_rules_t *)OSEC_PDE_DATA(inode);

	struct dpi_rules_proc *proc = (struct dpi_rules_proc *)file->private_data;
	size_t len;
	size_t __count = count;
	char *ln_start, *ln_end;
	int ret;

	while(count > 0)
	{
		len = proc->wbuf_sz - proc->wpos;
		if(count < len)
			len = count;
		if(len == 0)
			return -EINVAL;
		
		if(copy_from_user(proc->wbuf + proc->wpos, data, len))
			return -EFAULT;
		proc->wpos += len;

		/* Pick out each possible line */
		for(ln_start = proc->wbuf;
			ln_start < proc->wbuf + proc->wpos &&
			( ln_end = (char *)memchr(ln_start, '\n', (size_t)(proc->wbuf + proc->wpos - ln_start)) );
			ln_start = ln_end + 1)
		{
			*ln_end = '\0';
			/* Parse and do operations on current line*/
			if(ln_end - ln_start > 0)
			{
				if((ret = dpi_rules_cmd_parse(rules, ln_start, proc)) < 0)
				{
					proc->wpos = 0;
					return ret;
				}
			}
		}
		/* Move the incomplete line data ahead */
		if(ln_start > proc->wbuf)
		{
			if(ln_start < proc->wbuf + proc->wpos)
			{
				size_t remained = (size_t)(proc->wbuf + proc->wpos - ln_start);
				memmove(proc->wbuf, ln_start, remained);
				proc->wpos = remained;
			}
			else
				proc->wpos = 0;
		}
		
		data += len;
		count -= len;
	}

	return __count - count;
}

static inline size_t dpi_rules_show(
        rule_entry_t *rule,
		struct buffer_s ***curpp, 
		unsigned long edata )
{
	struct buffer_s **curp = *curpp;
	char s1[20], s2[20];
	//char line[50];
	size_t len;
	char *dp;

	if((*curp = (struct buffer_s *)kzalloc(sizeof(struct buffer_s), GFP_KERNEL)) == NULL)
		return 0;
	(*curp)->next = NULL;

    dp = (*curp)->line;
    sprintf(dp, "target:%s,type:%d,action:%d,id:%d,rule_idx:%d,ref:%d,protect_rw:%x,tpnc:%d\n", \
            rule->name, rule->type,rule->action,rule->id,rule->rule_idx, rule->ref, rule->protect_rw, rule->tpnc);
    dp += strlen(dp);
    //sprintf(dp, "\n");
//    LOG_INFO("==[%s]\n",dp);
	len = (*curp)->len = strlen((*curp)->line);
	*curpp = &(*curp)->next;

	return len;
}

static char *dpi_rules_show_mem(dpi_rules_t *rules, size_t *lenp)
{
	int i;
	unsigned long __edata = 0;
	struct buffer_s *head = NULL, **curp = &head, *cur, *cur_next;
	char *data;
	size_t len = 0, wpos;
    LOG_INFO("===dpi_rules_show_mem\n");

    rule_entry_t *entrys = NULL;
	rcu_read_lock();
	entrys = rcu_dereference(rules->entrys);
    for (i = 0; i < DPI_RULES_MAX_COUNT && entrys[i].name[0] != '\0'; i++) {
        len += dpi_rules_show(entrys + i, &curp,  __edata);
    }
	/* It won't actually get here */
	rcu_read_unlock();




	if(len == 0)
	{
		*lenp = len;
		return NULL;
	}
	if((data = (char *)kmalloc(len, GFP_KERNEL)) == NULL)
	{
		for(cur = head; cur; cur = cur_next)
		{
			cur_next = cur->next;
			kfree(cur);
		}
		*lenp = len;
		return NULL;
	}
	for(cur = head, wpos = 0; cur; cur = cur_next)
	{
		cur_next = cur->next;
		if(!(wpos < len))
			break;
		memcpy(data + wpos, cur->line, cur->len);
		wpos += cur->len;
		kfree(cur);
	}
	*lenp = len;
	return data;
}

static ssize_t dpi_rules_proc_read(struct file *file, char __user *data, size_t count, loff_t *f_pos)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	dpi_rules_t *rules = (dpi_rules_t *)OSEC_PDE_DATA(inode);
	struct dpi_rules_proc *proc = (struct dpi_rules_proc *)file->private_data;
	size_t len;

    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

	if(proc->rbuf == NULL)
	{
		/* ------------------------------------ */
		down_read(&rules->rwsem);
		proc->rbuf = dpi_rules_show_mem(rules, &proc->rbuf_len);
		up_read(&rules->rwsem);
		/* ------------------------------------ */
		proc->rpos = 0;
	}
	if((len = proc->rbuf_len - proc->rpos) == 0) {
		return 0;
    }
	if(count < len)
		len = count;
	
	if(copy_to_user(data, proc->rbuf + proc->rpos, len))
		return -EFAULT;
	proc->rpos += len;

	return len;
}

static int dpi_rules_proc_open(struct inode *inode, struct file *file)
{
	struct dpi_rules_proc *proc;
    	
	if((proc = (struct dpi_rules_proc *)kmalloc(sizeof(struct dpi_rules_proc), GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memset(proc, 0x0, sizeof(struct dpi_rules_proc));
	file->private_data = proc;
	proc->wbuf_sz = DPI_RULES_PROC_WBUF_SZ;
	proc->wpos = 0;
    LOG_INFO("success open acsm rules\n");
	return 0;
}

static int dpi_rules_proc_release(struct inode *inode, struct file *file)
{
	dpi_rules_t *rules = (dpi_rules_t *)OSEC_PDE_DATA(inode);
	struct dpi_rules_proc *proc = (struct dpi_rules_proc *)file->private_data;

	/* Parse the last unfinished line on close */
	if(proc->wpos > 0 && proc->wpos < proc->wbuf_sz)
	{
		proc->wbuf[proc->wpos] = '\0';
        if (rules)
		    dpi_rules_cmd_parse(rules, proc->wbuf, proc);
	}
	/* Release the read buffer on close */
	if(proc->rbuf)
		kfree(proc->rbuf);
	kfree(proc);
	file->private_data = NULL;
	return 0;
}

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static const struct proc_ops dpi_rules_proc_fops =
{
//	.owner   = THIS_MODULE,
	.proc_read   = dpi_rules_proc_read,
	.proc_write   = dpi_rules_proc_write,
	.proc_open    = dpi_rules_proc_open,
	.proc_release = dpi_rules_proc_release,
    .proc_lseek   = default_llseek,
};
#else
static const struct file_operations dpi_rules_proc_fops =
{
	.owner   = THIS_MODULE,
	.read   = dpi_rules_proc_read,
	.write   = dpi_rules_proc_write,
	.open    = dpi_rules_proc_open,
	.release = dpi_rules_proc_release,
    .llseek   = default_llseek,
};
#endif

static int dpi_state_tbl_init(void)
{
    DPI_State_TBL = kmalloc(sizeof(struct state_array)*DPI_STATE_TBL_MAX, GFP_ATOMIC | __GFP_ZERO);
    if (unlikely(DPI_State_TBL == NULL)) {
        LOG_INFO("DPI_State_TBL alloc fail\n");
        return -1;
    }    
    DPI_State_Flag_TBL = kmalloc(sizeof(int)*DPI_STATE_TBL_MAX, GFP_ATOMIC | __GFP_ZERO);
    if (unlikely(DPI_State_Flag_TBL == NULL)) {
        kfree(DPI_State_TBL);
        LOG_INFO("DPI_State_Flag_TBL alloc fail\n");
        return -1;
    }    

    LOG_INFO("dpi_state_tbl size is %lu byte\n", sizeof(struct state_array)*DPI_STATE_TBL_MAX);

    return 0;
}


int dpi_rules_init(struct proc_dir_entry *proc_parent)
{
    int retv = 0;
    dpi_rules.entrys = kmalloc(DPI_RULES_MAX_COUNT * sizeof(rule_entry_t), GFP_ATOMIC | __GFP_ZERO);
    if (dpi_rules.entrys == NULL) {
        return -1;
    }
    if ((retv = dpi_state_tbl_init()) != 0) 
    {
        LOG_INFO("dpi_state_tbl_ini fail==========\n");
        goto err1;
    }

	proc_create_data("rules", 0644, proc_parent, &dpi_rules_proc_fops, &dpi_rules);
    G_state_id_inc = 1;

    rules_init_finish = 1;
    LOG_INFO("dpi_rules_init finish\n");
    return retv;
err1:
    kfree(dpi_rules.entrys);
    return -1;
}

int dpi_rules_exit(struct proc_dir_entry *proc_parent)
{
    int retv = 0;
    if (rules_init_finish != 1) {
        return -1;
    }
    remove_proc_entry("rules", proc_parent);
    rule_entry_t *entrys = NULL;
    down_write(&dpi_rules.rwsem);
    entrys = dpi_rules.entrys;
    rcu_assign_pointer(entrys, NULL);
    synchronize_rcu();
    up_write(&dpi_rules.rwsem);
    kfree(dpi_rules.entrys);
    kfree(DPI_State_Flag_TBL);
    kfree(DPI_State_TBL);
    LOG_INFO("dpi_rules_exit finish\n");

    return retv;
}



rule_entry_t * get_rules_rcu_lock(void)
{
    rule_entry_t *entrys = NULL;
    rcu_read_lock();
    entrys = rcu_dereference(dpi_rules.entrys);
    return entrys;
}

