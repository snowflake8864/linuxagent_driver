#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/crypto.h>
//#include <linux/rwlock.h>
#include "core/kvd_memcache.h"
#include "gnHead.h"
#include "utils/utils.h"
#include "utils/var_proc.h"
#include "true_process_tbl.h"
#include "defense/defense_inner.h"


#define TRUE_RULE_SIZE 18  // MD5 hash size in bytes

struct true_process_entry {
    union {
        struct {
            u8 md5[16];
            u8 rule_id;
            u8 rule_type;
        };
        u8 key[TRUE_RULE_SIZE];
    };
    struct hlist_node node; // 哈希表的链表节点
};

#define HASH_TABLE_SIZE 1024

static struct hlist_head true_process_table[HASH_TABLE_SIZE];
static DEFINE_RWLOCK(true_process_lock);  // 定义读写锁
static struct kmem_cache *true_process_entry_cache; // 内存池


static unsigned int hash_md5_with_rule_id(const u8 *md5, const u8 rule_id, const u8 rule_type) {
    unsigned int hash = 0;
    int i;
    for (i = 0; i < 16; i++) {
        hash += (md5[i] << ((i % 4) * 8));  // 将md5每字节位移叠加
    }
    hash ^= rule_id;  // 将 rule_id 直接与hash值异或
    hash ^= rule_type; // 新增：将rule_type也与hash值异或

    return hash % HASH_TABLE_SIZE;
}

static int insert_true_process(const u8 *md5, const u8 rule_id, const u8 rule_type)
{
    struct true_process_entry *entry;
    unsigned int hash_index;


    // 先查找是否已存在相同的 md5 和 rule_id
    if (find_true_process(md5, rule_id, rule_type)) {
        LOG_INFO("MD5: %*phN, rule_id: %d already exists, skipping insert\n", 16, md5, rule_id);
        return -EEXIST;  // 返回已存在的错误码
    }

    entry = kvd_mem_cache_zalloc(true_process_entry_cache, GFP_KERNEL);
    if (!entry) {
        LOG_ERROR("true_process_entry_cache alloc fail\n");
        return -ENOMEM;
    }

    memcpy(entry->md5, md5, 16);
    entry->rule_id = rule_id;
    entry->rule_type = rule_type;

    hash_index = hash_md5_with_rule_id(md5, rule_id, rule_type);

    //LOG_INFO("Add MD5: %*phN, rule_id:%d\n", 16, md5, rule_id);
    write_lock(&true_process_lock);
    hlist_add_head(&entry->node, &true_process_table[hash_index]);
    write_unlock(&true_process_lock);

    return 0;
}

int find_true_process(const u8 *md5, const u8 rule_id, const u8 rule_type)
{
    struct true_process_entry *entry;
    struct hlist_node *node;

    unsigned int hash_index = hash_md5_with_rule_id(md5, rule_id, rule_type);

    read_lock(&true_process_lock);
    hlist_for_each(node, &true_process_table[hash_index]) {
        entry = hlist_entry(node, struct true_process_entry, node);
        if (memcmp(entry->md5, md5, 16) == 0 && entry->rule_id == rule_id && entry->rule_type == rule_type) {
            read_unlock(&true_process_lock);
            return 1; // 找到
        }
    }
    read_unlock(&true_process_lock);
    return 0; // 未找到
}

static void delete_all_true_process(void) 
{
    struct true_process_entry *entry;
    struct hlist_node *node;
    struct hlist_node *tmp;
    int i;

    write_lock(&true_process_lock);
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        hlist_for_each_safe(node, tmp, &true_process_table[i]) {
            entry = hlist_entry(node, struct true_process_entry, node);
            hlist_del(node); // 从哈希表中删除节点
            kvd_mem_cache_free(true_process_entry_cache, entry); // 释放条目内存
        }
        INIT_HLIST_HEAD(&true_process_table[i]); // 重新初始化哈希表
    }
    write_unlock(&true_process_lock);
}

static void show_all_true_process(void) 
{
    struct true_process_entry *entry;
    struct hlist_node *node;
    struct hlist_node *tmp;
    int i;

    read_lock(&true_process_lock);
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        hlist_for_each_safe(node, tmp, &true_process_table[i]) {
            entry = hlist_entry(node, struct true_process_entry, node);
            LOG_INFO("MD5: %*phN,value:%d\n",16, entry->md5, entry->rule_id);
        }
    }
    read_unlock(&true_process_lock);
}

static int is_valid_hex_char(char c) {
    return isxdigit(c);  // 检查是否为十六进制字符
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
#if 0
static int hex_to_bin(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;  // 非法字符
}
#endif

static int hex2bin(uint8_t *dst, const char *src, size_t count)
{
    int hi = 0, lo = 0;
    while (count--) {
        hi = hex_to_bin(*src++);
        lo = hex_to_bin(*src++);

        if (hi < 0 || lo < 0)
            return -EINVAL;  // 遇到非法字符

        *dst++ = (hi << 4) | lo;
    }
    return 0;
}

#endif
#if 0
static int split_md5(const char *input, uint8_t *md5, uint8_t *number) 
{
    int i;
    char *equals_sign = strchr(input, ',');
    if (!equals_sign) {
        LOG_ERROR("Invalid input: no ',, found\n");
        return -EINVAL;  // 输入无效
    }

    if (equals_sign - input != 32) {
        LOG_ERROR("Invalid input: MD5 length is not 32 characters\n");
        return -EINVAL;
    }

    for (i = 0; i < 32; i++) {
        if (!is_valid_hex_char(input[i])) {
            LOG_ERROR("Invalid input: non-hexadecimal character found\n");
            return -EINVAL;
        }
    }

    
    if (unlikely(hex2bin(md5, input, 16) != 0)) {
        LOG_INFO("Failed to convert MD5 string to binary\n");
        return -EINVAL;
    }


    *number = (uint8_t)simple_strtoul(equals_sign + 1, NULL, 10);
    //LOG_INFO("MD5: %*phN, number:%d\n",16, md5, *number);
    return 0;  // 成功
}
#else
static int split_md5(const char *input, uint8_t *md5, uint8_t *rule_id, uint8_t *rule_type) {
    char *md5_str_start = (char *)input; // 指向输入字符串的起始位置
    char *comma1, *comma2;
    char md5_str[33]; // MD5 是 32 位十六进制数，加一个空字符
    int i;
 
    // 查找第一个逗号
    comma1 = strchr(md5_str_start, ',');
    if (!comma1) {
        LOG_ERROR("Invalid input: no first comma found\n");
        return -EINVAL;
    }
 
    strncpy(md5_str, md5_str_start, comma1 - md5_str_start);
    md5_str[comma1 - md5_str_start] = '\0'; // 确保字符串以空字符结尾
 
    if (strlen(md5_str) != 32) {
        LOG_ERROR("Invalid input: MD5 length is not 32 characters\n");
        return -EINVAL;
    }
    for (i = 0; i < 32; i++) {
        if (!is_valid_hex_char(md5_str[i])) {
            LOG_ERROR("Invalid input: non-hexadecimal character found\n");
            return -EINVAL;
        }
    }

    
    if (unlikely(hex2bin(md5, md5_str, 16) != 0)) {
        LOG_INFO("Failed to convert MD5 string to binary\n");
        return -EINVAL;
    }


    // 移动指针到第一个逗号之后，查找第二个逗号
    comma1++; // 跳过第一个逗号
    comma2 = strchr(comma1, ',');
    if (!comma2) {
        LOG_ERROR("Invalid input: no second comma found\n");
        return -EINVAL;
    }
 
    // 提取 rule_id（第一个逗号到第二个逗号之间的部分）
    *rule_id = (uint8_t)simple_strtoul(comma1, (char **)&comma2, 10);
 
    // 提取 rule_type（第二个逗号之后的部分）
    comma2++; // 跳过第二个逗号
    *rule_type = (uint8_t)simple_strtoul(comma2, NULL, 10);
 
    // 注意：这里没有检查 simple_strtoul 的转换是否成功，也没有处理可能的溢出。
    // 在实际应用中，您应该添加这些错误检查。
 
    // 假设 hex2bin 调用成功（这里没有实现），并且 simple_strtoul 也成功。
    return 0; // 成功
}
#endif


static int __true_process_cmd_parse(char *cmd)
{
    LOG_INFO("true_process:[%s]\n",cmd);
    uint8_t md5[16];
    uint8_t rule_id, rule_type;
    int ret = split_md5(cmd, md5, &rule_id, &rule_type);
    if (ret != 0) {
        LOG_ERROR("Failed to parse input\n");
        return -1;
    }
    //int err = kstrtoint(cmd, 10, &cmd);
    LOG_INFO("MD5: %*phN,rule_id:%d,rule_type:%d\n",16, md5, rule_id,rule_type);
    insert_true_process(md5, rule_id, rule_type); 
    return 0;
}

static int true_process_cmd_parse(char *cmd)
{
    trim_spaces(cmd);
	if(strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0)
	{
        if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) !=0) {
            return -EINVAL;
        }

        LOG_INFO("delete all true process\n");
        delete_all_true_process();
		return 0;
	} if(strncmp(cmd, "show", 4) == 0) {
        LOG_INFO("show:%s\n",cmd);
        show_all_true_process();
    }else {
        if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) !=0) {
            return -EINVAL;
        }
        char *sp,*ln_start;
        for(ln_start = cmd; (sp = strchr(ln_start, '\n')); ln_start = sp + 1)
        {   
            *sp = '\0';
            trim(ln_start);
            if (ln_start[0] == '#')
                continue;
            if (__true_process_cmd_parse(ln_start) == 0) {

            }
        }
        if (ln_start != NULL) {
            trim(ln_start);
            if (__true_process_cmd_parse(ln_start) == 0) {
            }
        }

    }

    return 0;
}

/*
 * Operations for setting or displaying block gateway.
 */
static int __true_process_build(char *buf, size_t buf_sz, void *info)
{
    memset(buf, 0, buf_sz);
	return 0;
}
static int __true_process_parse(const char *buf, void *info)
{
    /*if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) !=0) {
        return -EINVAL;
    }
    */
    return true_process_cmd_parse(buf);
	//return 0;
}
static struct var_proc_info true_process_vinfo =
{
	.parse = __true_process_parse,
	.build = __true_process_build,
};


int true_process_init(struct proc_dir_entry *proc_parent) 
{
    LOG_INFO("Md5 rules info module loaded\n");

    int i;

    // 初始化哈希表
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        INIT_HLIST_HEAD(&true_process_table[i]);
    }

    // 创建内存池
    true_process_entry_cache = kvd_mem_cache_create("true_process_entry_cache", sizeof(struct true_process_entry), 0);
    if (!true_process_entry_cache) {
        LOG_INFO("Failed to create true_process_entry_cache\n");
        return -ENOMEM;
    }
	var_proc_create("true_process_rt", proc_parent, &true_process_vinfo);	
    return 0;
}

void true_process_exit(struct proc_dir_entry *proc_parent) 
{

    // 清理所有条目
    delete_all_true_process();
    // 销毁内存池
    kvd_mem_cache_destroy(true_process_entry_cache);

    LOG_INFO("true process module unloaded\n");
	var_proc_remove("true_process_rt", proc_parent);
}

