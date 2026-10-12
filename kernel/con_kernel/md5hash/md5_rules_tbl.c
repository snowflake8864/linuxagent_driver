#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/crypto.h>
#include <linux/rcupdate.h> // RCU support
#include "core/kvd_memcache.h"
#include "core/gnkernel.h"
#include "gnHead.h"
#include "utils/utils.h"
#include "utils/var_proc.h"
#include "defense/defense_inner.h"
#include "md5_rules_tbl.h"

#define MD5_HASH_SIZE 16  // MD5 hash size in bytes
#define ACTION_SIZE 256   // Size of the action string

// MD5 entry structure
struct md5_entry {
    u8 md5[MD5_HASH_SIZE];
    u8 action; // 0: white, 1: black, 2: undefined
    struct list_head list; // Use list_head instead of hlist_node
    struct rcu_head rcu;   // RCU callback for delayed free
};

#define HASH_TABLE_SIZE 2048

unsigned long process_black_white_last_update_timestamp;
static int md5_count = 0;

// Hash table using list_head
static struct list_head md5_table[HASH_TABLE_SIZE];
static DEFINE_SPINLOCK(md5_lock); // Protect write operations
static struct kmem_cache *md5_entry_cache;

// Improved hash function
static unsigned int hash_md5(const u8 *md5) {
    unsigned int hash = 0;
    int i;
    for (i = 0; i < MD5_HASH_SIZE; i++) {
        hash = (hash * 31 + md5[i]) % HASH_TABLE_SIZE; // Better distribution
    }
    return hash;
}

// Insert a new MD5 entry with RCU protection
static int insert_md5_action(const u8 *md5, const u8 action)
{
    struct md5_entry *entry;
    unsigned int hash_index = hash_md5(md5);

    // Check if the MD5 already exists
    rcu_read_lock();
    struct md5_entry *tmp;
    list_for_each_entry_rcu(tmp, &md5_table[hash_index], list) {
        if (memcmp(tmp->md5, md5, MD5_HASH_SIZE) == 0) {
            rcu_read_unlock();
            LOG_INFO("MD5 already exists: %*phN, updating action to %d\n", 16, md5, action);
            tmp->action = action; // Update action value
            return 0; // Already exists, update and return
        }
    }
    rcu_read_unlock();

    // Allocate a new entry
    entry = kvd_mem_cache_zalloc(md5_entry_cache, GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    memcpy(entry->md5, md5, MD5_HASH_SIZE);
    entry->action = action;

    spin_lock(&md5_lock);
    list_add_rcu(&entry->list, &md5_table[hash_index]); // Add with RCU
    spin_unlock(&md5_lock);

    //LOG_INFO("Inserted new MD5: %*phN, action: %d\n", 16, md5, action);
    return 0;
}

// Find an MD5 entry using RCU
int find_md5_action(const u8 *md5)
{
    struct md5_entry *entry;
    unsigned int hash_index = hash_md5(md5);

    rcu_read_lock();
    list_for_each_entry_rcu(entry, &md5_table[hash_index], list) {
        if (memcmp(entry->md5, md5, MD5_HASH_SIZE) == 0) {
            rcu_read_unlock();
            return entry->action; // Found matching action
        }
    }
    rcu_read_unlock();
    return 2; // Not found
}

// Show all MD5 entries using RCU
static void show_all_md5_actions(void)
{
    struct md5_entry *entry;
    int i;
    int count = 0;

    rcu_read_lock();
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        list_for_each_entry_rcu(entry, &md5_table[i], list) {
            LOG_SHOW("MD5: %*phN, value: %d\n", 16, entry->md5, entry->action);
            ++count;
        }
    }
    rcu_read_unlock();

    md5_count = count;
    LOG_SHOW("Total MD5 count: %d\n", count);
}

// Delete a single MD5 entry with RCU
static int delete_md5_action(const u8 *md5, const uint8_t action)
{
    struct md5_entry *entry;
    unsigned int hash_index = hash_md5(md5);

    spin_lock(&md5_lock);
    list_for_each_entry_rcu(entry, &md5_table[hash_index], list) {
        if (memcmp(entry->md5, md5, MD5_HASH_SIZE) == 0) {
            if (likely(action == entry->action)) {
                list_del_rcu(&entry->list); // Remove from the list with RCU
                kfree_rcu(entry, rcu);      // Delayed free using RCU
            }
            spin_unlock(&md5_lock);
            //LOG_INFO("Deleted MD5: %*phN\n", 16, md5);
            return 0; // Successfully deleted
        }
    }
    spin_unlock(&md5_lock);
    LOG_ERROR("Failed to delete MD5: %*phN (not found)\n", 16, md5);
    return -ENOENT; // Not found
}

// Delete all MD5 entries safely with RCU
static void delete_all_md5_actions(void)
{
    struct md5_entry *entry, *tmp;
    int i, count = 0;
    
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        spin_lock(&md5_lock);
        list_for_each_entry_safe(entry, tmp, &md5_table[i], list) {
            list_del_rcu(&entry->list); // Remove from the list with RCU
            kfree_rcu(entry, rcu);      // Delayed free using RCU
            ++count;
            //LOG_INFO("Deleted MD5: %*phN\n", 16, entry->md5);
        }
        spin_unlock(&md5_lock);
    }

    synchronize_rcu(); // Wait for all readers to finish
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
    rcu_barrier();
#endif
    LOG_INFO("Deleted MD5 count:%d\n", count);
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

// Parse input and split MD5 and action
static int split_md5(const char *input, uint8_t *md5, uint8_t *number)
{
    int i;
    char *equals_sign = strchr(input, '=');
    if (!equals_sign) {
        LOG_ERROR("Invalid input: no '=, found\n");
        return -EINVAL;  // 输入无效
    }

    if (equals_sign - input != 32) {
        LOG_ERROR("Invalid input: MD5 length is not 32 characters[%s]\n", input);
        return -EINVAL;
    }

    for (i = 0; i < 32; i++) {
        if (!isxdigit(input[i])) {
            LOG_ERROR("Invalid input: non-hexadecimal character found\n");
            return -EINVAL;
        }
    }

    if (hex2bin(md5, input, MD5_HASH_SIZE) != 0) {
        LOG_INFO("Failed to convert MD5 string to binary\n");
        return -EINVAL;
    }

    *number = (uint8_t)simple_strtoul(equals_sign + 1, NULL, 10);
    return 0;  // 成功
}

// Command parser
static int md5_cmd_parse(char *cmd)
{
    trim_spaces(cmd);

    // Clear all MD5 rules
    if (strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0) {
        if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) != 0) {
            return -EINVAL;
        }

        set_md5_load_status();
        LOG_INFO("Clear all MD5 rules\n");
        delete_all_md5_actions();

        process_black_white_last_update_timestamp = jiffies;
        return 0;
    }
    // Show all MD5 rules
    else if (strncmp(cmd, "show", 4) == 0) {
        LOG_INFO("Show all MD5 rules\n");
        show_all_md5_actions();
    }
    // Finish MD5 load
    else if (strncmp(cmd, "finish", 6) == 0) {
        LOG_INFO("Finish MD5 load\n");
        clear_md5_load_status();
    }
    // Delete a single MD5 rule

    else if (strncmp(cmd, "del ", 4) == 0) {
        if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) != 0) {
            return -EINVAL;
        }

        u8 md5[MD5_HASH_SIZE];
        char *args = cmd + 4; // Skip "del "

        // Trim leading spaces
        while (*args == ' ') {
            args++;
        }

        // Expecting format: "0 <md5>" or "1 <md5>"
        if (args[0] != '0' && args[0] != '1') {
            LOG_ERROR("Invalid action value in del command: %s\n", args);
            return -EINVAL;
        }

        uint8_t action = args[0] - '0';

        // Skip action and following spaces
        char *md5_str = args + 1;
        while (*md5_str == ' ') {
            md5_str++;
        }

        if (strlen(md5_str) != 32 || hex2bin(md5, md5_str, MD5_HASH_SIZE) != 0) {
            LOG_ERROR("Invalid MD5 format for deletion: %s\n", md5_str);
            return -EINVAL;
        }

        int ret = delete_md5_action(md5, action);
        if (ret == 0) {
            process_black_white_last_update_timestamp = jiffies;
            LOG_INFO("Deleted MD5 (action=%u): %*phN\n", action, MD5_HASH_SIZE, md5);
        } else {
            LOG_ERROR("Failed to delete MD5 (action=%u): %*phN (not found)\n", action, MD5_HASH_SIZE, md5);
        }
        return ret;
    }

    // Insert a new MD5 rule
    else {
        if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) != 0) {
            return -EINVAL;
        }

        u8 md5[MD5_HASH_SIZE];
        uint8_t action;
        int ret = split_md5(cmd, md5, &action);
        if (ret != 0) {
            LOG_ERROR("Failed to parse input[%s]\n", cmd);
            return -1;
        }

        insert_md5_action(md5, action);
        process_black_white_last_update_timestamp = jiffies;
    }

    return 0;
}

// Build output for /proc file
static int __md5_rules_build(char *buf, size_t buf_sz, void *info)
{
    memset(buf, 0, buf_sz);
    int ret = 0;
    ret += snprintf(buf + ret, buf_sz - ret, "Total MD5 count: %d\n", md5_count);
    return 0;
}

// Parse input from /proc file
static int __md5_rules_parse(const char *buf, void *info)
{
    return md5_cmd_parse((char *)buf);
}

static struct var_proc_info md5_rules_vinfo =
{
    .parse = __md5_rules_parse,
    .build = __md5_rules_build,
};

// Module initialization
int md5_rules_init(struct proc_dir_entry *proc_parent)
{
    LOG_INFO("Md5 rules info module loaded\n");

    int i;

    // Initialize hash table
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        INIT_LIST_HEAD(&md5_table[i]);
    }

    // Create memory pool
    md5_entry_cache = kvd_mem_cache_create("md5_entry_cache", sizeof(struct md5_entry), 0);
    if (!md5_entry_cache) {
        LOG_INFO("Failed to create md5_entry_cache\n");
        return -1;
    }

    var_proc_create("md5_rt", proc_parent, &md5_rules_vinfo);
    return 0;
}

// Module cleanup
void md5_rules_exit(struct proc_dir_entry *proc_parent)
{
    // Cleanup all entries
    delete_all_md5_actions();

    // Destroy memory pool
    kvd_mem_cache_destroy(md5_entry_cache);

    LOG_INFO("MD5 module unloaded\n");

    var_proc_remove("md5_rt", proc_parent);
}
