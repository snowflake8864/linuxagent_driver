#include <linux/list.h> // 提供 hlist_head 和 hlist_node
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/stat.h>
#include <linux/jiffies.h>
#include "core/kvd_memcache.h"
#include "core/gnkernel.h"
#include "gnHead.h"
#include "utils/utils.h"
#include "utils/var_proc.h"
#include "process_rules.h"

#define HASH_BITS 10
#define HASH_SIZE (1 << HASH_BITS)
static struct hlist_head process_hash[HASH_SIZE];
static rwlock_t hash_lock;

// 内存池
#define PROCESS_AUDIT_INFO_POOL_SIZE 1024
static struct kmem_cache *process_audit_info_pool;

// 哈希函数
static unsigned long _full_name_hash(const char *name)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *name++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash;
}

// 获取文件修改时间
static uint64_t get_file_mtime(const char *filename)
{
    struct path path;
    struct kstat stat;
    int rc;

    rc = kern_path(filename, LOOKUP_FOLLOW, &path);
    if (rc) {
        LOG_ERROR("Failed to get path for %s, error %d\n", filename, rc);
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    rc = vfs_getattr(&path, &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
    rc = vfs_getattr(&path, &stat);
#else
    rc = vfs_getattr(path.mnt, path.dentry, &stat);
#endif
    if (rc) {
        LOG_ERROR("Failed to get attributes for %s, error %d\n", filename, rc);
        path_put(&path);
        return 0;
    }

    path_put(&path);
    return (uint64_t)stat.mtime.tv_sec;
}

static inline void process_audit_info_get(struct process_audit_info *info)
{
    atomic_inc(&info->refcount);
}

// 减少引用计数并释放
static void process_audit_info_put(struct process_audit_info *info)
{
    if (atomic_dec_and_test(&info->refcount)) {
        //LOG_INFO("free process audit node del %s -> %*phN, timestamp:%lu,rule_mode:%d\n", info->path, 16, info->md5, info->timestamp, info->rule_mode);
        kvd_mem_cache_free(process_audit_info_pool, info);
    }
}

// 添加或更新进程审计信息
int add_or_update_audit_process_info(const char *path, const uint8_t *md5, uint8_t rule_mode)
{
    unsigned long key = _full_name_hash(path);
    struct process_audit_info *info;
    int bucket = key & (HASH_SIZE - 1); // 手动计算桶索引
    bool found = false;

    write_lock(&hash_lock);
    // 较旧内核，使用 hlist_for_each 手动访问
    struct hlist_node *node;
    hlist_for_each(node, &process_hash[bucket]) {
        info = hlist_entry(node, struct process_audit_info, hnode);
        if (strcmp(info->path, path) == 0) {
            if (memcmp(info->md5, md5, sizeof(info->md5)) != 0) {
                memcpy(info->md5, md5, sizeof(info->md5));
            }
            info->mtime = get_file_mtime(path);
            info->rule_mode = rule_mode;
            info->timestamp = jiffies;
            info->process_black_white_last_update_timestamp = process_black_white_last_update_timestamp;
            found = true;
            break;
        }
    }

    if (!found) {
        // 新记录
        info = kvd_mem_cache_zalloc(process_audit_info_pool, GFP_KERNEL);
        if (!info) {
            write_unlock(&hash_lock);
            return -ENOMEM;
        }
        strncpy(info->path, path, sizeof(info->path) - 1);
        info->path[sizeof(info->path) - 1] = '\0';
        memcpy(info->md5, md5, sizeof(info->md5));
        info->mtime = get_file_mtime(path);
        info->rule_mode = rule_mode;
        info->timestamp = jiffies;
        info->process_black_white_last_update_timestamp = process_black_white_last_update_timestamp;
        info->is_access_interval_gt_5s = 0;
        atomic_set(&info->refcount, 1);
        hlist_add_head(&info->hnode, &process_hash[bucket]);
    }
    write_unlock(&hash_lock);
    return 0;
}

// 获取进程审计信息
struct process_audit_info *get_process_audit_info(const char *path)
{
    unsigned long key = _full_name_hash(path);
    struct process_audit_info *info;
    int bucket = key & (HASH_SIZE - 1);

    read_lock(&hash_lock);
    struct hlist_node *node;
    hlist_for_each(node, &process_hash[bucket]) {
        info = hlist_entry(node, struct process_audit_info, hnode);
        if (strcmp(info->path, path) == 0) {
            process_audit_info_get(info);
            info->is_access_interval_gt_5s = (jiffies - info->timestamp > 5 * HZ);
            if (info->is_access_interval_gt_5s)
                info->timestamp = jiffies;
            read_unlock(&hash_lock);
            return info;
        }
    }
    read_unlock(&hash_lock);
    return NULL;
}

// 获取进程 MD5
int get_process_md5(const char *path, uint8_t *md5)
{
    unsigned long key = _full_name_hash(path);
    struct process_audit_info *info;
    int bucket = key & (HASH_SIZE - 1);

    read_lock(&hash_lock);
    struct hlist_node *node;
    hlist_for_each(node, &process_hash[bucket]) {
        info = hlist_entry(node, struct process_audit_info, hnode);
        if (strcmp(info->path, path) == 0) {
            memcpy(md5, info->md5, sizeof(info->md5));
            read_unlock(&hash_lock);
            return 0;
        }
    }
    read_unlock(&hash_lock);
    return -ENOENT;
}

// 获取进程规则模式和访问间隔
int get_process_rule_mode_and_interval(const char *path, uint8_t *rule_mode, char **md5, uint8_t *is_access_interval_gt_5s)
{
    unsigned long key = _full_name_hash(path);
    struct process_audit_info *info;
    int bucket = key & (HASH_SIZE - 1);
    int retv = 0;

    read_lock(&hash_lock);
    struct hlist_node *node;
    hlist_for_each(node, &process_hash[bucket]) {
        info = hlist_entry(node, struct process_audit_info, hnode);
        if (strcmp(info->path, path) == 0) {
            *is_access_interval_gt_5s = (jiffies - info->timestamp > 600 * HZ);//
            if (*is_access_interval_gt_5s) {
                info->timestamp = jiffies;
                if (info->mtime != get_file_mtime(path)) {
                    retv = 0;
                    goto out;
#if 0                    
                } else {
                    if (info->rule_mode == 1) {
                        retv = 0;
                    }
#endif                    
                }
            }

            if (unlikely(info->process_black_white_last_update_timestamp != process_black_white_last_update_timestamp)) {
                retv = 2; //black or white rules will modify
                *md5 = info->md5;
            } else {
                retv = 1;
            }
            *rule_mode = info->rule_mode;
            break;
        }
    }
out:
    read_unlock(&hash_lock);
    return retv;
}

// 打印所有进程信息
void find_all_process_info(void)
{
    struct process_audit_info *info;
    int bucket, count = 0;

    read_lock(&hash_lock);
    for (bucket = 0; bucket < HASH_SIZE; bucket++) {
        struct hlist_node *node;
        hlist_for_each(node, &process_hash[bucket]) {
            info = hlist_entry(node, struct process_audit_info, hnode);
            count++;
            LOG_SHOW("%s -> %*phN, timestamp:%lu,rule_mode:%d\n", info->path, 16, info->md5, info->timestamp, info->rule_mode);
        }
    }
    read_unlock(&hash_lock);
    LOG_SHOW("Total %d process info entries\n", count);
}

// 删除单个进程审计信息
static void delete_process_audit_info(const char *path)
{
    unsigned long key = _full_name_hash(path);
    struct process_audit_info *info;
    struct hlist_node *node, *tmp;
    int bucket = key & (HASH_SIZE - 1);

    write_lock(&hash_lock);
    hlist_for_each_safe(node, tmp, &process_hash[bucket]) {
        info = hlist_entry(node, struct process_audit_info, hnode);
        if (strcmp(info->path, path) == 0) {
            hlist_del(&info->hnode);
            process_audit_info_put(info);
            break;
        }
    }
    write_unlock(&hash_lock);
}

// 删除所有进程审计信息
void delete_all_process_audit_info(void)
{
    struct process_audit_info *info;
    struct hlist_node *node, *tmp;
    int bucket;

    write_lock(&hash_lock);
    for (bucket = 0; bucket < HASH_SIZE; bucket++) {
        hlist_for_each_safe(node, tmp, &process_hash[bucket]) {
            info = hlist_entry(node, struct process_audit_info, hnode);
            hlist_del(&info->hnode);
            //LOG_INFO("%s -> %*phN, timestamp:%lu,rule_mode:%d\n", info->path, 16, info->md5, info->timestamp, info->rule_mode);
            process_audit_info_put(info);
        }
    }
    write_unlock(&hash_lock);
}
// 删除所有进程审计信息
static void update_all_process_info(void)
{
    struct process_audit_info *info;
    struct hlist_node *node, *tmp;
    int bucket;

    write_lock(&hash_lock);
    for (bucket = 0; bucket < HASH_SIZE; bucket++) {
        hlist_for_each_safe(node, tmp, &process_hash[bucket]) {
            info = hlist_entry(node, struct process_audit_info, hnode);
            if (jiffies - info->timestamp > 3600 * HZ) {
                hlist_del(&info->hnode);
                //LOG_INFO("update del %s -> %*phN, timestamp:%lu,rule_mode:%d\n", info->path, 16, info->md5, info->timestamp, info->rule_mode);
                process_audit_info_put(info);
                continue;
            }
            info->mtime = 0;
            info->timestamp = (jiffies - (310 * HZ));
        }
    }
    write_unlock(&hash_lock);
}

// 命令解析
static int rules_cmd_parse(char *cmd)
{
    trim_spaces(cmd);
    if (strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0) {
        delete_all_process_audit_info();
        return 0;
    } else if (strncmp(cmd, "show", 4) == 0) {
        LOG_SHOW("show:%s\n", cmd);
        find_all_process_info();
    }else if (strncmp(cmd, "update", 6) == 0) {
        LOG_INFO("update:%s\n", cmd);
        update_all_process_info();
    }

    return 0;
}

// 进程规则操作
static int __process_rules_build(char *buf, size_t buf_sz, void *info)
{
    memset(buf, 0, buf_sz);
    return 0;
}

static int __process_rules_parse(const char *buf, void *info)
{
    char *cmd = kstrdup(buf, GFP_KERNEL);
    if (!cmd)
        return -ENOMEM;
    int ret = rules_cmd_parse(cmd);
    kfree(cmd);
    return ret;
}

static struct var_proc_info process_rules_vinfo = {
    .parse = __process_rules_parse,
    .build = __process_rules_build,
};

// 模块初始化
int process_audit_init(struct proc_dir_entry *proc_parent)
{
    int i;

    rwlock_init(&hash_lock);
    // 初始化哈希表
    for (i = 0; i < HASH_SIZE; i++)
        INIT_HLIST_HEAD(&process_hash[i]);

    process_audit_info_pool = kvd_mem_cache_create("process_audit_info_cache", sizeof(struct process_audit_info), 0);
    if (!process_audit_info_pool) {
        LOG_ERROR("Failed to create process_audit_info_pool\n");
        return -ENOMEM;
    }

    var_proc_create("process_rt", proc_parent, &process_rules_vinfo);
    LOG_INFO("Process audit module loaded\n");
    return 0;
}

// 模块退出
void process_audit_exit(struct proc_dir_entry *proc_parent)
{
    delete_all_process_audit_info();
    if (process_audit_info_pool) {
        kvd_mem_cache_destroy(process_audit_info_pool);
        process_audit_info_pool = NULL;
    }
    var_proc_remove("process_rt", proc_parent);
    LOG_INFO("Process audit module unloaded\n");
}

