#include "gnHead.h"
#include "utils/utils.h"
#include "utils/var_proc.h"
#include "docker_rules.h"
#include "defense/defense_inner.h"

#define MAX_PID_COUNT 4194305
#define MAX_DOCKER_PIDS 512  // 最大 PID 数量限制
#define BITMAP_SIZE (MAX_PID_COUNT / 32)

static spinlock_t pid_locks[BITMAP_SIZE];  // 每个索引一个锁
static atomic_t pid_count = ATOMIC_INIT(0);  // 使用原子变量管理 PID 计数
static uint32_t pidBitMap[BITMAP_SIZE];
static uint32_t docker_pids[MAX_DOCKER_PIDS];  // 固定数组存储 PID
static uint32_t docker_root_pid;
static uint8_t docker_version;
static uint8_t pid_count_v1;

// 初始化锁
void init_docker_pid_locks(void)
{
    int i;
    for (i = 0; i < BITMAP_SIZE; i++) {
        spin_lock_init(&pid_locks[i]);
    }
}

static int pid_to_index(int pid) {
    return pid / 32;
}

// 获取当前使用的 PID 数量
uint32_t get_docker_pid_count(void) {
    return atomic_read(&pid_count);
}

// 将位图中的特定位设置为1，并记录 PID
void set_docker_pid(uint32_t pid)
{
    int index = pid_to_index(pid);
    int bit = pid % 32;
    spin_lock(&pid_locks[index]);  // 获取对应索引的锁

    if (!(pidBitMap[index] & (1 << bit))) {  // 如果该位原来是 0
        if (atomic_read(&pid_count) >= MAX_DOCKER_PIDS) {
            spin_unlock(&pid_locks[index]);
            LOG_ERROR("PID limit reached: %u\n", MAX_DOCKER_PIDS);
            return;
        }
        pidBitMap[index] |= 1 << bit;

        // 添加到数组
        int new_count = atomic_inc_return(&pid_count);
        docker_pids[new_count - 1] = pid;
    }

    spin_unlock(&pid_locks[index]);  // 释放锁
}

// 清除指定 PID 在位图和数组中的标记
void clear_docker_pid(uint32_t pid)
{
    size_t i;
    int index = pid_to_index(pid);
    int bit = pid % 32;

    spin_lock(&pid_locks[index]);  // 获取对应索引的锁
    if (pidBitMap[index] & (1 << bit)) {  // 如果该位原来是 1
        pidBitMap[index] &= ~(1 << bit);

        // 从数组中移除
        int current_count = atomic_read(&pid_count);
        for (i = 0; i < current_count; i++) {
            if (docker_pids[i] == pid) {
                docker_pids[i] = docker_pids[--current_count];
                atomic_set(&pid_count, current_count);
                break;
            }
        }
    }
    spin_unlock(&pid_locks[index]);  // 释放锁
}

// 清除位图中所有的 PID 标记
void clear_all_docker_pids(void)
{
    int i;
    for (i = 0; i < BITMAP_SIZE; i++) {
        spin_lock(&pid_locks[i]);  // 获取对应索引的锁
        pidBitMap[i] = 0;
        spin_unlock(&pid_locks[i]);  // 释放锁
    }
    atomic_set(&pid_count, 0);  // 重置计数器
}

// 检查 PID 是否在位图中被标记为已使用
int is_docker_pid(uint32_t pid) {
    int ret = 0;
    int index = pid_to_index(pid);
    int bit = pid % 32;

    spin_lock(&pid_locks[index]);  // 获取对应索引的锁
    ret = (pidBitMap[index] & (1 << bit)) != 0;
    spin_unlock(&pid_locks[index]);  // 释放锁

    return ret;
}

int is_start_docker(void)
{
    return atomic_read(&pid_count) != 0;
}

int is_start_docker_v1(void)
{
    return pid_count_v1 > 0;
}

void start_docker_v1(void)
{
    pid_count_v1 = 1;
}

// 获取指定 PID 的状态（是否被使用）
int get_docker_pid_state(uint32_t pid)
{
    int index = pid_to_index(pid);
    int bit = pid % 32;
    int state;

    spin_lock(&pid_locks[index]);  // 获取对应索引的锁
    state = (pidBitMap[index] & (1 << bit)) != 0;
    spin_unlock(&pid_locks[index]);  // 释放锁

    return state;
}

void set_docker_root_pid(uint32_t pid)
{
    docker_root_pid = pid;
}

int is_docker_root_process(uint32_t pid)
{
    return docker_root_pid == pid && docker_root_pid > 5;
}

uint8_t get_docker_version(void)
{
    return docker_version;
}

void set_docker_version(uint8_t ver)
{
    docker_version = ver;
}

// 解析输入命令
static int split_docker_pid(const char *input, uint8_t *pid_type, uint8_t *op_type, uint32_t *pid)
{
    char *first_comma = strchr(input, ',');
    if (!first_comma) {
        LOG_ERROR("Invalid input: no first ',' found\n");
        return -EINVAL;  // 输入无效
    }

    char *second_comma = strchr(first_comma + 1, ',');
    if (!second_comma) {
        LOG_ERROR("Invalid input: no second ',' found\n");
        return -EINVAL;  // 输入无效
    }

    // 解析 pid_type
    char *type_end = NULL;
    *pid_type = (uint8_t)simple_strtoul(input, &type_end, 10);
    if (type_end == input || type_end != first_comma) {
        LOG_ERROR("Invalid input: pid_type is not a valid number\n");
        return -1;
    }

    // 解析 op_type
    char *op_end = NULL;
    *op_type = (uint8_t)simple_strtoul(first_comma + 1, &op_end, 10);
    if (op_end == first_comma + 1 || op_end != second_comma) {
        LOG_ERROR("Invalid input: op_type is not a valid number\n");
        return -1;
    }

    // 解析 pid
    char *pid_end = NULL;
    *pid = (uint32_t)simple_strtoul(second_comma + 1, &pid_end, 10);
    if (pid_end == second_comma + 1 /* || *pid == 0 */) {
        LOG_ERROR("Invalid input: PID is out of range or not a valid number\n");
        return -1;
    }

    return 0;  // 成功
}

// 命令解析函数
static int rules_cmd_parse(char *cmd)
{
    trim_spaces(cmd);
    if (strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0) {
        LOG_INFO("clear pids:%s\n", cmd);
        clear_all_docker_pids();
        return 0;
    } else {
        LOG_INFO("load:%s\n", cmd);

        uint32_t pid;
        uint8_t pid_type;
        uint8_t op_type;

        if (likely(split_docker_pid(cmd, &pid_type, &op_type, &pid) == 0)) {
            switch (pid_type) {
                case 1: // root pid
                    set_docker_root_pid(pid);
                    docker_version = pid_type;
                    pid_count_v1 = 1;
                    break;

                case 2: // add or remove docker pid
                    if (op_type == 1) {
                        set_docker_pid(pid);
                    } else {
                        clear_docker_pid(pid);
                    }
                    docker_version = pid_type;
                    break;

                case 3: // only set root pid
                    set_docker_root_pid(pid);
                    break;

                case 4:
                    pid_count_v1 = 0;
                    break;
            }
        }
    }

    return 0;
}

// 构建规则信息
static int __process_rules_build(char *buf, size_t buf_sz, void *info)
{
	
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

    memset(buf, 0, buf_sz);
    int ret = 0, i;

    ret += snprintf(buf + ret, buf_sz - ret, "Docker version: %u\n", docker_version);
    ret += snprintf(buf + ret, buf_sz - ret, "Docker Root PID: %u\n", docker_root_pid);

    if (docker_version == 2) {
        ret += snprintf(buf + ret, buf_sz - ret, "Docker Container Count: %u\n", atomic_read(&pid_count));
    } else if (docker_version == 1) {
        ret += snprintf(buf + ret, buf_sz - ret, "Docker Container Count: %d\n", pid_count_v1);
    }

    if (docker_version == 2) {
        ret += snprintf(buf + ret, buf_sz - ret, "Docker Container PID:\n");
        int current_count = atomic_read(&pid_count);
        for (i = 0; i < current_count; i++) {
            ret += snprintf(buf + ret, buf_sz - ret, "%u\n", docker_pids[i]);
        }
    }

    return 0;
}

// 解析规则信息
static int __process_rules_parse(const char *buf, void *info)
{
    if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) != 0) {
        return -EINVAL;
    }

    rules_cmd_parse((char *)buf);
    return 0;
}

static struct var_proc_info process_rules_vinfo =
{
    .parse = __process_rules_parse,
    .build = __process_rules_build,
};

// 初始化模块
int docker_audit_init(struct proc_dir_entry *proc_parent)
{
    LOG_INFO("Process info module loaded\n");
    init_docker_pid_locks();  // 初始化锁
    var_proc_create("docker_rt", proc_parent, &process_rules_vinfo);
    return 0;
}

// 卸载模块
void docker_audit_exit(struct proc_dir_entry *proc_parent)
{
    var_proc_remove("docker_rt", proc_parent);
}
