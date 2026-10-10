#include <linux/module.h>
#include "gnHead.h"
#include "utils/utils.h"
#include "utils/var_proc.h"
#include "module_ref.h"
#include <linux/atomic.h>
#include "defense/defense_inner.h"


extern struct proc_dir_entry *proc_osec;

static int split_cmd(const char *input, uint8_t *cmd, uint8_t *number) 
{
    int i;
    char *equals_sign = strchr(input, ' ');
    if (!equals_sign) {
        LOG_ERROR("Invalid input: no ' ', found\n");
        return -EINVAL;  // 输入无效
    }

    if (equals_sign - input >4) {
        LOG_ERROR("Invalid input: ref cmd length is biger characters[%s]\n", input);
        return -EINVAL;
    }

    strncpy(cmd, input, equals_sign - input);
    
    *number = (uint8_t)simple_strtoul(equals_sign + 1, NULL, 10);
    return 0;  // 成功
}
#if 0
static int rules_cmd_parse(char *cmd)
{
    uint8_t num;
    trim_spaces(cmd);
    if(strcmp(cmd, "c") == 0 || strncmp(cmd, "clear", 5) == 0) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
        atomic_set(&THIS_MODULE->refcnt, 0);
        LOG_INFO("test_module: refcount forced to 0, now %d\n",
                module_refcount(THIS_MODULE));
#endif
    } else if (strncmp(cmd, "inc", 3) == 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
        atomic_inc(&THIS_MODULE->refcnt);
#else
        try_module_get(THIS_MODULE);
#endif
        LOG_INFO("test_module: refcount incremented, now %d\n",
                module_refcount(THIS_MODULE));

    } else if (strncmp(cmd, "dec", 3) == 0) {
        if (module_refcount(THIS_MODULE) > 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
            atomic_dec(&THIS_MODULE->refcnt);
#else
        module_put(THIS_MODULE);
#endif
        }
    } 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    else if (sscanf(cmd, "add %d", &num) == 1) {
        if (num > 0) {
            atomic_add(num, &THIS_MODULE->refcnt);
            LOG_INFO("test_module: refcount increased by %d, now %d\n", 
                   num, module_refcount(THIS_MODULE));
        } else {
            LOG_INFO("test_module: invalid increment value\n");
        }
    } else if (sscanf(cmd, "sub %d", &num) == 1) {
        if (num > 0) {
            if (module_refcount(THIS_MODULE) >= num) {
                atomic_sub(num, &THIS_MODULE->refcnt);
                LOG_INFO("test_module: refcount decreased by %d, now %d\n", 
                        num, module_refcount(THIS_MODULE));
            } else {
                LOG_INFO("test_module: refcount %d too low to subtract %d\n", 
                        module_refcount(THIS_MODULE), num);
            }
        } else {
            LOG_INFO("test_module: invalid subtract value\n");
        }
    }
#endif


    return 0;
}
#else

static atomic_t logic_refcnt = ATOMIC_INIT(0);

static int rules_cmd_parse(char *cmd)
{
    int num;

    trim_spaces(cmd);

    /* clear */
    if (!strcmp(cmd, "c") || !strncmp(cmd, "clear", 5)) {

        int cur = atomic_xchg(&logic_refcnt, 0);

        while (cur-- > 0)
            module_put(THIS_MODULE);

        LOG_INFO("clear: logic=0 kernel=%lu\n",
                 module_refcount(THIS_MODULE));
    }

    /* inc */
    else if (!strncmp(cmd, "inc", 3)) {
        if (try_module_get(THIS_MODULE)) {
            atomic_inc(&logic_refcnt);
            LOG_INFO("inc: logic=%d kernel=%lu\n",
                     atomic_read(&logic_refcnt),
                     module_refcount(THIS_MODULE));
        }
    }

    /* dec */
    else if (!strncmp(cmd, "dec", 3)) {
        if (atomic_read(&logic_refcnt) > 0) {
            atomic_dec(&logic_refcnt);
            module_put(THIS_MODULE);
            LOG_INFO("dec: logic=%d kernel=%lu\n",
                     atomic_read(&logic_refcnt),
                     module_refcount(THIS_MODULE));
        }
    }

    /* add N */
    else if (sscanf(cmd, "add %d", &num) == 1 && num > 0) {
        int i;
        for (i = 0; i < num; i++) {
            if (try_module_get(THIS_MODULE))
                atomic_inc(&logic_refcnt);
        }
        LOG_INFO("add %d: logic=%d kernel=%lu\n",
                 num,
                 atomic_read(&logic_refcnt),
                 module_refcount(THIS_MODULE));
    }

    /* sub N */
    else if (sscanf(cmd, "sub %d", &num) == 1 && num > 0) {
        int i;
        int cur = atomic_read(&logic_refcnt);

        if (num > cur)
            num = cur;

        for (i = 0; i < num; i++) {
            atomic_dec(&logic_refcnt);
            module_put(THIS_MODULE);
        }
        LOG_INFO("sub %d: logic=%d kernel=%lu\n",
                 num,
                 atomic_read(&logic_refcnt),
                 module_refcount(THIS_MODULE));
    }

    return 0;
}

#endif
static int __process_ref_parse(const char *buf, void *info)
{
    if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) !=0) {
		return -EINVAL;
    }

    rules_cmd_parse(buf);
	return 0;
}

/*
 * Operations for setting or displaying block gateway.
 */
static int __process_ref_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

    memset(buf, 0, buf_sz);
    struct module* this = THIS_MODULE;
    u_int refcnt = module_refcount(this);
	snprintf(buf, 1024,  "ref: %u\n", refcnt);
	return 0;
}

static struct var_proc_info process_ref_vinfo =
{
	.parse = __process_ref_parse,
	.build = __process_ref_build,
};


int module_ref_init(void) 
{
    LOG_INFO("Process info module loaded\n");
	var_proc_create("module_ref", proc_osec, &process_ref_vinfo);	
    return 0;
}

void module_ref_exit(void) 
{
	var_proc_remove("module_ref", proc_osec);
}


