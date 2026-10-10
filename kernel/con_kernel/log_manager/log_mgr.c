#include <linux/module.h>
#include "gnHead.h"
#include "utils/utils.h"
#include "utils/var_proc.h"
#include "log_mgr.h"
extern struct proc_dir_entry *proc_osec;
int osec_log_level = 1;
static uint _log_mamager_timer_on = 0;
struct timer_list log_manager_timer;
static int __log_level_parse(const char *buf, void *info)
{

    if (sscanf(buf, "%d", &osec_log_level) == 1) {
        if (osec_log_level > 4) {
            printk("log manager_module: invalid log level value\n");
            osec_log_level = 0;
        } 
    } 
    return 0;
}

/*
 * Operations for setting or displaying block gateway.
 */
static int __log_level_build(char *buf, size_t buf_sz, void *info)
{
    memset(buf, 0, buf_sz);
    snprintf(buf, 1024,  "kernel log level: %u\n", osec_log_level);
    return 0;
}

static struct var_proc_info log_level_vinfo =
{
    .parse = __log_level_parse,
    .build = __log_level_build,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static void log_manager_timer_function(struct timer_list *timer)
#else
static void log_manager_timer_function(unsigned long unused)
#endif
{
    osec_log_level = 0;
}



int log_manager_init(void) 
{
    LOG_INFO("log manager module loaded\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    timer_setup(&log_manager_timer, log_manager_timer_function, 0);
#else
    setup_timer(&log_manager_timer, log_manager_timer_function, 0);
#endif
    mod_timer(&log_manager_timer, jiffies + 15 * HZ);  
     (void)xchg(&_log_mamager_timer_on,1);
    var_proc_create("log_level", proc_osec, &log_level_vinfo);	
    return 0;
}

void log_manager_exit(void) 
{
   // osec_log_level = 4;
    var_proc_remove("log_level", proc_osec);
    if(xchg(&_log_mamager_timer_on,0)) {
        del_timer_sync(&log_manager_timer); 
        LOG_INFO("stop log manager timer===============================\n");
    }

}

