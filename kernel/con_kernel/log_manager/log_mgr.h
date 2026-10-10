#ifndef __KERNEL_LOG_MGR_H__
#define __KERNEL_LOG_MGR_H__
// 声明一个日志等级变量
extern int osec_log_level;

#define LOG_ERROR(fmt, args...) \
    do { \
        if (osec_log_level >= 1) \
            printk(KERN_ERR "osec [ERROR][%s][%d]: " fmt, __FUNCTION__, __LINE__, ##args); \
    } while (0)

#define LOG_WARN(fmt, args...) \
    do { \
        if (osec_log_level >= 2) \
            printk(KERN_WARNING "osec [WARN ][%s][%d]: " fmt, __FUNCTION__, __LINE__, ##args); \
    } while (0)

#define LOG_DEBUG(fmt, args...) \
    do { \
        if (osec_log_level >= 3) \
            printk(KERN_DEBUG "osec [DEBUG ][%s][%d]: " fmt, __FUNCTION__, __LINE__, ##args); \
    } while (0)

#define LOG_INFO(fmt, args...) \
    do { \
        if (osec_log_level >= 4) \
            printk(KERN_INFO "osec [INFO ][%s][%d]: " fmt, __FUNCTION__, __LINE__, ##args); \
    } while (0)
#define LOG_SHOW(fmt, args...) \
    do { \
        printk(KERN_INFO "osec [SHOW ][%s][%d]: " fmt, __FUNCTION__, __LINE__, ##args); \
    } while (0)


int log_manager_init(void); 
void log_manager_exit(void); 
#endif

