#ifndef __GNKERNEL_H__
#define __GNKERNEL_H__
#include <linux/types.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/notifier.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
#include <linux/sched.h>
#endif

#include "config.h"

#include "gnHead.h"
#include "flag_cache.h"

#include "core/kvd_core.h" //for bool

int is_self_process(void);
int is_self_process2(pid_t pid);
bool is_self_comm(void);
int is_system_process(struct task_struct *tsk);

bool is_white_box_test(void);

int  gnkernel_init(int protocol,const char* cdev_name);
void gnkernel_exit(void);

typedef int (*vsec_con_cb_fn_t)(void* , int );
typedef struct vsec_con_cb_s {
    NLPolicyType index;
    vsec_con_cb_fn_t pfunc;
} vsec_con_cb_t;

typedef struct vsec_con_cb_set_s {
    vsec_con_cb_t* pcallbacks;
    int ncount;
} vsec_con_cb_set_t;

int send_nl_data(int cmd, void* data, int nsize);
int send_nowait_nl_data(int cmd, void * data, int nsize);
int send_wait_nl_data(int cmd, void* data, int nsize, void** ppwait, void* extra);
int send_nl_data_callback(int cmd, void* data, int nsize, void** ppwait, void* extra, Tkerncallback callback);

int register_notify_callback(vsec_con_cb_t* pcon_callback, int count);
int unregister_notify_callback(vsec_con_cb_t* pcon_callback);

typedef void (*tlv_proto_fn_t)(void* data,size_t data_len);
typedef struct vsec_tlv_proto_cb_s {
    u_char pt; //product type
    tlv_proto_fn_t pfunc;
} vsec_tlv_proto_cb_t;

//只能在模块初始化时进行调用
int register_tlv_proto_callback(vsec_tlv_proto_cb_t* pcb);

//不支持在运行中调用
int unregister_tlv_proto_callback(vsec_tlv_proto_cb_t* pcb);

//product notify action
enum {
    PTN_ACTION_REG = 1,
    PTN_ACTION_UNREG = 2,
};
typedef struct {
    u_int product; //NL_PRODUCTION_XXX
    u_char action; //PTN_ACTION_XX
}product_notify_t;

int register_product_notifier(struct notifier_block* notifier);
void unregister_product_notifier(struct notifier_block* notifier);

//ECHO指令通知类型
enum {
    ECN_SET_PID = 1, //set port id
    ECN_CLEAR_PID = 2, //clear port-id
    ECN_SET_DEBUG = 3,//set debug flag
};

typedef struct {
    u_int portid;
    u_int pid;
} ecn_data_pid_t;

int register_echo_notifier(struct notifier_block* notifier);
void unregister_echo_notifier(struct notifier_block* notifier);
u32 get_snd_portid(void);
pid_t get_service_pid(void);
void clear_portid_service_pid(void);

extern u_int warn_dump_stack;
#define KOSEC_WARN_ON(fmt,msg...) do { \
    printk("warning at %s:%d/%s;"fmt, __FILE__, __LINE__, __FUNCTION__,##msg); \
	if (warn_dump_stack) { dump_stack(); } \
} while (0)

extern const char* __hook_mode;
extern unsigned long process_black_white_last_update_timestamp;
#endif
