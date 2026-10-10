#include <linux/types.h>
#include <linux/sort.h>
#include "gnHead.h"
#include "gnkernel.h"
#include "flag_cache.h"
#include "core/kvd_core.h"

//运行模式
enum {
    RELEASE_MODE = 0, //发布模式
    WHITE_BOX_MODE, //白盒测试模式，只对内部测试公开
};

unsigned long debug_flag = 0;
u_int warn_dump_stack = 0;
static int run_mode = RELEASE_MODE;
const char* __hook_mode = "syscall-hook";

extern int check_snd_portid(u32 portid);
extern void set_portid_service_pid(u32 portid,pid_t pid);

static int handle_cmd_bool_end(void* data, int data_len)
{
    int rc = -1;
    void* pwait_flag;

    struct bool_info* pbinfo = (struct bool_info*)data;
    pwait_flag = pbinfo->pwait_flag;
    if (pwait_flag) {
        int *pBool = (int*)get_wait_extra(pwait_flag);
        if (pBool) {
            *pBool = pbinfo->bBool;
        }

        wake_wait_flag(pwait_flag);
        rc = 0;
    }

    return rc;
}


static int handle_cmd_md5rule_end(void* data, int data_len)
{
    int rc = -1;
    void* pwait_flag;

    md5_rules_item_t* pbinfo = (md5_rules_item_t*)data;
    pwait_flag = pbinfo->pwait_flag;
    if (pwait_flag) {
        md5_rule_entry_t *entry = (md5_rule_entry_t*)get_wait_extra(pwait_flag);
        if (entry) {
            memcpy(entry->md5, pbinfo->md5, 16);
            entry->type = pbinfo->type;
        }

        wake_wait_flag(pwait_flag);
        rc = 0;
    }

    return rc;
}



static int handle_cmd_simple_end(void* data, int data_len)
{
    int rc = -1;
    void* pwait_flag;

    pwait_flag = *(void**)data;
    if (pwait_flag) {
        wake_wait_flag(pwait_flag);
        rc = 0;
    }

    return rc;
}

//现在不需要了，内核直接从System.map中读取了
static int handle_cmd_add_symbol(void *data, int data_len)
{
	return 0;
}

static int handle_cmd_unspec(void* data, int len)
{
    LOG_DEBUG("handle_cmd_unspec\n");
    return 0;
}

void set_debug_flag(int flag)
{
    if(flag) {
        set_bit(0,&debug_flag);
    } else {
        clear_bit(0,&debug_flag);
    }
}

typedef struct {
    int mode;
    size_t len;
    const char* name;
} run_mode_item_t;
static run_mode_item_t __run_modes[] = {
                    {RELEASE_MODE,7,"release"},
                    {WHITE_BOX_MODE,12,"whiteboxtest"},
                };

int set_run_mode(const char* mode,size_t len)
{
    size_t i = 0;
    int rc = -EINVAL;

    if(!mode) { return rc; }

    for(;i < ARRAY_SIZE(__run_modes);i++) {
        run_mode_item_t* pitem = __run_modes + i;
        if(pitem->len != len) { continue; }

        if(!strncmp(pitem->name,mode,len)) {
            rc = 0;
            run_mode = pitem->mode;
            break;
        }
    }

    if(rc == 0) {
        LOG_INFO("set run mode: %s\n",mode);
    }

    return rc;
}

//是否在进行白盒测试
bool is_white_box_test(void)
{
    return (run_mode == WHITE_BOX_MODE);
}

//DEVICE_VERSION在Makefile中定义
#define SUPPORT_DRIVER_VERSION DEVICE_VERSION



//us is a short name for user service
//合法的初始化用户态进程名
static struct { 
		const char* us_comm;
		size_t len;
	} valid_us_comms[] = {
        {KOSEC_COMP_NAME,sizeof(KOSEC_COMP_NAME) - 1},
        {KOSEC_TQUI_NAME,sizeof(KOSEC_TQUI_NAME) - 1},
    };

static int do_handle_echo_cmd(void* data, int len,u32 portid);
//这个函数就是一个摆设，后面实际没有用.但不能删除
static int handle_echo_cmd(void* data, int len)
{
   return do_handle_echo_cmd(data,len,CURRENT_PID);
}

bool is_self_comm(void)
{
    size_t i;
    bool ok = false;
    size_t size = 0;

    size = ARRAY_SIZE(valid_us_comms);
    for(i = 0;i < size;i++) {
        ok = !kvd_strncasecmp(CURRENT_COMM,
        			valid_us_comms[i].us_comm,
					valid_us_comms[i].len);
        if(ok) { break; }
    }

    return ok;
}

//ECHO指令通知
static BLOCKING_NOTIFIER_HEAD(echo_cmd_chain);

int register_echo_notifier(struct notifier_block* notifier)
{
    int rc = -EINVAL;
    
    if(!notifier || !notifier->notifier_call) {
        return rc;
    }

    rc = blocking_notifier_chain_register(&echo_cmd_chain,notifier);

    return rc;
}

void unregister_echo_notifier(struct notifier_block* notifier)
{
    blocking_notifier_chain_unregister(&echo_cmd_chain,notifier);
}

static void echo_cmd_notify(unsigned long ecn,void* data)
{
    blocking_notifier_call_chain(&echo_cmd_chain,ecn,data);
}

#define MIN_LEN_ULIBVER 10
#define MAX_LEN_ULIBVER 16
//内核只支持2.0.0.42xx及以上的版本
#define SUPP_USER_LIBVER "2.0.0.42"

static int handle_set_portid_cmd(u32 portid,u_char* data,int data_len)
{
    int nlen = 0;
    int rc = -EINVAL;
    char str[0x100] = {0};
    pid_t pid = CURRENT_PID;
    ecn_data_pid_t ecn_data;
    char user_libver[128] = {0};

    //白盒测试模式下不验证进程名，方便进行测试
	if(!is_white_box_test() &&
      (!is_self_comm()))
    {
        LOG_ERROR("bad echo set cmd from %s,"
            "portid: %u\n",CURRENT_COMM,portid);
        return rc;
    }
    LOG_INFO("=======[%s],data_len:%d\n",(char *)data, data_len);
#if 0    
    //白盒测试模式下不验证版本号
    if(!is_white_box_test()) {
         if((data_len < MIN_LEN_ULIBVER) || 
            (data_len > MAX_LEN_ULIBVER)) 
        {
            LOG_ERROR("bad set port-id echo-cmd,"
                "bad user-lib-ver\n");
            return rc;
        }
    
        memcpy(user_libver,data,data_len);
        if(strcmp(user_libver,SUPP_USER_LIBVER) < 0) {
            LOG_ERROR("bad user libver: %s,"
                "please update it\n",user_libver);
            return rc;
        }
    }
#endif

    LOG_INFO("set portid[%u], pid:%d,user-libver: %s\n",
            portid,pid,user_libver);

    ecn_data.pid = pid;
    ecn_data.portid = portid;
    //这个要先于ECHO指令通知执行
    set_portid_service_pid(portid,pid);
    echo_cmd_notify(ECN_SET_PID,&ecn_data);



//    do_set_portid_cmd(portid,pid);
//    client_start();



    nlen = kvd_snprintf(str,sizeof(str),"%s%s",
                ECHO_CMD_STR_SET_PORT_ID,
                SUPPORT_DRIVER_VERSION);
    rc = send_nl_data(NL_POLICY_CMD_ECHO,
                    (void *)str,
                    nlen);
    return rc;
}

static int handle_clear_portid_cmd(u32 portid)
{
    int rc = -EINVAL;
    ecn_data_pid_t ecn_data;

    if(!check_snd_portid(portid)) {
        LOG_ERROR("bad echo clear port msg "
            "from port_id: %u\n",portid);
        return rc;
    }

    rc = 0;
    ecn_data.portid = portid;
    ecn_data.pid = CURRENT_PID;
    echo_cmd_notify(ECN_CLEAR_PID,&ecn_data);
    // wake_all_wait_flags(); //这个在此处调用是否真的需要???

    return rc;
}

//设置调试标识不再验证portid,因为调试就是为了找问题
//没有必要再验证portid了
static int handle_set_debug_cmd(u_char* data,int len)
{
    int flag = 0;
    u_char c = '0';
    size_t size = 0;
    int rc = -EINVAL;

    size = sizeof(ECHO_CMD_STR_SET_DEBUG) - 1;
    if(len < (size + 1)) {
        return rc;
    }

    c = data[size];
    //为了同时应对两种情况(这个非常恶心，因为我们没有严格的通信格式规范):
    //应用层设置了字符0或直接将该字节位设置成0
    if(c == '0') { c = 0; }
    flag = c & 0xFF;
    set_debug_flag(flag);
    rc = 0;

    LOG_INFO("set debug cmd: %d\n",flag);

    return rc;
}

int do_handle_echo_cmd(void* data, int len,u32 portid)
{
    int rc = -EINVAL;
    if (!strncmp(ECHO_CMD_STR_SET_PORT_ID,data,
        sizeof(ECHO_CMD_STR_SET_PORT_ID) - 1)) 
    {
        //检验用户态库版本
        int size = sizeof(ECHO_CMD_STR_SET_PORT_ID) - 1;
        rc = handle_set_portid_cmd(portid,data + size,len - size);
    } else if(!strncmp(ECHO_CMD_STR_CLEAR_PORT_ID,data,len)) {
        rc = handle_clear_portid_cmd(portid);
    } else {
        size_t size = sizeof(ECHO_CMD_STR_SET_DEBUG) - 1;
        if(!strncmp(ECHO_CMD_STR_SET_DEBUG,data,size)) {
            rc = handle_set_debug_cmd(data,len);
        }
    }

#if 0
   int rc = -EINVAL;
    if (!strncmp(ECHO_CMD_STR_SET_PORT_ID,data,len)) {
        rc = handle_set_portid_cmd(portid);
    } else if(!strncmp(ECHO_CMD_STR_CLEAR_PORT_ID,data,len)) {
        rc = handle_clear_portid_cmd(portid);
    } else {
        size_t size = sizeof(ECHO_CMD_STR_SET_DEBUG) - 1;
        if(!strncmp(ECHO_CMD_STR_SET_DEBUG,data,size)) {
            rc = handle_set_debug_cmd(data,len);
        }
    }
#endif

    return rc;
}

//产品注册/反注册通知通知
static BLOCKING_NOTIFIER_HEAD(product_chain);
int register_product_notifier(struct notifier_block* notifier)
{
    int rc = -EINVAL;
    
    if(!notifier || !notifier->notifier_call) {
        return rc;
    }

    rc = blocking_notifier_chain_register(&product_chain,notifier);

    return rc;
}

void unregister_product_notifier(struct notifier_block* notifier)
{
    blocking_notifier_chain_unregister(&product_chain,notifier);
}

static void product_notify(product_notify_t* ptn)
{
    blocking_notifier_call_chain(&product_chain,0,ptn);
}

static int product_types[] = {
        NL_PRODUCTION_SELF,
        NL_PRODUCTION_AUDIT,
        NL_PRODUCTION_AV,
    };

static bool is_valid_product_type(int type)
{
    size_t i = 0;
    bool ok = false;

    for(;i < ARRAY_SIZE(product_types);i++) {
        ok = (product_types[i] == type);
        if(ok) { break; }
    }

    return ok;
}

static int handle_cmd_reg_production(void* data, int data_len)
{
    int inited = 0;
    product_notify_t ptn;
    int nType = *(int*)data;

    if(!is_valid_product_type(nType)) {
        LOG_ERROR("unknow product type: %d\n",nType);
        return 0;
    }

    inited = 1;
    ptn.product = nType;
    ptn.action = PTN_ACTION_REG;
    product_notify(&ptn);

    if (inited) {
        send_nl_data(NL_POLICY_CMD_REGISTERED_NOTIFY,
                    &nType, sizeof(nType));
    }

    return 0;
}

/*
 *Note:
 *此处是用于处理反注册指令的，应用层很多功能模块设计的不合理:
 *1.没有有完整的策略控制开关或者在模块关闭时根本不发送关闭指令
 * 所以我们在此处不得已只能使用产品反注册接口当做策略控制开关来使用了
 */
static int handle_cmd_unreg_product(void* data, int data_len)
{
    product_notify_t ptn;
    int nType = *(int*)data;

    if(!is_valid_product_type(nType)) {
        LOG_ERROR("unknow product: %d unregister\n",nType);
        return 0;
    }

    ptn.product = nType;
    ptn.action = PTN_ACTION_UNREG;
    product_notify(&ptn);

    return 0;
}

static vsec_con_cb_set_t g_callback_array[(NL_MAX_CLASSIC_INDEX>>BIT_INDEX_OFFSET)+1];
int dispath_msg(u16 msg_type, void* data,int data_len,u32 portid)
{
    int rc = -EINVAL;
    int notify_idx = 0;
    vsec_con_cb_fn_t pfunc;
    int count = 0;
    int index_first = msg_type >> BIT_INDEX_OFFSET;
    int index_second = msg_type & 0xFF;

    if (index_first >= ARRAY_SIZE(g_callback_array)) {
        return rc;
    }

    count = g_callback_array[index_first].ncount;
    if (index_second >= count) {
        LOG_ERROR("kernel con second index is error,index_first:%d index_second: %d,count: %d"
            "msg_type = %x,\n",index_first, index_second,count,(int)msg_type);
        return rc;
    }

//    LOG_DEBUG("dispath msg:0x%x, %p, len:%d, port_id:%d, pid:%d\n",\
            (int)msg_type, data, data_len,portid, CURRENT_PID);
    
    rc = 0;
    //只要进入实际的策略处理就返回成功0
    notify_idx = g_callback_array[index_first].pcallbacks[index_second].index;
    //echo策略特殊处理
    if(notify_idx == NL_POLICY_CMD_ECHO) {
        do_handle_echo_cmd(data,data_len,portid);
        return rc;
    } else if(notify_idx == NL_POLICY_CMD_ADD_SYMBOL) {
        //ADD_SYMBOL策略特殊处理
        handle_cmd_add_symbol(data,data_len);
        return rc;
    } else {
        if(!check_snd_portid(portid)) {
            rc = -EPERM;
            LOG_ERROR("bad msg %d from port_id: %d\n",
                (int)msg_type,portid);
            return rc;
        }
    }

    pfunc = g_callback_array[index_first].pcallbacks[index_second].pfunc;
    if (pfunc)
        pfunc(data, data_len);

    return rc;
}


static int vsec_con_cb_cmp(const void* a,const void* b)
{
	const vsec_con_cb_t* cb1 = a;
	const vsec_con_cb_t* cb2 = b;

	return (cb1->index - cb2->index);
}

int register_notify_callback(vsec_con_cb_t* pcon_cbs, int count)
{
    int index;
    int rc = -EINVAL;

    if (pcon_cbs == NULL || count == 0) {
        LOG_ERROR("pcon_callback:%p, count:%d\n",
					pcon_cbs, count);
        return rc;
    }

    index = pcon_cbs->index >> BIT_INDEX_OFFSET;
    if (index >= ARRAY_SIZE(g_callback_array)) {
        LOG_ERROR("pcon_callback index:%d too big\n", index);
        return rc;
    }

    rc = 0;
	/*Note:
     *这里一定要排序，
     *因为我们的second_index依赖于vsec_con_cb_t的index值顺序
	 *要求pcallbacks数组中的元素一定要按照vsec_con_cb_t的index值升序排列
     */
	sort(pcon_cbs,count,sizeof(*pcon_cbs),
			vsec_con_cb_cmp,NULL);
    g_callback_array[index].pcallbacks = pcon_cbs;
    g_callback_array[index].ncount = count;
    LOG_INFO("==================index:%d,conut:%d\n",index,count);
    return rc;
}

int unregister_notify_callback(vsec_con_cb_t* pcon_cbs)
{
    int index;
    int rc = -EINVAL;

    if (pcon_cbs == NULL) {
        LOG_ERROR("pcon_callback:%p\n", pcon_cbs);
        return rc;
    }

    index = pcon_cbs->index >> BIT_INDEX_OFFSET;
    if (index >= ARRAY_SIZE(g_callback_array)) {
        LOG_ERROR("pcon_callback index:%d too big\n", index);
        return rc;
    }

    rc = 0;
    g_callback_array[index].pcallbacks = NULL;
    g_callback_array[index].ncount = 0;
    return rc;
}




static vsec_con_cb_t con_callbacks[] = {
    {
        .index = NL_POLICY_CMD_UNSPEC,
        .pfunc = handle_cmd_unspec,
    },
    {
        .index = NL_POLICY_CMD_ECHO,
        .pfunc = handle_echo_cmd,
    },
    {
        .index = NL_POLICY_SIMPLE_END,
        .pfunc = handle_cmd_simple_end,
    },
    {
        .index = NL_POLICY_BOOL_END,
        .pfunc = handle_cmd_bool_end,
    },
    {
        .index = NL_POLICY_CMD_REGISTER,
        .pfunc = handle_cmd_reg_production,
    },
	{
    	.index = NL_POLICY_CMD_ADD_SYMBOL,
		.pfunc = handle_cmd_add_symbol,
	},
    {
    	.index = NL_POLICY_CMD_UNREGISTER,
		.pfunc = handle_cmd_unreg_product,
	},
    {
        .index = NL_POLICY_MD5RULE_END,
        .pfunc = handle_cmd_md5rule_end,
    },


};

int register_cmd_handlers(void)
{
    memset(g_callback_array,0,
        sizeof(g_callback_array));
    
    return register_notify_callback(con_callbacks,
                    ARRAY_SIZE(con_callbacks));
}

void unregister_cmd_handlers(void)
{
    unregister_notify_callback(con_callbacks);
}

