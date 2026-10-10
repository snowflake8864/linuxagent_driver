#ifndef GN_HEAD_H
#define GN_HEAD_H

#ifndef __KERNEL__
    //user-space
    #include <stdint.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <linux/types.h>
    #include <sys/socket.h>
    #include <time.h>
    #include <sys/time.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <sys/ioctl.h>
#else
    #include <linux/in.h>
    #include <linux/in6.h>
    #include <linux/time.h>
    #include <linux/types.h>
    #include <linux/version.h>
    #include <linux/if.h>
    #include <linux/coda.h>
    #include "log_manager/log_mgr.h"
    
   // #define LOG_INFO(fmt, args...) printk(KERN_INFO "osec [%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
   // #define LOG_ERROR(fmt, args...) printk(KERN_ERR "osec [%s][%d]: "fmt, __FUNCTION__, __LINE__, ##args)
#if 0
	#ifdef DEBUG_FLAG
        extern unsigned long debug_flag;
        #ifdef DEBUG
            #define LOG_DEBUG(fmt, args...) printk(KERN_DEBUG "osec [%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
        #else
            #define LOG_DEBUG(fmt, args...) {if (test_bit(0,&debug_flag)) {printk(KERN_DEBUG "osec [%s][%d]: "fmt, __FUNCTION__, __LINE__, ##args);}}
        #endif
    #else
        #ifdef DEBUG
            #define LOG_DEBUG(fmt, args...) printk(KERN_DEBUG "osec [%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
        #else
            #define LOG_DEBUG(fmt, args...) 
        #endif
    #endif
#endif
    #define LOG_ERROR_SELF(fmt, args...) printk(fmt, ##args)
    #define LOG_ERROR_SYS(fmt, args...) printk(fmt, ##args)
    #define LOG_ERROR_DEV(fmt, args...) printk(fmt, ##args)
#endif

typedef enum {
    NL_POLICY_ATTR_UNSPEC,
    NL_POLICY_ATTR_BIN_MSG,
    NL_POLICY_ATTR_STR_MSG,
    NL_POLICY_ATTR_WAIT_FLAG,
    NL_POLICY_ATTR_DATA_MSG,
    __NL_POLICY_ATTR_MAX,
} NL_POLICY_ATTR;

#define GN_POLICY_ATTR_MAX (__GN_POLICY_ATTR_MAX - 1)

typedef enum {
    NL_PRODUCTION_EMPTY = 0,
    NL_PRODUCTION_SELF = 1,
    NL_PRODUCTION_AV = 2,
    NL_PRODUCTION_APP_CONTROL = 4,
    NL_PRODUCTION_AUDIT = 8,
} NL_PRODUCTION;

/* commands: enumeration of all commands (functions),
 * used by userspace application to identify command to be ececuted
 */
typedef enum {
    NL_POLICY_CMD_UNSPEC,
    NL_POLICY_CMD_ECHO = 1,
    NL_POLICY_SIMPLE_END,
    NL_POLICY_BOOL_END,
    NL_POLICY_CMD_REGISTER,
    NL_POLICY_CMD_ADD_SYMBOL,
    NL_POLICY_CMD_UNREGISTER,
    NL_POLICY_MD5RULE_END,
    
//self protection notify index array
    NL_POLICY_DEFENSE_UNSPEC = 0x100,
    NL_POLICY_DEFENSE_SWITCHER,
    NL_POLICY_DEFENSE_ADD_WHITE_EXE,
//self protection notify index array
    NL_POLICY_SELF_SWITCHER,
    NL_POLICY_GLOBAL_DIR,
    NL_POLICY_EXIPORT_RULE,
    NL_POLICY_PROTECT_RULE,
    NL_POLICY_DEFENSE_FILE_PROCESS_POLICY,
    
//network change
    NL_POLICY_NETWORK_UNSPEC = 0x700,
    NL_POLICY_NETWORK_POLICY,
    NL_POLICY_NETSYSLOG_POLICY,
    NL_POLICY_NETWORK_SERVERIP_POLICY,
    NL_POLICY_NETWORK_NETBLOCK,
    NL_POLICY_NETWORK_BUSINESS_PORT_POLICY,
    NL_POLICY_NETWORK_CLOSE,
    NL_MAX_CLASSIC_INDEX,

/*
 *再添加内核发给应用层的通知，一定要向后加，不要再动以前的了
 *内核发给应用层的通知不要再在这里加了！！！！！！！！！！！！！
 *不然肯定会导致无法兼容以前的版本，引起程序崩溃消息无法正常处理等各种问题
 *后续对内核发给应用层的通知也要做分节处理
*/
////////////////////////////////////////////////////////////////////////////////
//kernel to client common
    NL_POLICY_CMD_NOTIFY = 0x503, //compatiable AK2
    //Note:内核发送给用户态的TLV通知,不要修改这个值，
    //后续内核发给用户态的TLV格式通知，全部会采用该值
    #define NL_NOTIFY_TLV NL_POLICY_CMD_NOTIFY
    NL_POLICY_CMD_REGISTERED_NOTIFY,
////////////////////////////////////////////////////////////////////////////////
//再添加内核发给应用层的通知，一定要向后加，不要再动以前的了
//内核发给应用层的通知不要再在这里加了！！！！！！！！！！！！！
//下面这些一直到NL_POLICY_NETWORK_DNSIP_NOTIFY都不要再动了!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//antivirus rtmonitor
    NL_POLICY_AV_PROCESS_EXEC_NOTIFY,
    NL_POLICY_AV_PROCESS_EXEC_ZCOPY_NOTIFY,
    NL_POLICY_AV_FILE_CHANGE_NOTIFY,
    NL_POLICY_AV_FILE_RENAME_NOTIFY,
    NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY,
    NL_POLICY_AV_SELF_PROTECTION_NOTIFY,
    NL_POLICY_NET_PORT_NOTIFY,
    NL_POLICY_NET_PORT_ZCOPY_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_NOTIFY,
    NL_POLICY_NET_DNS_PORT_NOTIFY,
    NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY,
    NL_POLICY_INFO_KERN_TO_APP_NOTIFY,
    NL_POLICY_UPDATE_PROCESS_RULE_NOTIFY,

////////////////////////////////////////////////////////////////////////////////    
    NL_MAX_INDEX = 0x1000, //4096
} NLPolicyType;

#define BIT_INDEX_OFFSET 8

#define ECHO_CMD_STR_SET_PORT_ID  "set portid"
#define ECHO_CMD_STR_CLEAR_PORT_ID  "clear portid"
#define ECHO_CMD_STR_ECHO     "echo"

#define ECHO_CMD_STR_SET_DEBUG     "set debug"

//the bool sync information structure
struct bool_info {
    void* pwait_flag;
    int bBool;
};

/*Note:
 *端口组(无论是用户态下给内核还是内核发送给用户态时)
 *一定要是:网络字节序
 */
struct vsec_port_pair{
    uint16_t first; //first port
    uint16_t second; //second port
}__attribute__((packed));

/*Note:
 *ipv4地址组(无论是用户态下给内核还是内核发送给用户态时)
 *一定要是:网络字节序
 */
struct vsec_ipv4_pair{
    struct in_addr s_first; //first ipv4
    struct in_addr s_second; //second ipv4
}__attribute__((packed));

/*Note:
 *ipv6地址组(无论是用户态下给内核还是内核发送给用户态时)
 *一定要是:网络字节序
 */
struct vsec_ipv6_pair{
    struct in6_addr s6_first; //first ipv6
    struct in6_addr s6_second; //second ipv6
}__attribute__((packed));

/*
 *ipv4地址/port组，全部是网络字节序
 */
struct vsec_ipport_pair {
    struct in_addr in;
    u_short port;
}__attribute__((packed));

/*
 *ipv6地址/port组，全部是网络字节序
 */
struct vsec_ip6port_pair {
    struct in6_addr in6;
    u_short port;
}__attribute__((packed));

//dns协议规定域名总长度最大限制是253
#define KOSEC_DNAME_MAX      253
///////////////////////////////////////////////////////////////////////////////
//Audit System

//审计版本标识
enum audit_versions {
    AUDIT_V1 = 0, //默认版本的审计，初始版本
    AUDIT_V2, //第二个版本的审计(增加了ipv6支持)
};

enum {
    AUDIT_ACTION_NONE   =    0, //无效的审计操作
    AUDIT_ACTION_OPEN   =    1,
    AUDIT_ACTION_RENAME =    2,
    AUDIT_ACTION_TRUNCATE =  3,
    AUDIT_ACTION_CHMOD   =   4,
    AUDIT_ACTION_UNLINK  =   5,
    AUDIT_ACTION_MKDIR   =   6,
    AUDIT_ACTION_RMDIR   =   7,
    AUDIT_ACTION_CHOWN   =   8,
    AUDIT_ACTION_WRITE   =   9,
    AUDIT_ACTION_PORT_BIND = 10, //端口绑定
    AUDIT_ACTION_PORT_FREE = 11, //绑定端口释放
    AUDIT_ACTION_CREATE  =   12,
};

#define PROCESS_MONITOR_EXEC 0
#define PROCESS_MONITOR_KILL 1
#define PROCESS_MONITOR_EXIT 2
#define PROCESS_MONITOR_FORK 3

#define SERVICE_MONITOR_STOP     0
#define SERVICE_MONITOR_START    1
#define SERVICE_MONITOR_RESTART  2

#define AUDIT_PORT_BIND_AUDIT   0   //端口绑定,只审计
#define AUDIT_PORT_BIND_BLOCK   1   //端口绑定阻断
#define AUDIT_PORT_BIND_FREE    2   //端口绑定释放操作

struct port_audit_info {
    int32_t pid;
    int32_t port;
    int32_t black;
    char process_name[16];
};

//针对AK7的端口绑定审计
struct new_port_audit_info {
    int32_t pid;
    int32_t port;
    u_char action; //AUDIT_ACTION_PORT_BIND,AUDIT_ACTION_PORT_FREE
    u_char mode; //AUDIT_MODE_BLACK,AUDIT_MODE_WHITE,
    u_char op; //AUDIT_OP_AUDIT,AUDIT_OP_BLOCK
    
    char process_name[16];
};

struct port_scan_info {
    __be32 src;
    __be32 dst;
    int32_t port;
};

//新版本的audit version
struct port_scan_info_v2 {
    u_short family; //AF_INET,AF_INET4
    u_short port; //网络字节序

    //网络字节序
    union {
        struct in_addr	in; 
	    struct in6_addr	in6;
    } saddr,daddr; 
};

struct arp_defense_info {
    __be32 ip;
    unsigned char mac[20];
};

struct conm_netflow_info {
    int mode;
    int up;
    int protocol;
    __be32 sip;
    __be32 sport;
    __be32 dip;
    __be32 dport;
};

//ak6之后，主审网络连接需要审计建立连接的进程名称
//为了兼容ak6之前的版本，所以定义 struct new_conm_netflow
//结构类型;ak6(2.0.0.2000)之后的版本全部采用这些结构

struct new_conm_netflow {
    int mode;
    int up;
    int protocol;
    __be32 sip;
    __be16 sport;
    __be32 dip;
    __be16 dport;
    char comm[16];
};


#define AUDIT_NETSRV_HTTP "HTTP"
#define AUDIT_NETSRV_FTP "FTP"
#define AUDIT_NETSRV_SMTP "SMTP"

//2.0.0.4300版本加入:
//网络连接审计v2版本，同时支持ipv4/ipv6
//可用于替换前面的new_conm_netflow与zyj_conm_netflow
struct conm_netflow_v2 {
    u_char op; //AUDIT_OP_BLOCK/AUDIT_OP_AUDIT
    u_char mode; //AUDIT_MODE_BLACK/AUDIT_MODE_WHITE
    u_char up;
    u_char protocol;
    u_char family; //AF_INET/AF_INET6
    char netsrv[8]; //根据端口识别的网络服务名称(AUDIT_NETSRV_XXX)

    //ip/端口: 网络字节序,跟以前版本不同
    //(以前版本: port主机字节序,而ip网络字节序:做法很不标准)
    union {
        struct in_addr	in; 
	    struct in6_addr	in6;
    } saddr,daddr; 

    u_short sport;
    u_short dport;
    char comm[16];
};

enum {
    CONN_NETFLOW_B = 1,  ///< byte
    CONN_NETFLOW_KB,     ///< Kbyte
    CONN_NETFLOW_MB,     ///< Mbyte
    CONN_NETFLOW_GB,     ///< Gbyte
    CONN_NETFLOW_TB,     ///< Tbyte
};
struct conn_netflow_seckit {
    u_char up;          //< 1:流出-发送 0:流入-接收
    u_char protocol;    //< 协议TCP 、UDP
    u_char family;      //< AF_INET/AF_INET6
    u_char unit;        //< CONN_NETFLOW_xx
    u_short sport;      //< 源端口
    u_short dport;      //< 目的端口
    int64_t threshold;  //< 流量阀值
    int64_t flowsize;   //< 上传、下载流量大小
    union {             //< 源IP、目的IP
        struct in_addr  in;
        struct in6_addr in6;
    } saddr, daddr;
    pid_t pid;          //< 进程id
    char comm[16];      //< 进程名
};

struct process_flow {
    char comm[16];
    int32_t pid;
    int up;
    int sock_type;
    int flowsize;
    struct sockaddr selfaddr;
    struct sockaddr peeraddr;
	int action; //for shield
};

struct process_flow_v2 {
    char comm[16];
    int32_t pid;
    int up;
    int sock_type;
    int flowsize;
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } selfaddr, peeraddr;
    int action;
};

struct process_info {
    int32_t pid;
    int32_t uid;
    int32_t ppid;
    int32_t action;
	int32_t decision;
    int64_t memsize;
    long time;
	char process_name[256];
	char process_parent[256]; //for shield
};

struct process_info_inner {
    int32_t pid;
    int32_t uid;
    int32_t ppid;
    int32_t action;
	int32_t decision;
    int64_t memsize;
    long time;
	char process_name[256];
};

struct service_info {
	int32_t pid;
	int32_t uid;
	int32_t action;
    long time;
	char server_name[32];
	char dir_name[256];
};

struct print_info {
	char job_id[16];
	char files[16]; //打印的文件份数
	char filename[64];
};

#ifdef __KERNEL__
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
			#ifndef _STRUCT_TIMESPEC
			struct timespec {
				__kernel_old_time_t tv_sec;
				long tv_nsec;
			};
			
			struct timeval {
				__kernel_long_t tv_sec;
				__kernel_long_t tv_usec;
			};
			#endif
	#endif
#endif

struct path_info {
	char path[256];
	unsigned short mode;
	int32_t uid;
	struct timespec i_atime;
	struct timespec i_mtime;
	struct timespec i_ctime;
};

#define MAX_PROCESS_PATH 512
struct  av_process_info {
        union {
        struct {
            int pid;
            int ppid;
            int uid;
            int unused;
        }; 
        uint8_t md5[16];
    }; 
    int32_t type;
    union {
        struct {
            uint32_t is_dir:3,
                     deny:3,
                     param_pos:10,
                     level:3,
                     is_monitor_mode:2,
                     is_docker_process:1;
        };
        uint32_t flags_raw;  // 整个 flags 的原始值
    };
    char path[MAX_PROCESS_PATH];
};
struct symbol_msg {
	long sym_addr;
	char name[0];
};


//1 Byte Product-Type,2 Bytes Fileds length
//the header length of tlv 
#define TLV_HDR_LEN      3
//兼容2.0.0.4000之前的版本
#define TLV_HEADER_LEN   TLV_HDR_LEN

typedef struct vsec_tlv_hdr {
    u_char pt;
    u_short len;
    u_char fields[0];
} __attribute__((packed)) vsec_tlv_hdr_t;

//TLV通信协议格式的Product-Type
enum {
    OSEC_PT_NONE = 0,
    OSEC_PT_CORE = 1,
    OSEC_PT_SELF, //自保
    OSEC_PT_KERNEL,  // base libEntKernel.so 全局加白防火墙使用
    OSEC_PT_MAX = 0xFF,
};


//charater device
typedef struct {
    uint16_t type;//对应前面user向kernel发送的NL_POLICY_XXX
    uint16_t len;//data的长度
    void* addr; //用户空间地址
}vsec_data_t;

//内核发给用户态的数据格式
struct vsec_msg_data {
    int data_type;//对应前面kernel向user发送的NL_POLICY_XXX_NOTIFY
    int data_len;
    char data[0];
};

//这个是针对AK7,将报文限定变成16KB
#define KOSEC_NEW_DATA_MAX 16384

#define KOSEC_DATA_MAX 8192
#define KOSEC_IOC_MAGIC ('T' + 'Q')
#define KOSEC_IOC_SETVAL (_IOW(KOSEC_IOC_MAGIC, 0x1,vsec_data_t))

#define KOSEC_SET_DATA(data,_type,_len,_paddr) \
                    data.type = _type;      \
                    data.len = _len;         \
                    data.addr = _paddr;


#define KOSEC_CDEV_NAME  "osecbz1"
#define KOSEC_CDEV_PATH  "/dev/osectest"

#define KOSEC_OSEC_NAME "MagicArmor_0"


#define KOSEC_SYSFS_NAME   "osec"

#define KOSEC_SYSFS_PROTO "/sys/" KOSEC_SYSFS_NAME "/proto"

////////////////////////////////////////////////////

//公司名称标识
#define KOSEC_COMP_NAME	"MagicArmor_0"

#define KOSEC_TQUI_NAME  "MagicArmor_"

////////////////////////////////////////////////////////

///tq-char-mmap:基于字符设备的mmap
/*
   Frame structure:

   - Start. Frame must be aligned to KOSEC_MMC_ALIGNMENT=16
   - struct vsec_mmc_req
   - pad to KOSEC_MMC_ALIGNMENT=16
   - Gap, chosen so that packet data (Start + vsec_mmc_hdr) alignes to KOSEC_MMC_ALIGNMENT=16
   - Pad to align to KOSEC_MMC_ALIGNMENT=16

   * frames_per_block =  block_size/ frame_size
	indeed, packet_set_ring checks that the following condition is true
		frames_per_block * block_nr == frame_nr
	Lets see an example, with the following values:
		block_size= 4096
		frame_size= 2048
		block_nr  = 4
		frame_nr  = 8
	we will get the following buffer structure:
			block #1                 block #2 
	+---------+---------+    +---------+---------+ 
	| frame 1 | frame 2 |    | frame 3 | frame 4 | 
	+---------+---------+    +---------+---------+   

			block #3                 block #4 
	+---------+---------+    +---------+---------+ 
	| frame 5 | frame 6 |    | frame 7 | frame 8 | 
	+---------+---------+    +---------+---------+
 *
 *Note:
 *一个报文可能会占用多个frame,但一个报文必须保证在一个block中，不能跨block
 */

struct vsec_mmc_req {
	unsigned int	block_size;	/* Minimal size of contiguous block */
	unsigned int	block_nr;	/* Number of blocks */
	unsigned int	frame_size;	/* Size of frame */
	unsigned int	frame_nr;	/* Total number of frames */
};

#define KOSEC_MMC_ST_KERN		0
#define KOSEC_MMC_ST_USER		1
#define KOSEC_MMC_ST_LOSING	(1 << 2)

struct vsec_mmc_hdr
{
	unsigned long	status;
	unsigned int	snaplen;
};

#define KOSEC_MMC_ALIGNMENT	16
#define KOSEC_MMC_ALIGN(x)	(((x)+KOSEC_MMC_ALIGNMENT-1)&~(KOSEC_MMC_ALIGNMENT-1))
#define KOSEC_MMC_HDRLEN		(KOSEC_MMC_ALIGN(sizeof(struct vsec_mmc_hdr)))


struct vsec_pack_stats
{
	unsigned long	packets;
	unsigned long	drops;
};

#define KOSEC_MMC_SET_RING	0x10

#define KOSEC_IOC_SETRING (_IOW(KOSEC_IOC_MAGIC,KOSEC_MMC_SET_RING,struct vsec_mmc_req))

#define KOSEC_SYSFS_MMC "/sys/" KOSEC_SYSFS_NAME "/mmc"
///////////////////////////////////////////////////////////////////////////////////////



struct netlink_netlog {
    int start_idx;
    int end_idx;
    int max_idx;
};


struct osec_global_dir{
    uint8_t _type;
    char name[255];
    uint8_t name_len;
};

struct NetworkKernelRulesInfo{
    uint8_t addr_type:5,
            protocol:1, //1-tcp,0-udp
            is_ipv4:1,
            dest_port_type:1;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }sip;

    uint16_t sport;
//    uint32_t eip;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }eip;

    uint16_t eport;
    uint16_t redirectPort;
};

struct NetworkKernelPolicyInfo
{
    uint16_t pol_switch:1,
            acl_type:1,
            acl_num:8;
    struct NetworkKernelRulesInfo rules_info[20];
};


struct osec_network_report 
{
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }src;
    uint16_t src_port;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }dst;
    uint16_t dest_port;
    uint32_t pid;
    char comm[128];
    //char dns_name[255];
};

struct osec_network_report_old 
{
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }src;
    uint16_t src_port;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }dst;
    uint16_t dest_port;
    uint32_t pid;
    char comm[32];
    uint8_t type;
    //char dns_name[255];
};

struct osec_dns_report 
{
    uint32_t type;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint32_t pid;
    char comm[128];
    uint8_t is_ipv6:1,
            ip_cnt:4;
    union {
        uint32_t ipv4[12];
        uint8_t ipv6[48];
    };
    char dns_name[255];
};


struct osec_openport_report 
{
    uint32_t type;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }src_ip;

    uint16_t src_port;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }dest_ip;

    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }attack_dest_ip;


    uint16_t dest_port;
    uint32_t pid;
    char comm[128];
};

struct defense_action {
    int action;
    void* pwait_flag; 
};

struct av_file_info {
    int pid;
    int ppid;
    int uid;
    //char comm[512];
    char comm[128];
    char comm_p[16];
    char path[512];
    char dst_path[512];
    uint16_t log_type;
    union {
        struct {
            uint16_t is_dir:3,
                     type:3,
                     rules_type:4,
                     log_level:3;
        };
        uint16_t flags;
    };
};

struct av_file_audit_info {
    int pid;
    int ppid;
    int uid;
    //char comm[512];
    char comm[128];
    char comm_p[16];
    char path[512];
    uint16_t log_type;
    union {
        struct {
            uint16_t is_dir:3,
                     type:3,
                     rules_type:4,
                     log_level:3;
        };
        uint16_t flags;
    };
};


struct av_self_protection_info {
    int pid;
    int ppid;
    int uid;
    int type;
    char comm[128];
    //char comm_p[16];
    char path[128];
//    char dst_path[1024];
};

typedef struct com_info_s {
    uint32_t pid;
    uint32_t ppid;
    int type:3,
        version:3;
    //char comm[512];
}com_info_t;

typedef struct process_rules_info_s {
//    int pid;
//    int ppid;
//    int type;
    void* pwait_flag;
    char comm[512];
}process_rules_info_t;

typedef struct md5_rule_entry_s {
    uint8_t md5[16];
    uint8_t type:2; //0:black, 1: white, 2:unkown
} md5_rule_entry_t;

typedef struct md5_rules_item_s {
    void* pwait_flag;
    uint8_t md5[16];
    uint8_t type:2; //0:black, 1: white, 2:unkown
} md5_rules_item_t;


//charater device
typedef struct {
    uint16_t type;//对应前面user向kernel发送的NL_POLICY_XXX
    uint16_t len;//data的长度
    void* addr; //用户空间地址
}kosecs_data_t;

//内核发给用户态的数据格式
struct kosecs_msg_data {
    int data_type;//对应前面kernel向user发送的NL_POLICY_XXX_NOTIFY
    int data_len;
    char data[0];
};

/////////////////////////////////////////////////////
//导出的sysfs协议接口文件,通过该文件能够获取内核开启的netlink端口及char-dev标识
////////////////////////////////////////////////////

enum DEFENSE_TYPE {
    FILE_CREATE = 0,
    FILE_REMOTE = 1,
    FILE_MODIFY = 2,
    FILE_OPEN = 3,
    FILE_RENAME = 4,
    PROCESS_CREATE = 5,
    FILE_CLOSE = 6

};

#endif
