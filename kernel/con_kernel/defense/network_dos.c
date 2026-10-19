#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#include <linux/in.h>  // for IPPROTO_TCP
#endif
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>   // in4_pton, in6_pton
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/ipv6.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_ecn.h>
#include <net/arp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/dst.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/bitops.h>
#include <linux/delay.h>       // for msleep, usleep_range
#include "core/kvd_core.h"
#include "gnHead.h"
#include "core/gnkernel.h"
#include "utils/utils.h"
#include "core/flag_cache.h"
#include "netfilter/netfilter.h"
#include "defense_inner.h"
#include "core/zcopy.h"
#include "rules/conn_block_rules.h"
#include "utils/var_proc.h"
#include "forward/forward.h"
#define MAX_POLICY_SIZE 10
#define MAX_PORT_SIZE 10
#define MAX_URL_LEN 128

#define URL_FULL_MATCHING      0
#define URL_PRE_MATCHING       1
#define URL_MENT_MATCHING      2
#define URL_PRE_MENT_MATCHING  3


extern struct proc_dir_entry *proc_osec;
extern int init_forward;
struct NetworkKernelPolicy
{
    uint8_t acl_type;
    struct list_head NETISOLATE_LIST;
};

struct NetTcpUdpInfo {
    struct list_head list;
    struct rcu_head rcu;           // RCU 头部，用于延迟释放
    __u8 addr_type;
    __u8 protocol;
    struct NetworkKernelRulesInfo info;
};

#if TCP_ECN_FEATURE == 1
static uint32_t tcp_force_ecn = 1;
#endif

unsigned long timer_status = 0;  // 初始值为 0，表示所有定时器都关闭
struct timer_list netlog_audit_timer;
struct timer_list openport_audit_timer;
struct timer_list out_netlog_audit_timer;
struct timer_list dns_netlog_audit_timer;

static DEFINE_SPINLOCK(g_ntcp_policy_lock); // 保护写路径
//rwlock_t g_ntcp_policy_lock;
static struct NetworkKernelPolicy gListTcpPolicy;
//static uint16_t gWhilePort[50] = {0};
#define PORT_COUNT 65536
static uint32_t businessPortBitMap[PORT_COUNT/32];
//static uint32_t rstPortBitMap[PORT_COUNT/32];
//rwlock_t g_block_policy_lock;
static DEFINE_SPINLOCK(g_block_policy_lock); // 保护写路径
static struct NetworkKernelPolicyInfo *gNetBlockPoicy;
static __be32 server_ip = 0;
static uint8_t server_ip6[16];

#define NET_DOS_ENABLE  (1 << 0)
#define NET_SYSLOG_ENABLE (1 << 1)
#define PROC_START_ENABLE (1 << 2)
#define NET_BLOCK_ENABLE (1 << 3)
#define CLOSE_NET_BUSINESS (1 << 4)

static unsigned long _network_status = 0;

static int netdos_tcp_out(struct sk_buff* skb,struct iphdr* iph, uint32_t u_type);
static int get_process_executable_path(struct task_struct *task, char *buf, size_t buf_size); 
//static inline int get_process_path(pid_t pid, char *buf, size_t buflen); 


static inline void atomic_set_network_status(int bit) {
    set_bit(bit, &_network_status);
}

static inline void atomic_clear_network_status(int bit) {
    clear_bit(bit, &_network_status);
}

static inline bool atomic_is_network_status_set(int bit) {
    return test_bit(bit, &_network_status);
}

static int port_to_index(uint16_t port) {  
    return port / 32;  
}  
  
// 将位图中的特定位设置为1，表示该端口已使用  
static void set_business_port(uint16_t port) {  
    int index = port_to_index(port);  
    int bit = port % 32;  
//    LOG_INFO("====================================businessPortBitMap=%d\n",port);
    businessPortBitMap[index] |= 1 << bit;  
}  
static void clear_business_port(void) 
{  
    int i;
    for (i = 0; i < PORT_COUNT / 32; i++) {
        businessPortBitMap[i] = 0;
    }
}
// 检查端口是否在位图中被标记为已使用  
static int is_business_port(uint16_t port) {  
    int index = port_to_index(port);  
    int bit = port % 32;  
    return (businessPortBitMap[index] & (1 << bit)) != 0;  
}  

void net_dos_turn_on(void)
{
    atomic_set_network_status(NET_DOS_ENABLE); 
    LOG_INFO("network dos trun on\n");
}

void net_dos_turn_off(void)
{
    atomic_clear_network_status(NET_DOS_ENABLE); 
    LOG_INFO("network dos trun off\n");
}

static inline int is_net_dos_enable(void)
{
    return test_bit(NET_DOS_ENABLE, &_network_status);
}


void net_block_turn_on(void)
{
    atomic_set_network_status(NET_BLOCK_ENABLE); 
    LOG_INFO("net block trun on\n");
}

void net_block_turn_off(void)
{
    atomic_clear_network_status(NET_BLOCK_ENABLE); 
    LOG_INFO("net block trun off\n");
}

static inline int is_net_block_enable(void)
{
    return test_bit(NET_BLOCK_ENABLE, &_network_status);
}
void syslog_turn_on(void)
{
    atomic_set_network_status(NET_SYSLOG_ENABLE); 
    LOG_INFO("syslog trun on\n");
}

void syslog_turn_off(void)
{
    atomic_clear_network_status(NET_SYSLOG_ENABLE); 
    LOG_INFO("syslog trun off\n");
}

int is_syslog_enable(void)
{
    return test_bit(NET_SYSLOG_ENABLE, &_network_status);
}
void proc_start_turn_on(void)
{
    atomic_set_network_status(PROC_START_ENABLE); 
    LOG_INFO("process start trun on\n");
}

void proc_start_turn_off(void)
{
    atomic_clear_network_status(PROC_START_ENABLE); 
    LOG_INFO("process start trun off\n");
}
int is_proc_start_enable(void)
{
    return test_bit(PROC_START_ENABLE, &_network_status);
}

int is_close_net_business(void)
{
    return test_bit(CLOSE_NET_BUSINESS, &_network_status);
}

static int ip6_netblock_match(struct ipv6hdr *ip6h) {
    int i = 0;
    int nMatch = 0;
    struct NetworkKernelPolicyInfo *policy;

    rcu_read_lock();
    policy = rcu_dereference(gNetBlockPoicy);
    if (!policy || policy->acl_num == 0) {
        rcu_read_unlock();
        return 0;
    }

    for (i = 0; i<policy->acl_num; i++) {
        //LOG_INFO("netblock_match info eip:%x, daddr:%x, saddr:%x\n", policy->rules_info[i].eip, ip_header_->daddr, ip_header_->saddr);
        if (ipv6_masked_addr_cmp((struct in6_addr *)policy->rules_info[i].eip.ip6, (struct in6_addr *)policy->rules_info[i].sip.ip6, &ip6h->saddr) == 0) {
            //LOG_INFO("netblock_match dst addr eip:%x\n", ip_header_->daddr);
            nMatch = 1;
            break;
#if 0            
        } else if (ipv6_masked_addr_cmp((struct in6_addr *)Policy->rules_info[i].eip.ip6, (struct in6_addr *)Policy->rules_info[i].sip.ip6,  &ip6h->saddr) == 0) {
             //LOG_INFO("netblock_match saddr eip:%x\n", ip_header_->daddr);
             nMatch = 2;
             break;
#endif             
        }
    }
    rcu_read_unlock();
    return nMatch;
}



static unsigned int time_interval = 1 * 60 * HZ; // HZ 是内核的时钟周期

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static void openport_audit_timer_function(struct timer_list *timer)
#else
static void openport_audit_timer_function(unsigned long data)
#endif
{
    uint32_t idx = 0, prev_idx = 0;
    struct netlink_netlog netlog_msg;
    if (unlikely(!atomic_is_timer_status_set(OPENPORT_AUDIT_TIMER_ON))) {
        return;
    }
//    LOG_INFO("start ===timer open port openport_audit_data_count=%d\n", openport_audit_data_count);
//    mdelay(5000);

    netlog_msg.max_idx = get_openport_audit_idx(&prev_idx, &idx);
    if (idx > prev_idx) {
        netlog_msg.start_idx = prev_idx;
        netlog_msg.end_idx = idx;
//        LOG_INFO("timer open port openport_audit_data_count=%d, idx=%d start idx:%d, end idx:%d......\n", openport_audit_data_count, idx, netlog_msg.start_idx, netlog_msg.end_idx);
        send_nl_data(NL_POLICY_NET_PORT_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));

    }
//    LOG_INFO("stop===timer open port openport_audit_data_count=%d\n", openport_audit_data_count);
    if (likely(atomic_is_timer_status_set(OPENPORT_AUDIT_TIMER_ON))) 
    {
        // 如果标志为 1，则重新调度定时器
        mod_timer(&openport_audit_timer, jiffies + 45 * HZ);  
    }

} 

static int NetIsolateInfo_tcpudp_matching(struct iphdr *dest_addr, struct tcphdr* dest_port, int protocol_index, struct sk_buff *skb) 
{
    struct NetTcpUdpInfo* nci = NULL;
    struct NetTcpUdpInfo *last_nci = NULL;  // 记录上一次的 nci 地址
    struct list_head *pos;
    int ret = NF_ACCEPT;
    int nMatch = 0;
    int index_port = 0;
    int count = 0;
    const int max_count = 20;
    int visit_port = ntohs(dest_port->dest);
    if(is_self_process()) {
        return NF_ACCEPT;
    }

#if 0    
    if (memcmp(CURRENT_COMM, "MagicArmor", 10) == 0) {
        return NF_ACCEPT;
    }
    for (; index_port <50; index_port++) {
        if (visit_port == gWhilePort[index_port]) {
            LOG_DEBUG("return..[%d]\n",visit_port);
            return ret;
        }
    }
#endif
//    if (is_business_port(visit_port)) {
//        LOG_DEBUG("return..[%d]\n",visit_port);
//        return NF_ACCEPT;
//    }

    rcu_read_lock();
    list_for_each_entry_rcu(nci, &gListTcpPolicy.NETISOLATE_LIST, list) {
        // 检查当前 nci 地址是否与上一次相同
        if (last_nci == nci || count++ > max_count) {
            LOG_INFO("Duplicate nci address detected: %p, possible list corruption\n", nci);
            break;
        }

         //LOG_INFO("srcip:%u.%u.%u.%u, sport:%u, destip:%u.%u.%u.%u, dport:%u\n",\
                    IPQUADS(dest_addr->saddr), ntohs(dest_port->source), IPQUADS(dest_addr->daddr), ntohs(dest_port->dest));



        last_nci = nci;  // 更新上一次的地址
        nMatch = 0;
        if (nci->info.is_ipv4 == 0) {
            continue;
        }
        if (nci->info.sip.ip4 == 1) {
            nMatch = 1;
        } else if (nci->info.sip.ip4 == dest_addr->daddr) {
            nMatch = 1;
        } else {
             nMatch = 1;
        }
        if (nMatch == 1) {
            if ((nci->info.sport == nci->info.eport) && (nci->info.sport == visit_port)) {
                nMatch = 2;
            } 
            if ((nci->info.sport < nci->info.eport) && (nci->info.sport <= visit_port) && (nci->info.eport >= visit_port) ) {
                nMatch = 2;
            }
        }
        if (nMatch == 2) {
            //命中上报日志 
			//attack_dest_ip = dest_addr->daddr;
			//attack_src_ip = dest_addr->saddr;

#if 1       
			uint32_t sip = dest_addr->saddr, dip = dest_addr->daddr;
            uint16_t forward_dport = 0;
			//uint16_t sport = dest_port->source, dport = dest_port->dest;
			if (nci->info.eip.ip4 != 4294967295  && nci->info.eip.ip4 != 0  && (nci->info.dest_port_type == 1 || nci->info.redirectPort !=0) && visit_port >= nci->info.sport && visit_port <= nci->info.eport) {
                if (nci->info.dest_port_type == 1) {
                     forward_dport = dest_port->dest;
                } else {
                     forward_dport = htons(nci->info.redirectPort);
                }
//                LOG_SHOW("srcip:%u.%u.%u.%u, sport:%u, destip:%u.%u.%u.%u, dport:%u\n",\
                    IPQUADS(dest_addr->saddr), ntohs(dest_port->source), IPQUADS(dest_addr->daddr), ntohs(dest_port->dest));


                //uint32_t sip = dest_addr->saddr, dip = dest_addr->daddr;
                uint16_t sport = dest_port->source, dport = dest_port->dest;
                //session_cache_try_get(dest_addr->saddr, dest_port->source, dest_addr->daddr, dest_port->dest, dest_port->source, nci->info.eip, htons(nci->info.redirectPort), skb);
                //session_cache_try_get(nci->info.eip, htons(nci->info.redirectPort), dest_addr->daddr, dest_port->source, dest_port->dest, dest_addr->saddr, dest_port->source, NULL);
                session_cache_try_get(dest_addr->saddr, dest_port->source, dest_addr->daddr, dest_port->dest, dest_port->source, nci->info.eip.ip4, forward_dport, skb);
				nci->info.eip.pad[0] = 0;
				nci->info.eip.pad[1] = 0;
				nci->info.eip.pad[2] = 0;
                session_cache_try_get(nci->info.eip.ip4, forward_dport, dip, sport, dport, sip, sport, NULL); 
                set_rst_port(forward_dport, 1);
                set_rst_port(dest_port->source, 1);
                ret = NF_DROP;

            }
#endif
            if (zero_copy_load_succeed & OPENPORT_AUDIT_ENABLE) {
				//if (dest_addr->saddr != attack_dest_ip) 
                {
                    struct osec_openport_report *osec_report;
                    uint32_t idx = get_openport_audit_data(&osec_report);

                    osec_report->src_ip.pad[0] = 0;
                    osec_report->src_ip.pad[1] = 0;
                    osec_report->src_ip.pad[2] = 0;
                    osec_report->src_ip.ip4 = sip;
                    //osec_report->src_ip = attack_src_ip;
                    //osec_report->attack_dest_ip = attack_dest_ip;
                    osec_report->attack_dest_ip.ip4 = dip;
                    osec_report->src_port = visit_port;
                    osec_report->dest_port = ntohs(forward_dport);
                    //memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 
                    memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 
                    osec_report->pid = CURRENT_PID;
                    osec_report->type = nci->info.addr_type;
                    osec_report->dest_ip.ip4 = nci->info.eip.ip4;


                    struct netlink_netlog netlog_msg;
                    //LOG_INFO("zbuffer, eip.ip4:%u, srcip:%u.%u.%u.%u, sport:%u, destip:%u.%u.%u.%u, dport:%u attack%u.%u.%u.%u\n",\
                    nci->info.eip.ip4, IPQUADS(osec_report->src_ip.ip4), ntohs(osec_report->src_port), IPQUADS(osec_report->dest_ip.ip4), osec_report->dest_port, IPQUADS(osec_report->attack_dest_ip.ip4));

                    if (idx >= openport_audit_data_count - 1) 
                    {

                        uint32_t prev_idx = 0;
                        netlog_msg.max_idx = get_openport_audit_idx(&prev_idx, &idx);
                        netlog_msg.start_idx = prev_idx;
                        netlog_msg.end_idx = idx;
                        //LOG_INFO("open port idx=%d start idx:%d, end idx:%d......\n",idx, netlog_msg.start_idx, netlog_msg.end_idx);
                        rcu_read_unlock();
                        send_nl_data(NL_POLICY_NET_PORT_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
                        return ret;

                    } 
                    rcu_read_unlock();
                    return ret;

                }
            } else {
                struct osec_openport_report osec_report;

                osec_report.src_ip.pad[0] = 0;
                osec_report.src_ip.pad[1] = 0;
                osec_report.src_ip.pad[2] = 0;
                osec_report.src_ip.ip4 = sip;
                //osec_report->src_ip = attack_src_ip;
                //osec_report->attack_dest_ip = attack_dest_ip;
                osec_report.attack_dest_ip.ip4 = dip;
                osec_report.src_port = visit_port;
                osec_report.dest_port = ntohs(forward_dport);
                //memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 
                memcpy(osec_report.comm, CURRENT_COMM, sizeof(osec_report.comm)); 
                osec_report.pid = CURRENT_PID;
                osec_report.type = nci->info.addr_type;
                osec_report.dest_ip.ip4 = nci->info.eip.ip4;

                //LOG_INFO("upload ip and port report src_ip:%u.%u.%u.%u:%u-->%u.%u.%u.%u:%u, type:%u, desip_x:%u.%u.%u.%u\n",\
                    IPQUADS(osec_report.src_ip), osec_report.src_port, IPQUADS(osec_report.dest_ip), osec_report.dest_port, osec_report.type, IPQUADS(dest_addr->daddr));

                 rcu_read_unlock();
                send_nl_data(NL_POLICY_NET_PORT_NOTIFY, &osec_report, sizeof(struct osec_openport_report));
                return ret;
            }
        }


    }
    rcu_read_unlock();
    return ret;
}

#if 1
static int NetIsolateInfo_tcpudp_matching_v6( struct ipv6hdr* dest_addr, struct tcphdr* dest_port, int protocol_index, struct sk_buff *skb) 
{
    struct NetTcpUdpInfo* nci = NULL;
    struct NetTcpUdpInfo *last_nci = NULL;  // 记录上一次的 nci 地址
    struct list_head *pos;
    int ret = NF_ACCEPT;
    int nMatch = 0;
    int index_port = 0;
    int visit_port = ntohs(dest_port->dest);
    if(is_self_process()) {
        return NF_ACCEPT;
    }

    rcu_read_lock();
    list_for_each_entry_rcu(nci, &gListTcpPolicy.NETISOLATE_LIST, list) {
        // 检查当前 nci 地址是否与上一次相同
        if (last_nci == nci) {
            LOG_INFO("Duplicate nci address detected: %p, possible list corruption\n", nci);
            break;
        }
        last_nci = nci;  // 更新上一次的地址
        nMatch = 0;
        if (nci->info.is_ipv4 == 1) {
            continue;
        }
        if (nci->info.sip.as_u64[0] == 0 && nci->info.sip.as_u64[1] == 0 ) {
            nMatch = 1;
        } else if (memcmp(nci->info.sip.ip6, &dest_addr->daddr, sizeof(struct in6_addr)) == 0) {
            nMatch = 1;
        } else {
             nMatch = 1;
        }
//        LOG_INFO("xxxxxxxxxx,nci->sip:%u, nci->sport:%u, nci->eip:%u, nci->eport:%u, dest:%u, redirect port:%d\n",\
                nci->info.sip, nci->info.sport, nci->info.eip, nci->info.eport, visit_port, nci->info.redirectPort);
        //LOG_INFO("xxxxxxxxxx, srcip:%u, sport:%u, destip:%u, dport:%u",\
                dest_addr->saddr, ntohs(dest_port->source), dest_addr->daddr, visit_port);
        if (nMatch == 1) {
            if ((nci->info.sport == nci->info.eport) && (nci->info.sport == visit_port)) {
                nMatch = 2;
            } 
            if ((nci->info.sport < nci->info.eport) && (nci->info.sport <= visit_port) && (nci->info.eport >= visit_port) ) {
                nMatch = 2;
            }
        }
        if (nMatch == 2) {
            //命中上报日志 
		    struct in6_addr sip6, dip6;
            //memcpy(&sip6, dest_addr->saddr.in6_u.u6_addr16, sizeof(struct in6_addr));
            memcpy(&sip6, &dest_addr->saddr, sizeof(struct in6_addr));
            //memcpy(&dip6, dest_addr->daddr.in6_u.u6_addr16, sizeof(struct in6_addr));
            memcpy(&dip6, &dest_addr->daddr, sizeof(struct in6_addr));
            uint16_t forward_dport = 0;
#if 1            
			//uint16_t sport = dest_port->source, dport = dest_port->dest;
			if ( (nci->info.eip.as_u64[0] != 0 || nci->info.eip.as_u64[1] != 0) && (nci->info.dest_port_type == 1 || nci->info.redirectPort !=0) && visit_port >= nci->info.sport && visit_port <= nci->info.eport) {
                if (nci->info.dest_port_type == 1) {
                     forward_dport = dest_port->dest;
                } else {
                     forward_dport = htons(nci->info.redirectPort);
                }
                //uint32_t sip = dest_addr->saddr, dip = dest_addr->daddr;
                uint16_t sport = dest_port->source, dport = dest_port->dest;
                //session_cache_try_get(dest_addr->saddr, dest_port->source, dest_addr->daddr, dest_port->dest, dest_port->source, nci->info.eip, htons(nci->info.redirectPort), skb);
                //session_cache_try_get(nci->info.eip, htons(nci->info.redirectPort), dest_addr->daddr, dest_port->source, dest_port->dest, dest_addr->saddr, dest_port->source, NULL);
                session_cache_try_get_v6(&dest_addr->saddr, dest_port->source, &dest_addr->daddr, dest_port->dest, dest_port->source, (struct in6_addr *)nci->info.eip.ip6, forward_dport, skb);
                session_cache_try_get_v6((struct in6_addr *)nci->info.eip.ip6, forward_dport, &dip6, sport, dport, &sip6, sport, NULL); 
                set_rst_port(forward_dport, 1);
                set_rst_port(dest_port->source, 1);
                ret = NF_DROP;
            }
#endif
            if (zero_copy_load_succeed & OPENPORT_AUDIT_ENABLE) {

               struct osec_openport_report *osec_report;
                uint32_t idx = get_openport_audit_data(&osec_report);

                memcpy(osec_report->src_ip.ip6, sip6.in6_u.u6_addr16, sizeof(osec_report->src_ip.ip6));
                memcpy(osec_report->attack_dest_ip.ip6, dip6.in6_u.u6_addr16, sizeof(osec_report->attack_dest_ip.ip6));
                osec_report->src_port = visit_port;
                //osec_report->dest_port = nci->info.redirectPort;
                osec_report->dest_port = ntohs(forward_dport);
                memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 
                osec_report->pid = CURRENT_PID;
                osec_report->type = nci->info.addr_type;
                memcpy(osec_report->dest_ip.ip6,  nci->info.eip.ip6, sizeof(osec_report->dest_ip.ip6));


                struct netlink_netlog netlog_msg;
                //LOG_INFO("zbuffer, srcip:%u, sport:%u, destip:%u, dport:%u",\
                osec_report->src_ip, ntohs(osec_report->src_port), osec_report->dest_ip, osec_report->dest_port);

                if (idx >= openport_audit_data_count - 1) 
                {

                    uint32_t prev_idx = 0;
                    get_openport_audit_idx(&prev_idx, &idx);
                    netlog_msg.start_idx = prev_idx;
                    netlog_msg.end_idx = idx;
                //    LOG_INFO("open port idx=%d start idx:%d, end idx:%d......\n",idx, netlog_msg.start_idx, netlog_msg.end_idx);
                    rcu_read_unlock();
                    send_nl_data(NL_POLICY_NET_PORT_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
                    return ret;


                } 

            } else {
                struct osec_openport_report osec_report;
                //osec_report.src_ip = dest_addr->saddr;
                memcpy(osec_report.src_ip.ip6, sip6.in6_u.u6_addr16, sizeof(osec_report.src_ip.ip6));
                memcpy(osec_report.attack_dest_ip.ip6, dip6.in6_u.u6_addr16, sizeof(osec_report.attack_dest_ip.ip6));
                osec_report.src_port = visit_port;
                //osec_report.dest_port = nci->info.redirectPort;
                osec_report.dest_port = ntohs(forward_dport);
                memcpy(osec_report.comm, CURRENT_COMM, sizeof(osec_report.comm)); 
                osec_report.pid = CURRENT_PID;
                osec_report.type = nci->info.addr_type;
                //osec_report.dest_ip = nci->info.eip;
                memcpy(osec_report.dest_ip.ip6,  nci->info.eip.ip6, sizeof(osec_report.dest_ip.ip6));

                //LOG_INFO("upload ip and port report src_ip:%u.%u.%u.%u:%u-->%u.%u.%u.%u:%u, type:%u, desip_x:%u.%u.%u.%u\n",
                //    IPQUADS(osec_report.src_ip), osec_report.src_port, IPQUADS(osec_report.dest_ip), osec_report.dest_port, osec_report.type, IPQUADS(dest_addr->daddr));
                rcu_read_unlock();
                send_nl_data(NL_POLICY_NET_PORT_NOTIFY, &osec_report, sizeof(struct osec_openport_report));
                return ret;
            }
        }


    }
    rcu_read_unlock();
    return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static void netlog_audit_timer_function(struct timer_list *timer)
#else
static void netlog_audit_timer_function(unsigned long unused)
#endif
{
    uint32_t idx = 0, prev_idx = 0;
    struct netlink_netlog netlog_msg;

    if (unlikely(!atomic_is_timer_status_set(NETLOG_AUDIT_TIMER_ON))) {
        return;
    }
    netlog_msg.max_idx = get_in_netlog_audit_idx(&prev_idx, &idx);
    if (idx > prev_idx) {
        netlog_msg.start_idx = prev_idx;
        netlog_msg.end_idx = idx;
        //LOG_INFO("timer netdos_tcp_in start idx:%d, end idx:%d......\n",netlog_msg.start_idx, netlog_msg.end_idx);
        send_nl_data(NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
    }

    // 使用原子操作检查 NETLOG_AUDIT_TIMER_ON 状态位
    if (likely(atomic_is_timer_status_set(NETLOG_AUDIT_TIMER_ON))) {
        // 如果标志为 1，则重新调度定时器
        mod_timer(&netlog_audit_timer, jiffies + 60 * HZ);
    }

}

static int netdos_tcp_in(struct iphdr *iph, struct tcphdr* tcph, uint32_t u_type)
{
    if (!((iph->daddr & 0xFF) ^ 127)||!((iph->saddr & 0xFF) ^ 127) ){
        return NF_ACCEPT; 
    }   
	//LOG_INFO("in netdos_tcp_in [%s] %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u",\
			CURRENT_COMM,IPQUADS(iph->saddr), ntohs(tcph->source), IPQUADS(iph->daddr), ntohs(tcph->dest));

//    if (memcmp("swapper", CURRENT_COMM, 7) ==0 ) {
//        return NF_ACCEPT;
//    }
    if(is_self_process()) {
        return NF_ACCEPT;
    }
//    if (memcmp(CURRENT_COMM, "MagicArmor", 10) == 0) {
//        return NF_ACCEPT;
//    }
//    if (memcmp("ksoftirqd", CURRENT_COMM, strlen("ksoftirqd")) ==0 ) {
//        return NF_ACCEPT;
//    }


//        LOG_INFO("in netdos_tcp_in %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u",\
        IPQUADS(iph->saddr), ntohs(tcph->source), IPQUADS(iph->daddr), ntohs(tcph->dest));
//    if (is_business_port(ntohs(tcph->dest)) == 0) {
//        return NF_ACCEPT;
//    }
        //LOG_INFO("111in netdos_tcp_in %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u",\
        IPQUADS(iph->saddr), ntohs(tcph->source), IPQUADS(iph->daddr), ntohs(tcph->dest));

    if (zero_copy_load_succeed & IN_NETLOG_AUDIT_ENABLE) {
        struct osec_network_report *osec_report;
        uint32_t idx = get_in_netlog_audit_data(&osec_report);
        osec_report->src.pad[0] = 0;
        osec_report->src.pad[1] = 0;
        osec_report->src.pad[2] = 0;
        osec_report->src.ip4 = iph->saddr;
        osec_report->src_port = tcph->source;
        osec_report->dst.pad[0] = 0;
        osec_report->dst.pad[1] = 0;
        osec_report->dst.pad[2] = 0;
        osec_report->dst.ip4 = iph->daddr;
        osec_report->dest_port = tcph->dest;
        osec_report->pid = CURRENT_PID;
        //memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 
        memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 

        //osec_report->type = u_type;

        //LOG_DEBUG("netdos_tcp_in ......");
        struct netlink_netlog netlog_msg;
        if (idx >= in_netlog_audit_data_count - 1) {
            uint32_t prev_idx = 0;
            netlog_msg.max_idx = get_in_netlog_audit_idx(&prev_idx, &idx);
            netlog_msg.start_idx = prev_idx;
            netlog_msg.end_idx = in_netlog_audit_data_count - 1;
            //LOG_INFO("netdos_tcp_in idx=%d start idx:%d, end idx:%d......\n",idx, netlog_msg.start_idx, netlog_msg.end_idx);
            send_nl_data(NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
            
        }

    } else {
        struct osec_network_report_old osec_report;
        osec_report.src.pad[0] = 0;
        osec_report.src.pad[1] = 0;
        osec_report.src.pad[2] = 0;
        osec_report.src.ip4 = iph->saddr;
        osec_report.src_port = tcph->source;
        osec_report.dst.pad[0] = 0;
        osec_report.dst.pad[1] = 0;
        osec_report.dst.pad[2] = 0;
        osec_report.dst.ip4 = iph->daddr;
        osec_report.dest_port = tcph->dest;
        memcpy(osec_report.comm, CURRENT_COMM, sizeof(osec_report.comm)); 
        osec_report.pid = CURRENT_PID;
        osec_report.type = u_type;
        //LOG_DEBUG("netdos_tcp_in ......");
        send_nl_data(NL_POLICY_NET_CONNECT_PORT_NOTIFY, &osec_report, sizeof(struct osec_network_report_old));

    }


    return NF_ACCEPT;
}


static int netdos_tcp_in_v6(struct ipv6hdr *ip6h, struct tcphdr* tcph, uint32_t u_type)
{
#if 0
    if (memcmp("swapper", CURRENT_COMM, 7) ==0 ) {
        return NF_ACCEPT;
    }
    if (memcmp(CURRENT_COMM, "MagicArmor", 10) == 0) {
        return NF_ACCEPT;
    }
    if (memcmp("ksoftirqd", CURRENT_COMM, strlen("ksoftirqd")) ==0 ) {
        return NF_ACCEPT;
    }
#endif
//    LOG_INFO("in netdos_tcp_in_v6 process:%s, %pI6:%u-->%pI6:%u Protocol: %d\n", \
          CURRENT_COMM, &ip6h->saddr, ntohs(tcph->source),&ip6h->daddr, ntohs(tcph->dest), ip6h->nexthdr);  


    if (zero_copy_load_succeed & IN_NETLOG_AUDIT_ENABLE) {
        struct osec_network_report *osec_report;
        uint32_t idx = get_in_netlog_audit_data(&osec_report);

        memcpy(osec_report->src.ip6, ip6h->saddr.in6_u.u6_addr16, sizeof(osec_report->src.ip6));
        osec_report->src_port = tcph->source;
        memcpy(osec_report->dst.ip6, ip6h->daddr.in6_u.u6_addr16, sizeof(osec_report->dst.ip6));
        osec_report->dest_port = tcph->dest;
        osec_report->pid = CURRENT_PID;
          memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 
        //osec_report->type = u_type;

        //LOG_DEBUG("netdos_tcp_in ......");
        struct netlink_netlog netlog_msg;
        if (idx >= in_netlog_audit_data_count - 1) {
            uint32_t prev_idx = 0;
            netlog_msg.max_idx = get_in_netlog_audit_idx(&prev_idx, &idx);
            netlog_msg.start_idx = prev_idx;
            netlog_msg.end_idx = in_netlog_audit_data_count - 1;
            //LOG_INFO("netdos_tcp_in idx=%d start idx:%d, end idx:%d......\n",idx, netlog_msg.start_idx, netlog_msg.end_idx);
            send_nl_data(NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
            
        }

    } else {
        struct osec_network_report_old osec_report;
        memcpy(osec_report.src.ip6, ip6h->saddr.in6_u.u6_addr16, sizeof(osec_report.src.ip6));
        osec_report.src_port = tcph->source;
        memcpy(osec_report.dst.ip6, ip6h->daddr.in6_u.u6_addr16, sizeof(osec_report.dst.ip6));
        osec_report.dest_port = tcph->dest;
        memcpy(osec_report.comm, CURRENT_COMM, sizeof(osec_report.comm)); 
        osec_report.pid = CURRENT_PID;
        osec_report.type = u_type;
        //LOG_DEBUG("netdos_tcp_in ......");
        send_nl_data(NL_POLICY_NET_CONNECT_PORT_NOTIFY, &osec_report, sizeof(struct osec_network_report_old));
    }


    return NF_ACCEPT;
}


struct dns_header {
  uint16_t transaction_id, flags, num_queries, answer_rrs, authority_rrs, additional_rrs;
} __attribute__((packed));

struct answer_header {
  uint16_t name, type, class;
  uint32_t ttlv;
  uint16_t dlen;
  uint8_t address[0];
} __attribute__((packed));



static int parse_domain(const u8 *data, int data_len, u8 *dns_buf)
{

    int i = 0, j = 0;
    u8 field_len = 0;
    do {
       field_len = data[i];
       if (field_len == 0) {
         break;
       }
       ++ i;
       memcpy(dns_buf + j, data + i, field_len);
       i += field_len;
       j += field_len;
       dns_buf[j] = '.';
       ++ j;
    } while(i < data_len - 1);
    dns_buf[j - 1] = '\0';
    return i; 
}

static int parse_domain_zcopy(const u8 *data, int data_len,  struct osec_dns_report **report, uint32_t *idx)
{

    u8 field_pos[8];
    u8 field_count = 0;
    int i = 0, j = 0;
    u8 field_len = 0;
    do {
       field_len = data[i];
       if (field_len == 0 || j >= 7) {
         break;
       }
       field_pos[j++] = field_len;
       i++;
       //LOG_INFO("field_len=%d\n", field_len);
       i += field_len;
    } while(i < data_len - 1);
    if (likely(j > 0)) {
        if (*(uint16_t *)(data + i + 1) == 0x0100 || *(uint16_t *)(data + i + 1) == 0x1c00) {
            *idx = get_dns_netlog_audit_data(report);
            int m = 0, n = 0, k;
            for (k = 0; k < j; k++) {
                n++;
                memcpy((*report)->dns_name + m, data + n, field_pos[k]);
                m += field_pos[k];
                n += field_pos[k];
                if (k < j - 1) {
                    (*report)->dns_name[m] = '.';
                    ++m;
                }
            }
            //LOG_INFO("============dns_name[%s]\n",(*report)->dns_name);
        } else {
            return -1;
        }
    }
    return i; 
}

static int netdos_tcp_proc(struct sk_buff *skb, struct iphdr *ip_header_)
{
    struct tcphdr *tcp_header_ = NULL;
    int ret = 0;
    int acl_type = 0;

	int lay4_len;
 	int tcp_checksum = -1;
    tcp_header_ = (struct tcphdr *)((__u32 *)ip_header_ + ip_header_->ihl);
    lay4_len = skb->len - (ip_header_->ihl << 2);
#if 0
    if(is_self_process()) {
        return NF_ACCEPT;
    }
#endif
    if ((tcp_header_->syn == 1) && (tcp_header_->ack == 0)) {

        //if (ip_header_->saddr == server_ip||ip_header_->saddr == ip_header_->daddr) {
        //    return NF_ACCEPT;
        //}
        //LOG_INFO("syn  %u-%u.%u.%u.%u:%u-->%u.%u.%u.%u:%u process[%s]\n",\
        ip_header_->saddr,IPQUADS(ip_header_->saddr), ntohs(tcp_header_->source), IPQUADS(ip_header_->daddr), ntohs(tcp_header_->dest), CURRENT_COMM);
        //read_lock_bh(&g_ntcp_policy_lock);
#if 0
        if (is_net_dos_enable())
        {
            ret = NetIsolateInfo_tcpudp_matching(ip_header_, tcp_header_, 1, skb);
            acl_type = gListTcpPolicy.acl_type;
        }
        //read_unlock_bh(&g_ntcp_policy_lock);
        if (net_syslog_enable) {
            netdos_tcp_in(ip_header_, tcp_header_, 2);
        }
#else
        //if (net_syslog_enable) 

//        LOG_INFO("00 [%u.%u.%u.%u:%u->%u.%u.%u.%u:%u]\n", IPQUADS(ip_header_->saddr), ntohs(tcp_header_->source), IPQUADS(ip_header_->daddr), ntohs(tcp_header_->dest));
        if (is_business_port(ntohs(tcp_header_->dest))) {
            if (is_syslog_inner_enable()) {
               // LOG_INFO("[%u.%u.%u.%u:%u->%u.%u.%u.%u:%u]\n", IPQUADS(ip_header_->saddr), ntohs(tcp_header_->source), IPQUADS(ip_header_->daddr), ntohs(tcp_header_->dest));
                netdos_tcp_in(ip_header_, tcp_header_, 2);
            }
        } else {
            if (is_net_dos_enable())
            {
                ret = NetIsolateInfo_tcpudp_matching(ip_header_, tcp_header_, 1, skb);
                //acl_type = gListTcpPolicy.acl_type;
                //LOG_INFO("====  %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u process[%s] ret=%d\n",\
                        IPQUADS(ip_header_->saddr), ntohs(tcp_header_->source), IPQUADS(ip_header_->daddr), ntohs(tcp_header_->dest), CURRENT_COMM, ret);


                return ret;
            }
        }


#endif
    } else {
#if 1
			//LOG_INFO("before session_cache_lookup  %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u process[%s]\n",\
        IPQUADS(ip_header_->saddr), ntohs(tcp_header_->source), IPQUADS(ip_header_->daddr), ntohs(tcp_header_->dest), CURRENT_COMM);
 
#if 1
        //if (is_business_port(ntohs(tcp_header_->source) == 0)) 
        {
            if (session_cache_lookup(ip_header_->saddr, tcp_header_->source, ip_header_->daddr, tcp_header_->dest, skb)) {
                return NF_DROP;
            }
        }
#endif

#endif
    }
    return NF_ACCEPT;
}
#if 0
static inline uint32_t getNameLength(uint32_t i, const uint8_t *payload, uint32_t payloadLen) 
{
    if(payload[i] == 0x00)
        return(1);
    else if(payload[i] == 0xC0)
        return(2);
    else {
        u_int8_t len = payload[i];
        u_int8_t off = len + 1;

        if(off == 0) /* Bad packet */
            return(0);
        else
            return(off + getNameLength(i+off, payload, payloadLen));
    }
}
#else
static uint32_t getNameLength(uint32_t i, const uint8_t *payload, uint32_t payloadLen)
{
    uint32_t total = 0;
    int hops = 0;

    while (i < payloadLen) {
        if (hops > 10)
            return 0;

        uint8_t b = payload[i];
        if (b == 0x00) {
            total += 1; 
            return total;
        } else if ((b & 0xC0) == 0xC0) {
            if (i + 1 >= payloadLen)
                return 0; // 截断包
            total += 2;
            return total;
        } else {
            // 普通标签
            uint8_t len = b;
            if (len > 63) // DNS 标签长度不能超过 63
                return 0; // 无效包

            uint32_t next = i + 1 + len;
            if (next > payloadLen)
                return 0; // 越界

            total += 1 + len;
            i = next;
        }
    }

    return 0;
}
#endif
static inline uint16_t get16(int *i, const uint8_t *payload) {
  uint16_t v = *(const uint16_t*)&payload[*i];
  (*i) += 2;
  return(ntohs(v));
}


static int netisolate_dns_process(struct sk_buff* skb, struct udphdr *udp_header_,  struct osec_dns_report *report, u_int payload_len) 
{
#define MAX_DNS_REQUESTS            16

    if (unlikely(payload_len < sizeof(struct dns_header))) {
        return -1;
    }

    u8 *payload = (((u8 *) udp_header_) + sizeof(struct udphdr));
    struct dns_header *dns = (struct dns_header*)payload;
    uint8_t  is_dns = 0;
    uint32_t ret_code;

    int num_a_records = 0;
    uint8_t host_server_name[256]; 
    uint32_t a_record[MAX_DNS_REQUESTS] = { 0 };

    uint32_t query_offset, i;
    ret_code = dns->flags& 0x80 ? 0 : (dns->flags & 0x0F00);
    i = sizeof(struct dns_header);
    query_offset = i;
    int k = 0;
    if( dns->flags& 0x80) {
        /* DNS Reply */
        if((ntohs(dns->num_queries) <= MAX_DNS_REQUESTS)
                && (((ntohs(dns->answer_rrs) > 0) && (ntohs(dns->answer_rrs) <= MAX_DNS_REQUESTS))
                    || (( ntohs(dns->authority_rrs) > 0) && ( ntohs(dns->authority_rrs) <= MAX_DNS_REQUESTS))
                    || ((ntohs(dns->additional_rrs) > 0) && (ntohs(dns->additional_rrs) <= MAX_DNS_REQUESTS)))
          ) {
            is_dns = 1;
            if (unlikely(payload[i + 1] == '\0')) {
                return -1;
            }
            //LOG_INFO("=====================================[%d]===\n",payload[i]);
            i += parse_domain((u8 *)(dns + 1) , payload_len - i, report->dns_name);
            i += 5;
            //LOG_INFO("=====================================[%x]===payload_len=%d, dns_name[%s]\n",payload[i], payload_len, report->dns_name);

            uint16_t rsp_type, rsp_class;
            uint16_t num;
            uint16_t answer_rrs = ntohs(dns->answer_rrs);

            for(num = 0; num < answer_rrs; num++) {
                uint16_t data_len;
                if((i + 6) >= payload_len) {
                    break;
                }

                if((data_len = getNameLength(i, (uint8_t *)payload, payload_len)) == 0) {
                    break;
                } else
                    i += data_len;
                rsp_type = get16(&i, (uint8_t *)payload);
                rsp_class = get16(&i, (uint8_t *)payload);
                //LOG_INFO("type:%x,class:%x\n",rsp_type, rsp_class);
                i += 4;
                data_len = get16(&i, (uint8_t *)payload);

                if((data_len <= 1) || (data_len > (payload_len - i))) {
                    break;
                }
                
                if(rsp_type == 1 /* A */) {
                    if(data_len == 4) {
                        //u_int32_t v = ntohl(*((u_int32_t*)&ssv->payload[i]));
                        report->ipv4[k++] =  *((u_int32_t*)&payload[i]);
                        //LOG_INFO("dns res ip %u.%u.%u.%u\n", IPQUADS(report->res_ip[k - 1]));
                        if (k >= 6) {
                            break;
                        }
                    }
                }

                if(data_len == 0) {
                    break;
                }

                i += data_len;

            }
        }
    }
    return k > 0 ? 0: 1;
}

static inline int process_dns(const struct iphdr *iph, const struct udphdr *udph, const uint32_t payload_len)
{
#define MAX_DNS_REQUESTS            16

    struct osec_dns_report osec_report;
    if (unlikely(payload_len < sizeof(struct dns_header))) {
        return -1;
    }
    u8 *payload = (((u8 *) udph) + sizeof(struct udphdr));
    struct dns_header *dns = (struct dns_header*)payload;

    uint32_t  i;
    i = sizeof(struct dns_header);
    int k = 0;
    if( dns->flags& 0x80) {
        /* DNS Reply */
        if((ntohs(dns->num_queries) <= MAX_DNS_REQUESTS)
                && (((ntohs(dns->answer_rrs) > 0) && (ntohs(dns->answer_rrs) <= MAX_DNS_REQUESTS))
                    || (( ntohs(dns->authority_rrs) > 0) && ( ntohs(dns->authority_rrs) <= MAX_DNS_REQUESTS))
                    || ((ntohs(dns->additional_rrs) > 0) && (ntohs(dns->additional_rrs) <= MAX_DNS_REQUESTS)))
          ) {
            if (unlikely(payload[i + 1] == '\0')) {
                return -1;
            }

            osec_report.src_ip = iph->saddr;
            osec_report.src_port = udph->source;
            osec_report.dest_ip = iph->daddr;
            osec_report.dest_port = udph->source;
            memcpy(osec_report.comm, CURRENT_COMM, sizeof(osec_report.comm)); 
            osec_report.pid = CURRENT_PID;

            //LOG_INFO("zbuffer, srcip:%u, sport:%u, destip:%u, dport:%u",\
            osec_report->src_ip, ntohs(osec_report->src_port), osec_report->dest_ip, osec_report->dest_port);




            i += parse_domain((u8 *)(dns + 1) , payload_len - i, osec_report.dns_name);
            i += 5;
            //LOG_INFO("=====================================[%x]===payload_len=%d, dns_name[%s]\n",payload[i], payload_len, osec_report.dns_name);

            uint16_t rsp_type, rsp_class;
            uint16_t num;
            uint16_t answer_rrs = ntohs(dns->answer_rrs);

            for(num = 0; num < answer_rrs; num++) {
                uint16_t data_len;
                if((i + 6) >= payload_len) {
                    break;
                }

                if((data_len = getNameLength(i, (uint8_t *)payload, payload_len)) == 0) {
                    break;
                } else
                    i += data_len;
                rsp_type = get16(&i, (uint8_t *)payload);
                rsp_class = get16(&i, (uint8_t *)payload);
                //LOG_INFO("type:%x,class:%x\n",rsp_type, rsp_class);
                i += 4;
                data_len = get16(&i, (uint8_t *)payload);

                if((data_len <= 1) || (data_len > (payload_len - i))) {
                    break;
                }

                if(rsp_type == 1 /* A */) {
                    if(data_len == 4) {
                        //u_int32_t v = ntohl(*((u_int32_t*)&ssv->payload[i]));
                        osec_report.ipv4[k++] =  *((u_int32_t*)&payload[i]);
                        //LOG_INFO("nomal dns res ip %u.%u.%u.%u\n", IPQUADS(osec_report.res_ip[k - 1]));
                        if (k >= 6) {
                            break;
                        }
                    }
                }

                if(data_len == 0) {
                    break;
                }

                i += data_len;

            }
            //LOG_INFO("nomal send dns info============\n");
            send_nl_data(NL_POLICY_NET_DNS_PORT_NOTIFY, &osec_report, sizeof(struct osec_dns_report));
        }
    }
    return 0;
}

void ipv6_to_string(uint16_t *ipv6, char *str) {
    int i, zero_flag = 0, zero_count = 0, n = 0;
    uint8_t *tmp;
    for (i = 0; i < 8; i++) {
        tmp = (uint8_t *)(ipv6 + i);
        if (ipv6[i] != 0) {
            if (zero_flag == 0) {
                if (tmp[0] >= 0x100) {
                    n += snprintf(str + n, 46 - n, "%02x", tmp[0]);
                } else {
                    n += snprintf(str + n, 46 - n, "%01x", tmp[0]);
                }
                n += snprintf(str + n, 46 - n, "%02x:", tmp[1]);
            } else {
                if (tmp[0] >= 0x100) {
                    n += snprintf(str + n, 46 - n, ":%02x", tmp[0]);
                } else {
                    n += snprintf(str + n, 46 - n, ":%01x", tmp[0]);
                }
                n += snprintf(str + n, 46 - n, "%02x:", tmp[1]);
            }
            zero_flag = 0;
            zero_count = 0;
        } else {
            zero_flag = 1;
            ++ zero_count;
        }
    }
    if (zero_count > 1) {
        strncat(str,  ":", 1);
    }
}
  
static inline int process_dns_zcopy(const struct iphdr *iph, const struct udphdr *udph, const uint32_t payload_len)
{
#define MAX_DNS_REQUESTS            16

    struct osec_dns_report *osec_report;
    if (unlikely(payload_len < sizeof(struct dns_header))) {
        return -1;
    }
    u8 *payload = (((u8 *) udph) + sizeof(struct udphdr));
    struct dns_header *dns = (struct dns_header*)payload;

    uint32_t  i;
    i = sizeof(struct dns_header);
    int k = 0;
    if( dns->flags& 0x80) {
        /* DNS Reply */
#if 0 
        if((ntohs(dns->num_queries) <= MAX_DNS_REQUESTS)
                && (((ntohs(dns->answer_rrs) > 0) && (ntohs(dns->answer_rrs) <= MAX_DNS_REQUESTS))
                    || (( ntohs(dns->authority_rrs) > 0) && ( ntohs(dns->authority_rrs) <= MAX_DNS_REQUESTS))
                    || ((ntohs(dns->additional_rrs) > 0) && (ntohs(dns->additional_rrs) <= MAX_DNS_REQUESTS)))
          ) 
#else
        if((ntohs(dns->num_queries) <= MAX_DNS_REQUESTS)
                && ((ntohs(dns->answer_rrs) > 0) && (ntohs(dns->answer_rrs) <= MAX_DNS_REQUESTS))
          ) 
#endif
          {
            if (unlikely(payload[i + 1] == '\0')) {
                return -1;
            }
            //LOG_INFO("zbuffer, srcip:%u, sport:%u, destip:%u, dport:%u",\
            osec_report->src_ip, ntohs(osec_report->src_port), osec_report->dest_ip, osec_report->dest_port);

            uint32_t idx = 0;
            int _i = parse_domain_zcopy((u8 *)(dns + 1) , payload_len - i, &osec_report, &idx);
            if (unlikely(_i <= 0)) {
                return -1;
            }
            i += _i;
            i += 5;
            osec_report->src_ip = iph->saddr;
            osec_report->src_port = udph->source;
            osec_report->dest_ip = iph->daddr;
            osec_report->dest_port = udph->source;
            memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 
            osec_report->pid = CURRENT_PID;



            uint16_t rsp_type, rsp_class;
            uint16_t num;
            uint16_t answer_rrs = ntohs(dns->answer_rrs);

            //LOG_INFO("====process:%s[%s]=====================answer_rrs=[%d]===========[%x]===payload_len=%d, dns_name[%s]\n",osec_report->comm, CURRENT_COMM, answer_rrs, payload[i], payload_len, osec_report->dns_name);
            struct answer_header  *ans;
            for(num = 0; num < answer_rrs; num++) {
                if (i > payload_len) {
                    break;
                }
                ans = (struct answer_header *)(payload + i);
                if (likely(ans->name == 0x0cc0)) {
                    switch(ans->type) {
                        case 0x1c00:
                            {
                                if(likely(k < 3 && ntohs(ans->dlen) == 16)) {
                                    //u_int32_t v = ntohl(*((u_int32_t*)&ssv->payload[i]));
                                    memcpy(osec_report->ipv6 + k * 16, ans->address, 16);

                                    //LOG_INFO("===============dns ipv6 is :%pI6\n", ans->address);
                                    //char tmp_buf[50] = {0};
                                    //ipv6_to_string((uint16_t *)(osec_report->ipv6 + k * 16), tmp_buf);  
                                    //LOG_INFO("=====ipv6:[%s]\n", tmp_buf);
                                    ++osec_report->ip_cnt;
                                    i += 16;
                                    ++k;
                                }
                                osec_report->is_ipv6 = 1;
                                break;
                            }
                        case 0x0100:
                            {
                                if(likely( k < 12 && ntohs(ans->dlen) == 4)) {
                                    //u_int32_t v = ntohl(*((u_int32_t*)&ssv->payload[i]));
                                    osec_report->ipv4[k] =  *((u_int32_t*)ans->address);
                                    //LOG_INFO("dns res ip %u.%u.%u.%u\n", IPQUADS(osec_report->ipv4[k]));
                                    ++osec_report->ip_cnt;
                                    i += 4;
                                    k++;
                                }

                            }
                        default:
                            break;
                    }

                }

                i += sizeof(struct answer_header);
            }

            struct netlink_netlog netlog_msg;
            if (idx >= dns_netlog_audit_data_count - 1) 
            {

                uint32_t prev_idx = 0;
                netlog_msg.max_idx = get_dns_netlog_audit_idx(&prev_idx, &idx);
                netlog_msg.start_idx = prev_idx;
                netlog_msg.end_idx = idx;
                //LOG_INFO("open port idx=%d start idx:%d, end idx:%d......\n",idx, netlog_msg.start_idx, netlog_msg.end_idx);
                send_nl_data(NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));

            } 
        }
    }
    return 0;
}


static unsigned int _nf_hold_func_netdos(unsigned int holdnum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    struct iphdr *ip_header_ = NULL;
    __be16 tmp_port = 0;
    int ret = NF_ACCEPT;

    if (unlikely(is_close_net_business() == 1)) {
        return NF_ACCEPT;
    }
    if (unlikely(skb == NULL)) {
        return NF_ACCEPT;
    }
    ip_header_ = kosecs_ip_hdr(skb);

    if (!ip_header_) {
        return NF_ACCEPT;
    }

    //127.0.0.1过滤
    if (out != NULL) {
        if (out->flags & IFF_LOOPBACK){
            return NF_ACCEPT; 
        }   
    }   
    else {
        if (ip_header_->daddr == 2130706433){
            return NF_ACCEPT; 
        }   
    } 
    if(is_self_process()) {
        return NF_ACCEPT;
    }

//    if (memcmp("Magic", CURRENT_COMM, 5) == 0) {
//        return NF_ACCEPT;
//    }
    if (memcmp(CURRENT_COMM, "MagicArmor", 10) == 0) {
        return NF_ACCEPT;
    }

#if 0 
    if (memcmp("swapper", CURRENT_COMM, 7) ==0 ) {
        return NF_ACCEPT;
    }
#endif    

#if 0
    if (net_block_enable == 1) {
        ret = netblock_match(ip_header_);
        if (ret >0) {
            LOG_INFO("disable network visit\n");
            return  NF_DROP;
        }
    } 
#else
#if 0
    if (net_block_enable == 1) 
    {

        if (conn_block_check(ntohl(ip_header_->saddr))) {
            //            LOG_INFO("disable network visit\n");
            return  NF_DROP;
        }
    }
#endif    
#endif


    switch(ip_header_->protocol) {
        case IPPROTO_TCP: 
            {
                if (is_syslog_inner_enable() || is_net_dos_enable()) 
                {
//                    if(is_self_process()) {
//                        return NF_ACCEPT;
//                    }
                    return netdos_tcp_proc(skb, ip_header_);
                }
                break;
            }
        case IPPROTO_UDP: 
            {
                if (is_syslog_dns_enable()) {
                    struct udphdr *udph = NULL,_uh;
                    udph = ((struct udphdr*)(skb->data + ip_hdr(skb)->ihl * 4));
                    if(!udph) { return NF_ACCEPT; }
                    if(udph->source == __constant_htons(53)) {

                        //LOG_INFO("dns netlog  [%u.%u.%u.%u:%u-->%u.%u.%u.%u:%u]......\n", IPQUADS(ip_header_->saddr),ntohs(udph->source), IPQUADS(ip_header_->daddr), ntohs(udph->dest));
                        u_int uhoffset = skb->len - ip_header_->ihl * 4 - sizeof(struct udphdr);
                        if (likely(zero_copy_load_succeed & DNS_NETLOG_AUDIT_ENABLE)) {
                            process_dns_zcopy(ip_header_, udph,uhoffset);
                        } else {
                            process_dns(ip_header_, udph,uhoffset);
                        }
                    }
                }
                break;
            }
        default:
            break;
    }
    return NF_ACCEPT;
#if 0
    if( (!net_syslog_enable) && (!is_net_dos_enable())) {
        return NF_ACCEPT;
    }

    if (ip_header_->protocol == IPPROTO_TCP) {
        return netdos_tcp_proc(skb, ip_header_);
    }
    // else if (ip_header_->protocol == IPPROTO_ICMP) {
    //     return netdos_icmp_proc(skb, ip_header_);
    // } 

    if (is_syslog_dns_enable() &&ip_header_->protocol == IPPROTO_UDP) {
        struct udphdr *udph = NULL,_uh;
        udph = ((struct udphdr*)(skb->data + ip_hdr(skb)->ihl * 4));
        if(!udph) { return NF_ACCEPT; }
        if(udph->source == __constant_htons(53)) {

            //LOG_INFO("dns netlog  [%u.%u.%u.%u:%u-->%u.%u.%u.%u:%u]......\n", IPQUADS(ip_header_->saddr),ntohs(udph->source), IPQUADS(ip_header_->daddr), ntohs(udph->dest));
            u_int uhoffset = skb->len - ip_header_->ihl * 4 - sizeof(struct udphdr);
            if (likely(zero_copy_load_succeed & DNS_NETLOG_AUDIT_ENABLE)) {
                process_dns_zcopy(ip_header_, udph,uhoffset);
            } else {
                process_dns(ip_header_, udph,uhoffset);
            }
        }
    }
    return NF_ACCEPT;
#endif
}

static unsigned int _nf_hold_func_netdos_v6(unsigned int holdnum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    __be16 tmp_port = 0;
    int acl_type = 0;
    int ret = NF_ACCEPT;
    if (unlikely(is_close_net_business() == 1)) {
        return NF_ACCEPT;
    }

    if (unlikely(skb == NULL)) {
        return NF_ACCEPT;
    }

    if((!is_syslog_inner_enable()) && (!is_net_dos_enable())) {
        return NF_ACCEPT;
    }
    // 确保数据包是完整的，并且包含IPv6头和TCP头  
    if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr)))  
        return NF_ACCEPT;  

    struct ipv6hdr *ip6h = ipv6_hdr(skb);  
    if (!ip6h) {
        return NF_ACCEPT;
    }
    //127.0.0.1过滤
    if (out != NULL) {
        if (out->flags & IFF_LOOPBACK){
            return NF_ACCEPT; 
        }   
    }   
    else {
        struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;  
        if (ipv6_addr_equal(&ip6h->daddr, &loopback_addr)  || *(uint16_t *)&ip6h->saddr == 0x80fe || *(uint16_t *)&ip6h->daddr == 0x80fe) {  
            return NF_ACCEPT; 
        }  
    } 

    if(is_self_process()) {
        return NF_ACCEPT;
    }

#if 0    
    if (memcmp("Magic", CURRENT_COMM, 5) == 0) {
        return NF_ACCEPT;
    }
    if (memcmp("swapper", CURRENT_COMM, 7) ==0 ) {
        return NF_ACCEPT;
    }
#endif    


    uint16_t sport = 0, dport = 0;
    switch(ip6h->nexthdr) {
        case IPPROTO_TCP: {
             struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1); 
             sport = tcph->source;
             dport = tcph->dest;

             if ((tcph->syn == 1) && (tcph->ack == 0)) {

                 if (is_business_port(ntohs(tcph->dest))) {
                     if ( is_syslog_inner_enable()) {
                         netdos_tcp_in_v6(ip6h, tcph, 2);
                     }
                 } else {
                     if (is_net_dos_enable())
                     {
                         ret = NetIsolateInfo_tcpudp_matching_v6(ip6h, tcph, 1, skb);
                         //acl_type = gListTcpPolicy.acl_type;
                         return ret;
                     }
                 }

             } else {
                 if (session_cache_lookup_v6(&ip6h->saddr, tcph->source, &ip6h->daddr, tcph->dest, skb)) {
                     return NF_DROP;
                 }
             }
             break;
                          
            }
        case IPPROTO_UDP: {
             struct udphdr *udph = (struct udphdr *)(ip6h + 1);  
             sport = udph->source;
             dport = udph->dest;
            break;
        }
        default:
            return NF_ACCEPT;
            break;
    }
    //LOG_INFO("process:%s,Src IP: %pI6, Dest IP: %pI6, Src Port: %d, Dest Port: %d, Protocol: %d\n",  \
          CURRENT_COMM, &ip6h->saddr, &ip6h->daddr, ntohs(sport), ntohs(dport), ip6h->nexthdr);  


    return NF_ACCEPT;
}



static int modify_dst_ip(struct sk_buff *skb, u32 dip, uint16_t dport)
{
	struct sk_buff *nskb;
	struct iphdr *nih;
	struct tcphdr *nth;
    struct dst_entry *dst = NULL;
    struct rtable *rt = NULL;
    nih = ip_hdr(skb);  
    nth = (struct tcphdr *)((__u32 *)nih + nih->ihl);

    if (nth && (ipv4_stonl("10.0.12.10") == dip ) && ntohs(nth->dest) ==  5000) {
        nih->check = 0;
        nih->daddr = ipv4_stonl("1.1.1.10");

        //nth = tcp_hdr(nskb);  
        nth = (struct tcphdr *)((__u32 *)nih + nih->ihl);
        //nth->dest= dport;
        ip_send_check(nih);
    } 
    return 0;
}


static unsigned int _nf_pre_routing_hold_func_netdos(unsigned int holdnum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
	struct iphdr *ip_header_ = NULL;
    __be16 tmp_port = 0;
    int ret = NF_ACCEPT;

    if (unlikely(is_close_net_business() == 1)) {
        return NF_ACCEPT;
    }

    if (unlikely(skb == NULL)) {
        return NF_ACCEPT;
    }

    ip_header_ = kosecs_ip_hdr(skb);
    
    if (!ip_header_) {
        return NF_ACCEPT;
    }
    struct tcphdr *tcph = NULL;

    tcph = (struct tcphdr *)((__u32 *)ip_header_ + ip_header_->ihl);

    //modify_dst_ip(skb, ip_header_->daddr, tcph->dest);
    //return NF_ACCEPT;


    //127.0.0.1过滤
    if (out != NULL) {
        if (out->flags & IFF_LOOPBACK){
            return NF_ACCEPT; 
        }   
    }   
    else {
        if (ip_header_->daddr == 2130706433){
            return NF_ACCEPT; 
        }   
    } 
    if (ip_header_->daddr == server_ip||ip_header_->saddr == server_ip){
        return NF_ACCEPT; 
    }   

    if(is_self_process()) {
        return NF_ACCEPT;
    }


    if (is_internel_enable() == 0) {
        return  NF_DROP;
    }

    if (memcmp("Magic", CURRENT_COMM, 5) == 0) {
        return NF_ACCEPT;
    }
    if (is_net_block_enable()) 
    {

            //LOG_INFO("disable network visit[%u.%u.%u.%u->%u.%u.%u.%u]\n", IPQUADS(ip_header_->saddr), IPQUADS(ip_header_->daddr));
        if (conn_block_check(ntohl(ip_header_->saddr))) {
            //LOG_INFO("disable network visit[%u.%u.%u.%u->%u.%u.%u.%u]\n", IPQUADS(ip_header_->saddr), IPQUADS(ip_header_->daddr));
            return  NF_DROP;
        }
    } 
    return NF_ACCEPT;
}


static unsigned int _nf_pre_routing_hold_v6_func_netdos(unsigned int holdnum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    __be16 tmp_port = 0;
    int ret = NF_ACCEPT;
    if (unlikely(is_close_net_business() == 1)) {
        return NF_ACCEPT;
    }

    if (unlikely(skb == NULL)) {
        return NF_ACCEPT;
    }

    struct ipv6hdr *ip6h = ipv6_hdr(skb);  
    if (!ip6h) {
        return NF_ACCEPT;
    }
    struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1); 

    //127.0.0.1过滤
    if (out != NULL) {
        if (out->flags & IFF_LOOPBACK){
            return NF_ACCEPT; 
        }   
    } else {
        struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;  
        if (ipv6_addr_equal(&ip6h->daddr, &loopback_addr) || *(uint16_t *)&ip6h->saddr == 0x80fe || *(uint16_t *)&ip6h->daddr == 0x80fe) {  
            return NF_ACCEPT; 
        }  
    } 
    struct in6_addr *server_addr = (struct in6_addr *)server_ip6;
    if (ipv6_addr_equal(&ip6h->saddr, server_addr) || ipv6_addr_equal(&ip6h->daddr, server_addr)) {  
//    LOG_INFO("process:%s, %pI6-->%pI6\n", \
          CURRENT_COMM, &ip6h->saddr, &ip6h->daddr);  
        return NF_ACCEPT; 
    }
    if (is_internel_enable() == 0) {
        return  NF_DROP;
    }

    if(is_self_process()) {
        return NF_ACCEPT;
    }

    if (memcmp("Magic", CURRENT_COMM, 5) == 0) {
        return NF_ACCEPT;
    }
//    LOG_INFO("process:%s, %pI6:%u-->%pI6:%u Protocol: %d\n", \
          CURRENT_COMM, &ip6h->saddr, ntohs(tcph->source),&ip6h->daddr, ntohs(tcph->dest), ip6h->nexthdr);  

    if (is_net_block_enable()) 
    {
#if 1

        if (conn_block_check_v6(&ip6h->saddr)) {
            //LOG_INFO("disable network visit[%u.%u.%u.%u->%u.%u.%u.%u]\n", IPQUADS(ip_header_->saddr), IPQUADS(ip_header_->daddr));
//            LOG_INFO("hit block process:%s, %pI6:%u-->%pI6:%u Protocol: %d\n", \
              CURRENT_COMM, &ip6h->saddr, ntohs(tcph->source),&ip6h->daddr, ntohs(tcph->dest), ip6h->nexthdr);  


            return  NF_DROP;
        } else {
            if (ip6_netblock_match(ip6h)) {

//                LOG_INFO("hit block process:%s, %pI6:%u-->%pI6:%u Protocol: %d\n", \
                    CURRENT_COMM, &ip6h->saddr, ntohs(tcph->source),&ip6h->daddr, ntohs(tcph->dest), ip6h->nexthdr);  
                return  NF_DROP;
            }
        }
#endif        
    } 
    return NF_ACCEPT;
}



static unsigned int _nf_post_routing_hold_func_netdos_v6(unsigned int holdnum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    __be16 tmp_port = 0;
    int ret = NF_ACCEPT;
	if (!skb) {
        return NF_ACCEPT;
	}

    struct ipv6hdr *ip6h = ipv6_hdr(skb);  
    if (!ip6h) {
        return NF_ACCEPT;
    }
    struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1); 

    if (init_forward == 1 && tcph->rst == 1) {
#if 0
        if (session_cache_lookup2(iph->daddr, tcph->dest, iph->saddr, tcph->source, skb) == 1) {
            //    LOG_INFO("post routing %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u,rst:%d",\
            IPQUADS(iph->saddr), ntohs(tcph->source), IPQUADS(iph->daddr), ntohs(tcph->dest),tcph->rst);
            return NF_DROP; 
        }
#else
#if 1
        if (is_rst_port(tcph->dest) && is_rst_port(tcph->source)) {

                //LOG_INFO("post routing %pI6:%u-->%pI6:%u rst:%d\n", \
                    CURRENT_COMM, &ip6h->saddr, ntohs(tcph->source),&ip6h->daddr, ntohs(tcph->dest), tcph->rst);  
            struct osec_cb *cb = OSEC_CB(skb);
            if (cb->a != 0xaabbccdd);
                return NF_DROP; 
        }
#endif
#endif
    }
    return NF_ACCEPT;
}


static unsigned int _nf_post_routing_hold_func_netdos(unsigned int holdnum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    __be16 tmp_port = 0;
    int ret = NF_ACCEPT;
	
    if (unlikely(is_close_net_business() == 1)) {
        return NF_ACCEPT;
    }

    if (unlikely(skb == NULL)) {
        return NF_ACCEPT;
    }

    struct iphdr *iph = kosecs_ip_hdr(skb);
    
    if (!iph) {
        return NF_ACCEPT;
    }
    struct tcphdr *tcph = NULL;

    tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
    if (init_forward == 1 && tcph->rst == 1) {
#if 0
        if (session_cache_lookup2(iph->daddr, tcph->dest, iph->saddr, tcph->source, skb) == 1) {
            //    LOG_INFO("post routing %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u,rst:%d",\
            IPQUADS(iph->saddr), ntohs(tcph->source), IPQUADS(iph->daddr), ntohs(tcph->dest),tcph->rst);
            return NF_DROP; 
        }
#else
#if 1
        if (is_rst_port(tcph->dest) && is_rst_port(tcph->source)) {

    //        LOG_INFO("post routing %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u,rst:%d",\
                    IPQUADS(iph->saddr), ntohs(tcph->source), IPQUADS(iph->daddr), ntohs(tcph->dest),tcph->rst);
            struct osec_cb *cb = OSEC_CB(skb);
            if (cb->a != 0xaabbccdd);
                return NF_DROP; 
        }
#endif
#endif
    }
    return NF_ACCEPT;
}

struct dnshdr
{
    __be16 id;
#if defined (__LITTLE_ENDIAN_BITFIELD)
    __u8 rd:1,
         tc:1,
         aa:1,
         opcode:4,
         qr:1;
    __u8 rcode:4,
         z:3,
         ra:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8 qr:1,
         opcode:4,
         aa:1,
         tc:1,
         rd:1;
    __u8 ra:1,
         z:3,
         rcode:4;
#else
#error "unknown endian type"
#endif
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

struct dns_query_section
{
    char *qname;
    __u16 qtype;
    __u16 qclass;
};


typedef struct {
    u_short dname_len;
    char dname[256]; //dns报文给出的域名最大限制是253字节,我们在此处直接限定为256字节
}dname_parse_ctx_t;

static void dname_parse_cb(__u8* field,size_t field_len,void* ctx)
{
    dname_parse_ctx_t* dname_ctx = ctx;

    if(dname_ctx->dname_len > 0) {
        dname_ctx->dname[dname_ctx->dname_len++] = '.';
    }

    strncpy(dname_ctx->dname + dname_ctx->dname_len,
        (char*)field,field_len);
    dname_ctx->dname_len += field_len;
}

/*
 *解析域名或cname
 *对于域名或cname，在dns报文中都是以\0结尾，
 *且使用了长度对分段进行标识,并且每个分段都有可能是指针偏移
 */
static int parse_name2(struct dnshdr *dns_hdr,
                __u8* data,__u8* pend,
                void (*cb)(__u8* field,size_t field_len,void* ctx),
                void* ctx)
{
    int size = 0;

    for(;*data != '\0';)
    {
        //answer中的域名可能与query section中的域名相同，
        //此时报文可能会使用2字节指针偏移来替代，以节约报文空间
        //前2位是11固定标识,后14位是标识对应域名在该response报文中的偏移量(以字节为单位,从0开始)
        if((*data & 0xC0) == 0xC0)
        {
            // 取得偏移植.
            size_t name_offset = ntohs(*((__be16 *) data)) & 0x3FFF;
            // 找到目標域名
            __u8* link_name = ((__u8 *) dns_hdr) + name_offset;
            if(link_name >= pend) {
                size = -EINVAL;
                break;
            }

            //Note: 这里是一个递归，link_name标识仍然可能是指针
            //有些危险，不过对于udp dns报文来说递归层数一般不会超过3
            parse_name2(dns_hdr,link_name,pend,
                            cb,ctx);

            // 域名欄位長度加上指針大小.
            size += 2;
            data += 2;
            // 指針後面不可有域名字串, 離開處理.
            break;
        }

        //此时*data的值是表示的后续字段的长度
        {
            size_t field_len = *data;
            if(data + field_len + 1 >= pend) {
                size = -EINVAL;
                break;
            }

            cb(data + 1,field_len,ctx);

            data += field_len + 1;
            size += field_len + 1;
            //跨过域名结尾标识\0
            if(*data == '\0') { size++; }
        }
    }
   
    return size;
}


static int parse_domain_name(struct dnshdr *dns_hdr,
                    __u8* data,__u8* pend,
                    char* dname_buf,int dname_buflen)
{
    int n = 0;
    dname_parse_ctx_t* ctx = NULL;
    ctx = kzalloc(sizeof(*ctx),GFP_ATOMIC);
    if(!ctx) { return -ENOMEM; }

    n = parse_name2(dns_hdr,(char*)data,
                pend,dname_parse_cb,ctx);
    if(n <= 0) {
        kfree(ctx);
        return -EINVAL;
    }

    //这个不正常,我们发现存在只有一个字节的域名请求
    //这个没有域名
    if(ctx->dname_len <= 1) {
        kfree(ctx);
        return -EINVAL;
    }

    memcpy(dname_buf,ctx->dname,
        min((int)(ctx->dname_len),dname_buflen));
    kfree(ctx);

    return n;
}

// 分析 query section.
int parse_dns_query_section(struct dnshdr *dns_hdr,__u8* pend, 
                __u8 *section_loc, char* dns_url, int buff_size,
                struct dns_query_section* pdns_qd)
{
    size_t slen = 0;
    void *data_offset;
    struct dns_query_section dns_qd;
    memset(&dns_qd, 0, sizeof(dns_qd));

    data_offset = section_loc;

    if (data_offset == NULL) {
        return -EINVAL;
    }
    
    {
        int n = 0;
        n = parse_domain_name(dns_hdr,(__u8*)data_offset,
                    pend,dns_url,buff_size);
        if(n <= 0) { return -EINVAL; }

        slen += n;
    }

    data_offset = section_loc + slen;
    
    dns_qd.qtype = ntohs(*((__be16 *) data_offset));
    slen += sizeof(dns_qd.qtype);

    data_offset = section_loc + slen;

    dns_qd.qclass = ntohs(*((__be16 *) data_offset));
    slen += sizeof(dns_qd.qclass);

    memcpy(pdns_qd,&dns_qd,sizeof(dns_qd));

    return slen;
}

// 分析 DNS 封包.
#define KOSEC_DNSHDR_LEN (sizeof(struct dnshdr))
static int parse_dns_math_rules(struct dnshdr *dns_hdr, char *dns_buff, const int len)
{
    int rc = 0;
    uint8_t* pend = NULL;
    size_t qdcnt, sidx = 0;
    uint8_t *section_loc = NULL;

    qdcnt = ntohs(dns_hdr->qdcount);
    pend = ((uint8_t *) dns_hdr) + len;
    section_loc = ((uint8_t *) dns_hdr) + sizeof(struct dnshdr);

    struct dns_query_section dns_qd;
    for(sidx = 0; sidx < qdcnt; sidx++)
    {
        //域名目前我们在用户态的限定是70字节
        //DNS协议给出的限定是253
        //此处我们限定为256,能够满足需求了
        int slen = 0;
        char dname[256] = {0};
        if ((section_loc == NULL) || 
            (section_loc >= pend)) 
        {
            LOG_ERROR("1111111\n");
            rc = -EINVAL;
            break;
        }

        slen = parse_dns_query_section(dns_hdr,
                        (__u8*)pend,section_loc,
                        dname,sizeof(dname),&dns_qd);
        if (slen <= 0) {
            rc = slen;
            break;
        }
        section_loc += slen;
        memcpy(dns_buff, dname, 255);
    }
   
    return NF_ACCEPT;
}

bool vsec_need_gather_skb(const struct sk_buff* skb)
{
    u_char* tail = NULL;
    unsigned skb_ntk_len = 0;
    unsigned ntk_total_len = 0;

    // Check if entire packet data is here
    tail = skb_tail_pointer(skb);
	skb_ntk_len = (tail - skb_network_header(skb));

    //这里要计算ip分片重组后的长度,这个是skbuffer中保存的非连续数据长度
    ntk_total_len = skb->len - skb_network_offset(skb);

    return (skb_ntk_len < ntk_total_len);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static void out_netlog_audit_timer_function(struct timer_list *timer)
#else
static void out_netlog_audit_timer_function(unsigned long data)
#endif
{
    uint32_t prev_idx = 0, idx = 0;
    struct netlink_netlog netlog_msg;
    if (unlikely(!atomic_is_timer_status_set(OUT_NETLOG_AUDIT_TIMER_ON))) {
	return;
    }

    netlog_msg.max_idx = get_out_netlog_audit_idx(&prev_idx, &idx);
    if (idx > prev_idx) {
        netlog_msg.start_idx = prev_idx;
        netlog_msg.end_idx = idx;
        //LOG_INFO("timer netdos_tcp_out start idx:%d, end idx:%d......\n",netlog_msg.start_idx, netlog_msg.end_idx);
        send_nl_data(NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));

    }

    if (likely(atomic_is_timer_status_set(OUT_NETLOG_AUDIT_TIMER_ON))) {
        // 如果标志为 1，则重新调度定时器
        mod_timer(&out_netlog_audit_timer, jiffies + 60 * HZ);  
    }

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static void dns_netlog_audit_timer_function(struct timer_list *timer)
#else
static void dns_netlog_audit_timer_function(unsigned long data)
#endif
{
    uint32_t prev_idx = 0, idx = 0;
    struct netlink_netlog netlog_msg;
    if (unlikely(!atomic_is_timer_status_set(DNS_NETLOG_AUDIT_TIMER_ON))) {
	return;
    }

    netlog_msg.max_idx = get_dns_netlog_audit_idx(&prev_idx, &idx);
    if (idx > prev_idx) {
        netlog_msg.start_idx = prev_idx;
        netlog_msg.end_idx = idx;
        //LOG_INFO("timer dns  start idx:%d, end idx:%d......\n",netlog_msg.start_idx, netlog_msg.end_idx);
        send_nl_data(NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));

    }

    if (likely(atomic_is_timer_status_set(DNS_NETLOG_AUDIT_TIMER_ON))) {
        // 如果标志为 1，则重新调度定时器
        mod_timer(&dns_netlog_audit_timer, jiffies + 60 * HZ);  
    }

}

static int netdos_tcp_out(struct sk_buff* skb,struct iphdr* iph, uint32_t u_type)
{
    struct tcphdr *tcph = NULL;
    if(!skb || !iph) {
        return NF_ACCEPT;
    }


    if (!((iph->daddr & 0xFF) ^ 127)||!((iph->saddr & 0xFF) ^ 127) ){
        return NF_ACCEPT; 
    }   
    tcph = ((struct tcphdr*)(skb->data + ip_hdr(skb)->ihl * 4));
    if (tcph->syn != 1 || tcph-> ack !=0) {
        return NF_ACCEPT;
    }

    if (zero_copy_load_succeed & OUT_NETLOG_AUDIT_ENABLE) {
        struct osec_network_report *osec_report;

        uint32_t idx = get_out_netlog_audit_data(&osec_report);
        osec_report->src.pad[0] = 0;
        osec_report->src.pad[1] = 0;
        osec_report->src.pad[2] = 0;
        osec_report->src.ip4 = iph->saddr;
        osec_report->src_port = tcph->source;
        osec_report->dst.pad[0] = 0;
        osec_report->dst.pad[1] = 0;
        osec_report->dst.pad[2] = 0;
        osec_report->dst.ip4 = iph->daddr;
        osec_report->dest_port = tcph->dest;
        osec_report->pid = CURRENT_PID;
        if (!in_interrupt() && current->mm != NULL) {
            if (unlikely(get_process_executable_path(current, osec_report->comm, sizeof(osec_report->comm) -1) == -1)) 
            {
                memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm) -1);
            }

        } else {
            memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm) - 1); 
        }
        //osec_report->type = u_type;
#if 1
        struct netlink_netlog netlog_msg;
        if (idx >= out_netlog_audit_data_count - 1) {

            uint32_t prev_idx = 0 ;
            netlog_msg.max_idx = get_out_netlog_audit_idx(&prev_idx, &idx);
            netlog_msg.start_idx = prev_idx;
            netlog_msg.end_idx = out_netlog_audit_data_count - 1;
            //LOG_INFO("out netlog start idx:%d, end idx:%d......\n",netlog_msg.start_idx, netlog_msg.end_idx);
            send_nl_data(NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
        } 
#endif        
    } else {
        struct osec_network_report_old osec_report;
        osec_report.src.pad[0] = 0;
        osec_report.src.pad[1] = 0;
        osec_report.src.pad[2] = 0;
        osec_report.src.ip4 = iph->saddr;
        osec_report.src_port = tcph->source;
        osec_report.dst.pad[0] = 0;
        osec_report.dst.pad[1] = 0;
        osec_report.dst.pad[2] = 0;
        osec_report.dst.ip4 = iph->daddr;
        osec_report.dest_port = tcph->dest;
        if (!in_interrupt() && current->mm != NULL) {
            if (unlikely(get_process_executable_path(current, osec_report.comm, sizeof(osec_report.comm) -1) == -1)) {
                memcpy(osec_report.comm, CURRENT_COMM, sizeof(osec_report.comm) -1);
            }
        } else {
            memcpy(osec_report.comm, CURRENT_COMM, sizeof(osec_report.comm) -1 );
        }
        osec_report.pid = CURRENT_PID;
        //osec_report.type = u_type;
        //LOG_INFO("netdos_tcp_out ......");
        send_nl_data(NL_POLICY_NET_CONNECT_PORT_NOTIFY, &osec_report, sizeof(struct  osec_network_report_old));

    }
    return NF_ACCEPT;
}


#if TCP_ECN_FEATURE == 1
/* TCPHDR_ECE 在 2.6.32 中不存在，直接补上 */
#ifndef TCPHDR_ECE
#define TCPHDR_ECE 0x40
#endif

/* skb_try_make_writable 在约 3.0 内核引入，旧内核手动实现等价逻辑 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 7, 0) || ENABLE_SKB_TRY_MAKE_WRITABLE == 1
static inline int skb_try_make_writable(struct sk_buff *skb,
                                        unsigned int write_len)
{
    return skb_cloned(skb) && !skb_clone_writable(skb, write_len) &&
           pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}
#endif
static int set_tcp_ecn_mark(struct sk_buff *skb, struct iphdr *iph)
{
    struct tcphdr *th;
    unsigned int tcphdr_len;
    int tcp_len;

    // 确保 IP 头 + TCP 基本头在线性区
    if (unlikely(!pskb_may_pull(skb, (iph->ihl << 2) + sizeof(struct tcphdr))))
        return -EINVAL;

    // 重新获取 iph（pskb_may_pull 可能改变 skb->data）
    iph = ip_hdr(skb);
    th = tcp_hdr(skb);

    if (unlikely(th->doff < 5))
        return -EINVAL;

    // 确保整个 TCP 头（含选项）可写
    tcphdr_len = th->doff << 2;
    if (unlikely(skb_try_make_writable(skb, (iph->ihl << 2) + tcphdr_len)))
        return -ENOMEM;

    // 重新获取指针（skb_try_make_writable 可能再次改变 skb->data）
    iph = ip_hdr(skb);
    th = tcp_hdr(skb);

    /* 
     * TCP 头偏移 13 字节：Flags 字段
     * 只将 ECE 标志置 1，其他所有标志位保持不变
     */
    u8 *flags_byte = (u8 *)th + 13;
    *flags_byte |= TCPHDR_ECE;  // 只设置 ECE 位，不影响其他位

    // 重新计算校验和
    skb->ip_summed = CHECKSUM_NONE;
    th->check = 0;

    tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2);

    // 使用 skb_checksum 正确处理非线性 skb（兼容 x86_64/loongarch64）
    th->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr,
                             skb_checksum(skb, (iph->ihl << 2), tcp_len, 0));

    return 0;
}
#endif

static unsigned int _nf_local_out_func(unsigned int holdnum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
	struct iphdr *ip_header_ = NULL;
    __be16 tmp_port = 0;
    int ret = NF_ACCEPT;

//    if(!net_syslog_enable) {
//        return NF_ACCEPT;
//    }
    if (unlikely(is_close_net_business() == 1)) {
        return NF_ACCEPT;
    }

    if (unlikely(skb == NULL)) {
        return NF_ACCEPT;
    }

    if (!is_syslog_outer_enable()) {
        return NF_ACCEPT;
    }

    ip_header_ = kosecs_ip_hdr(skb);
    
    if (!ip_header_) {
        return NF_ACCEPT;
    }
#if 0
    struct tcphdr *tcph = NULL;
    tcph = (struct tcphdr *)((__u32 *)ip_header_ + ip_header_->ihl);
    if (tcph && (ipv4_stonl("192.168.16.81") == ip_header_->saddr || ipv4_stonl("192.168.16.81") == ip_header_->daddr ) && tcph->source != 0x1600 && tcph->dest != 0x1600) {
        LOG_INFO("send:%u.%u.%u.%u:%u-->%u.%u.%u.%u:%u, syn:%d,ack:%d,rst:%d, sk:%p\n",\
                IPQUADS(ip_header_->saddr), ntohs(tcph->source), IPQUADS(ip_header_->daddr), ntohs(tcph->dest),tcph->syn,tcph->ack, tcph->rst, skb->sk);

    }
#endif
    //127.0.0.1过滤
    if (out != NULL) {
        if (out->flags & IFF_LOOPBACK){
            return NF_ACCEPT; 
        }   
    }   
    else {
        if (ip_header_->daddr == 2130706433){
            return NF_ACCEPT; 
        }   
    }   
#if TCP_ECN_FEATURE == 1
    if (tcp_force_ecn == 1 && ip_header_->protocol == IPPROTO_TCP) {
        set_tcp_ecn_mark(skb, ip_header_);
#if 0
    struct tcphdr *tcph = NULL;
    tcph = (struct tcphdr *)((__u32 *)ip_header_ + ip_header_->ihl);
        LOG_INFO("send:%u.%u.%u.%u:%u-->%u.%u.%u.%u:%u, syn:%d,ack:%d,rst:%d, sk:%p\n",\
                IPQUADS(ip_header_->saddr), ntohs(tcph->source), IPQUADS(ip_header_->daddr), ntohs(tcph->dest),tcph->syn,tcph->ack, tcph->rst, skb->sk);

#endif
    }
#endif

    if (ip_header_->daddr == server_ip) {
         return NF_ACCEPT; 
    }   
    //LOG_INFO("out net log [%s]\n",CURRENT_COMM);
    if (memcmp("Magic", CURRENT_COMM, 5) == 0) {
        return NF_ACCEPT;
    }
    if (strcmp("dnsmasq", CURRENT_COMM) ==0 ) {
        return NF_ACCEPT;
    }
    if (memcmp("swapper", CURRENT_COMM, 7) ==0 ) {
        return NF_ACCEPT;
    }
    if (memcmp("ksoftirqd", CURRENT_COMM, strlen("ksoftirqd")) ==0 ) {
        return NF_ACCEPT;
    }

    if (ip_header_->protocol == IPPROTO_TCP) {
        return netdos_tcp_out(skb, ip_header_, 1);
	} 
#if 0    
    else if (ip_header_->protocol == IPPROTO_UDP) {
        netdos_udp_out(skb, ip_header_);
    } 
#endif
    return NF_ACCEPT;
}

static int netdos_tcp6_out(struct sk_buff* skb,struct ipv6hdr* ip6h, uint32_t u_type)
{
    if(!skb || !ip6h) {
        return NF_ACCEPT;
    }
    struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1); 
    if (tcph->syn != 1 || tcph-> ack !=0) {
        return NF_ACCEPT;
    }
    if (memcmp("Magic", CURRENT_COMM, 5) == 0) {
        return NF_ACCEPT;
    }
    if (strcmp("dnsmasq", CURRENT_COMM) ==0 ) {
        return NF_ACCEPT;
    }
    if (memcmp("swapper", CURRENT_COMM, 7) ==0 ) {
        return NF_ACCEPT;
    }
    if (memcmp("ksoftirqd", CURRENT_COMM, strlen("ksoftirqd")) ==0 ) {
        return NF_ACCEPT;
    }

 //   LOG_INFO("process:%s,Src IP: %pI6, Dest IP: %pI6, Src Port: %d, Dest Port: %d, Protocol: %d\n",  \
          CURRENT_COMM, &ip6h->saddr, &ip6h->daddr, ntohs(tcph->source), ntohs(tcph->dest), ip6h->nexthdr);  


    //LOG_INFO("out net log===============[%s]\n", CURRENT_COMM);
    if (zero_copy_load_succeed & OUT_NETLOG_AUDIT_ENABLE) {
        struct osec_network_report *osec_report;

        uint32_t idx = get_out_netlog_audit_data(&osec_report);
        memcpy(osec_report->src.ip6, ip6h->saddr.in6_u.u6_addr16, sizeof(osec_report->src.ip6));
        osec_report->src_port = tcph->source;
        memcpy(osec_report->dst.ip6, ip6h->daddr.in6_u.u6_addr16, sizeof(osec_report->dst.ip6));
        osec_report->dest_port = tcph->dest;
        osec_report->pid = CURRENT_PID;
        memcpy(osec_report->comm, CURRENT_COMM, sizeof(osec_report->comm)); 

        //printk("network process[%s]\n",osec_report.comm);
        //osec_report->type = u_type;
#if 1
        struct netlink_netlog netlog_msg;
        if (idx >= out_netlog_audit_data_count - 1) {

            uint32_t prev_idx = 0 ;
            netlog_msg.max_idx = get_out_netlog_audit_idx(&prev_idx, &idx);
            netlog_msg.start_idx = prev_idx;
            netlog_msg.end_idx = out_netlog_audit_data_count - 1;
            //LOG_INFO("out netlog start idx:%d, end idx:%d......\n",netlog_msg.start_idx, netlog_msg.end_idx);
            send_nl_data(NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY, &netlog_msg, sizeof(struct netlink_netlog));
        } 
#endif        
    } else {
        struct osec_network_report_old osec_report;
        memcpy(osec_report.src.ip6, ip6h->saddr.in6_u.u6_addr16, sizeof(osec_report.src.ip6));
        osec_report.src_port = tcph->source;
        memcpy(osec_report.dst.ip6, ip6h->daddr.in6_u.u6_addr16, sizeof(osec_report.dst.ip6));
        osec_report.dest_port = tcph->dest;
        memcpy(osec_report.comm, CURRENT_COMM, sizeof(osec_report.comm));
        osec_report.pid = CURRENT_PID;
        //osec_report.type = u_type;
        //LOG_INFO("netdos_tcp_out ......");
        send_nl_data(NL_POLICY_NET_CONNECT_PORT_NOTIFY, &osec_report, sizeof(struct osec_network_report_old));

    }
    return NF_ACCEPT;
}
static unsigned int _nf_local_out_v6_func(unsigned int holdnum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    int ret = NF_ACCEPT;

    if (unlikely(is_close_net_business() == 1)) {
        return NF_ACCEPT;
    }

    if (unlikely(skb == NULL)) {
        return NF_ACCEPT;
    }

    if (!is_syslog_outer_enable()) {
        return NF_ACCEPT;
    }


    struct ipv6hdr *ip6h = ipv6_hdr(skb);  
    if (!ip6h) {
        return NF_ACCEPT;
    }

    //127.0.0.1过滤
    if (out != NULL) {
        if (out->flags & IFF_LOOPBACK){
            return NF_ACCEPT; 
        }   
    }   
    else {
        struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;  
        if (ipv6_addr_equal(&ip6h->daddr, &loopback_addr)) {  
            return NF_ACCEPT; 
        }  
    } 





    if (ip6h->nexthdr == IPPROTO_TCP) {

        return netdos_tcp6_out(skb, ip6h, 1);
	} 

    return NF_ACCEPT;
}

static int handle_cmd_netsyslog_policy(void* data, int len) 
{
#if 0
    int val = *(int*)data;
    if (val) {
        net_syslog_enable = 1;
    } else {
        net_syslog_enable = 0;
    }
#else
    static char pre_buf[2] = {0};
    char *buf = (char *)data;
    //LOG_SHOW("=======================================pre buf:%d,%d, buf:%d,%d\n", pre_buf[0], pre_buf[1], buf[0], buf[1]);
    if (pre_buf[0] != buf[0]) {
        if (buf[0]) {
            syslog_turn_on();
            start_process_audit_timer();
        } else {
            syslog_turn_off();
        }
    }
    if (pre_buf[1] != buf[1]) {
        if (buf[1]) {
            proc_start_turn_on();
            start_process_audit_timer();
        } else {
            proc_start_turn_off();
        }
    }
    pre_buf[0] = buf[0];
    pre_buf[1] = buf[1];
    if (is_syslog_enable() == 0 && is_proc_start_enable() == 0) {
        stop_process_audit_timer();
    }
    

#endif
    LOG_INFO("===================netsys log switch status:%d, proc_start_enable:%d\n", is_syslog_enable(), is_proc_start_enable());
    return 0;
}

static struct rtable *get_route_by_addr(uint32_t addr)
{
    struct rtable *rt = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)

    struct flowi4 fl4;
    memset(&fl4, 0, sizeof(fl4));
    fl4.flowi4_proto = IPPROTO_IP;
    fl4.daddr  = addr;
    return ip_route_output_key(&init_net, &fl4);
#else
    struct flowi fl =
    {   
        .oif = 0,
        .nl_u = { .ip4_u = { .saddr = 0, .daddr = 0, .tos = 0, } },
        .proto = IPPROTO_IP,
        .flags = 0,
        .uli_u = { .ports = { .sport = 0, .dport = 0, } },
    };  
    fl.nl_u.ip4_u.daddr = addr;
    if(ip_route_output_key(&init_net, &rt, &fl) == 0)
        return rt; 
    /* No route... */
#endif
    return NULL;
}

static int try_add_get_rtable(void)
{
    struct list_head *pos;
    struct NetTcpUdpInfo* nci = NULL;
    struct rtable *rt = NULL; 
    list_for_each(pos, &(gListTcpPolicy.NETISOLATE_LIST)) {
        nci =list_entry(pos, struct NetTcpUdpInfo, list);
        if (nci->info.redirectPort !=0 ) {

            if (is_business_port(nci->info.redirectPort)) {
                continue;
            }

            //rt = get_route_by_addr(nci->info.eip);
            //LOG_INFO("=======================rt=%p[%lx]\n",rt,rt);
            //add_forward_rtable_rules(nci->info.eip, (unsigned long)rt);
        }
    }
    return 0;
}

// RCU 辅助函数
static int add_net_tcp_udp_list_rcu(struct NetworkKernelRulesInfo *info, struct list_head *list)
{
    struct NetTcpUdpInfo *nci;

    if (!info) {
        LOG_INFO("rules info is NULL\n");
        return -1;
    }

   
    nci = kmalloc(sizeof(struct NetTcpUdpInfo), GFP_ATOMIC);
    if (!nci) {
        LOG_INFO("kmalloc NetTcpUdpInfo failed\n");
        return -1;
    }
    memset(nci, 0, sizeof(struct NetTcpUdpInfo));

    nci->protocol = info->protocol;
    nci->addr_type = info->addr_type;
    memcpy(&nci->info, info, sizeof(nci->info));
    INIT_LIST_HEAD(&nci->list);
    list_add_tail_rcu(&nci->list, list); // 添加到尾部
#if 1
    if (info->is_ipv4 == 1) {
        LOG_INFO("sip:%u.%u.%u.%u(%u.%u.%u.%u),sport:%u,eip:%u.%u.%u.%u, eport:%u\n", IPQUADS(nci->info.sip.ip4), IPQUADS(info->sip.ip4), nci->info.sport, IPQUADS(nci->info.eip.ip4),nci->info.eport);
    } else {
        LOG_INFO("%pI6:%u-->%pI6:%u \n", \
                (struct in6_addr *)nci->info.sip.ip6, nci->info.sport,  (struct in6_addr *)nci->info.eip.ip6, nci->info.eport); 
    }
#endif

    return 0;
}



static void clean_net_tcp_udp_list_rcu(struct list_head *list)
{
    struct NetTcpUdpInfo *nci, *tmp;
    struct list_head free_list;

    INIT_LIST_HEAD(&free_list);

    spin_lock_bh(&g_ntcp_policy_lock);
    list_for_each_entry_safe(nci, tmp, list, list) {
        list_del_rcu(&nci->list);
        list_add(&nci->list, &free_list);  // 临时移到 free_list
    }
    INIT_LIST_HEAD(list);
    spin_unlock_bh(&g_ntcp_policy_lock);

    // 在锁外释放
    list_for_each_entry_safe(nci, tmp, &free_list, list) {
        list_del(&nci->list);  // 非 RCU 操作，仅清理临时链表
        kfree_rcu(nci, rcu);  // 使用 kfree_rcu 替代 call_rcu
    }
}


static void splice_net_tcp_udp_list_rcu(struct list_head *src, struct list_head *dst)
{
    struct list_head *pos, *n;

    if (list_empty(src)) {
        return;
    }

    spin_lock(&g_ntcp_policy_lock);
    list_for_each_safe(pos, n, src) {
        list_del(pos);  // 从源链表移除
        list_add_rcu(pos, dst);  // RCU 安全添加到目标链表
    }
    spin_unlock(&g_ntcp_policy_lock);
}

// Netlink 规则更新
static int handle_cmd_net_dos_policy(void *data, int len)
{
    struct NetworkKernelPolicyInfo *policy_info = (struct NetworkKernelPolicyInfo *)data;
    struct list_head temp_list;
    int i, ret;

    if (!policy_info) {
        LOG_INFO("Policy Format Error: data is NULL\n");
        return 0;
    }

    // 验证长度
    if (len != sizeof(struct NetworkKernelPolicyInfo) ||
        policy_info->acl_num > 20) {
        LOG_INFO("Invalid policy length: %d, acl_num: %u\n", len, policy_info->acl_num);
        return 0;
    }

    if (policy_info->pol_switch == 0) {
        net_dos_turn_off();
        LOG_INFO("net_dos_enable value :%x\n", is_net_dos_enable());
        return 0;
    } else {
        net_dos_turn_on();
    }
    LOG_INFO("net_dos_enable:%x, acl_num: %x, acl_type: %x \n", is_net_dos_enable(), policy_info->acl_num, policy_info->acl_type); 

    INIT_LIST_HEAD(&temp_list);
    for (i = 0; i < policy_info->acl_num; i++) {
        ret = add_net_tcp_udp_list_rcu(&policy_info->rules_info[i], &temp_list);
        if (ret) {
            clean_net_tcp_udp_list_rcu(&temp_list);
            return 0;
        }
    }
    spin_lock(&g_ntcp_policy_lock);
    gListTcpPolicy.acl_type = policy_info->acl_type;
    spin_unlock(&g_ntcp_policy_lock);
    clean_net_tcp_udp_list_rcu(&gListTcpPolicy.NETISOLATE_LIST);
    splice_net_tcp_udp_list_rcu(&temp_list, &gListTcpPolicy.NETISOLATE_LIST);
    synchronize_rcu(); // 等待读路径完成
    LOG_INFO("load handle_cmd_net_dos_policy finish\n"); 
    return 0;
}

static int handle_cmd_net_business_port_policy(void* data, int len) 
{
    uint16_t *ports = (uint16_t *)data;
    //if (is_net_dos_enable()) 
    {
        int port_count = len / sizeof(uint16_t);
        //LOG_INFO("business Port count is %d, data_len:%d\n", port_count, len);
        clear_business_port();
        int i;
        for (i = 0; i  < port_count; i ++) {
            if (likely(ports[i] != 0))
                set_business_port(ports[i]);  
        }
        //try_add_get_rtable();
    }
    return 0;
}

static int handle_cmd_net_block_policy(void *data, int len)
{
    int i = 0;
    struct NetworkKernelPolicyInfo *policy_info = (struct NetworkKernelPolicyInfo *)data;
    struct NetworkKernelPolicyInfo *new_policy, *old_policy;

    if (!policy_info) {
        LOG_ERROR("Policy net block Format Error");
        return -EINVAL;
    }
    if (len != sizeof(struct NetworkKernelPolicyInfo) || policy_info->acl_num > 20) {
        LOG_INFO("Invalid policy length: %d, acl_num: %u\n", len, policy_info->acl_num);
        return -EINVAL;
    }
    new_policy = kmalloc(sizeof(struct NetworkKernelPolicyInfo), GFP_ATOMIC);
    if (!new_policy) {
        LOG_INFO("Failed to allocate memory for net block policy\n");
        return -ENOMEM;
    }
    memcpy(new_policy, policy_info, sizeof(struct NetworkKernelPolicyInfo));
    LOG_INFO("net block acl_num: %x, acl_type: %x,\n", policy_info->acl_num, policy_info->acl_type);

    spin_lock_bh(&g_block_policy_lock);
    old_policy = gNetBlockPoicy;
    rcu_assign_pointer(gNetBlockPoicy, new_policy);
    if (gNetBlockPoicy->acl_type > 0) {
        net_block_turn_on();
    } else {
        net_block_turn_off();
    }
    spin_unlock_bh(&g_block_policy_lock);
    LOG_INFO("net_block_enable:%d\n", is_net_block_enable());

    for (i = 0; i < policy_info->acl_num; i++) {
        LOG_INFO("===============ip:%pI6---%pI6\n", policy_info->rules_info[i].eip.ip6, policy_info->rules_info[i].sip.ip6);
    }

    if (old_policy) {
        synchronize_rcu();
        kfree(old_policy);
    }

    return 0;
}



int get_server_control_ip(__be32 recv_ip)
{
    LOG_INFO("get_server_ip: recv_ip is %u.%u.%u.%u \n", IPQUADS(recv_ip));
	server_ip = recv_ip;
    return 0;
}

static int handle_cmd_serverip_policy(void *data, int len)
{
    char *recv_data = data;
    int i;
    if (len == 4) {
	    server_ip = *(__be32 *)(recv_data);
        LOG_INFO("========get_server_ip: recv_ip is %u.%u.%u.%u \n", IPQUADS(server_ip));
    } else if (len == 16) {
        for (i = 0; i < 16; i++) {
            server_ip6[i] = recv_data[i];
        }
        LOG_INFO("===============get_server_ip6: recv_ip is :%pI6\n", server_ip6);
    }
   
    return 0;
	//return get_server_control_ip(*(__be32 *)(recv_data));
}
static int handle_cmd_net_business_close(void* data, int len) 
{
    LOG_INFO("Maybe unstall or update, close all network business======================\n");
    atomic_set_network_status(CLOSE_NET_BUSINESS); 
    stop_in_netlog_audit_timer();
    stop_out_netlog_audit_timer();
    stop_dns_netlog_audit_timer();
    stop_openport_audit_timer();
    stop_process_audit_timer();
    stop_file_audit_timer();
    return 0;
}

static int uc_init = 0;
static struct vsec_con_cb_s con_callbacks[] = {
    {
        .index = NL_POLICY_NETWORK_UNSPEC,
    },
    {
        .index = NL_POLICY_NETWORK_POLICY,
        .pfunc = handle_cmd_net_dos_policy,
    },
    {
        .index = NL_POLICY_NETWORK_NETBLOCK,
        .pfunc = handle_cmd_net_block_policy,
    },
    {
        .index = NL_POLICY_NETWORK_SERVERIP_POLICY,
        .pfunc = handle_cmd_serverip_policy,
    },
    {
        .index = NL_POLICY_NETSYSLOG_POLICY,
        .pfunc = handle_cmd_netsyslog_policy,
    },
    {
        .index = NL_POLICY_NETWORK_BUSINESS_PORT_POLICY,
        .pfunc = handle_cmd_net_business_port_policy,
    },
    {
        .index = NL_POLICY_NETWORK_CLOSE,
        .pfunc = handle_cmd_net_business_close,
    },


};

DEFINE_NF_HOOK_FN(netdos_nf_hold_local_in,_nf_hold_func_netdos);
DEFINE_NF_HOOK_FN(netdos_nf_hold_local_in_v6,_nf_hold_func_netdos_v6);
DEFINE_NF_HOOK_FN(netdos_nf_hold_pre_routing,_nf_pre_routing_hold_func_netdos);
DEFINE_NF_HOOK_FN(netdos_nf_hold_pre_routing_v6,_nf_pre_routing_hold_v6_func_netdos);
DEFINE_NF_HOOK_FN(netdos_nf_local_out,_nf_local_out_func);
DEFINE_NF_HOOK_FN(netdos_nf_hold_post_routing,_nf_post_routing_hold_func_netdos);
//DEFINE_NF_HOOK_FN(netdos_nf_hold_post_routing_v6,_nf_post_routing_hold_func_netdos_v6);
DEFINE_NF_HOOK_FN(netdos_nf_local_out_v6,_nf_local_out_v6_func);

static struct nf_hook_ops g_netdos_nf_holds[] = {
    {
        .hook = netdos_nf_local_out,
        .hooknum = OSEC_NF_INET_LOCAL_OUT,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST
    },
    {
        .hook = netdos_nf_hold_local_in,
        .hooknum = OSEC_NF_INET_LOCAL_IN,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST
    },
    {
        .hook = netdos_nf_hold_pre_routing,
        .hooknum = OSEC_NF_INET_PRE_ROUTING,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST
    },

    {
        .hook = netdos_nf_hold_pre_routing_v6,
        .hooknum = OSEC_NF_INET_PRE_ROUTING,
        .pf = PF_INET6,
        .priority = NF_IP_PRI_FIRST
    },
 
    {
        .hook = netdos_nf_hold_post_routing,
        .hooknum = OSEC_NF_INET_POST_ROUTING,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST
    },
    {
        .hook = netdos_nf_hold_local_in_v6,
        .hooknum = OSEC_NF_INET_LOCAL_IN,
        .pf = PF_INET6,
        .priority = NF_IP_PRI_FIRST
    },
    {
        .hook = netdos_nf_local_out_v6,
        .hooknum = OSEC_NF_INET_LOCAL_OUT,
        .pf = PF_INET6,
        .priority = NF_IP_PRI_FIRST
    },
#if 0
    {
        .hook = netdos_nf_hold_post_routing_v6,
        .hooknum = OSEC_NF_INET_POST_ROUTING,
        .pf = PF_INET6,
        .priority = NF_IP_PRI_FIRST
    },
#endif

};


struct list_head virtual_open_port_list;
static int net_rules_cmd_parse(char *cmd)
{
    trim_spaces(cmd);
    int open_port_switch = 0;
    // 设置服务端 IP 示例
    if (sscanf(cmd, "server_ipv4 %u", &server_ip) == 1) {
        return 0;
    } else if (sscanf(cmd, "vir_open_port_switch %u", &open_port_switch) == 1) {
        //LOG_SHOW("==================open_port_switch: %d\n", open_port_switch);
        if (open_port_switch) {
            net_dos_turn_on();
        } else {
            net_dos_turn_off();
        }
        return 0;
    }

    else if (strncmp(cmd, "VIR_OPEN_PORT ", strlen("VIR_OPEN_PORT ")) == 0) {
        uint32_t index = 0, total = 0;
        struct NetworkKernelRulesInfo *info = NULL;

        int protocol_num = 0;
        char type_str[8] = {0};
        char source_ip[64] = {0};
        char dest_ip[64] = {0};
        int start_port = 0, end_port = 0;
        int dest_port = 0, redirect_port = 0, dest_port_type = 0, addr_type = 0, is_ipv4 = 1;

        int matched = sscanf(cmd,
                "VIR_OPEN_PORT index=%u total=%u id=%*u protocol=%d type=%7s is_ipv4=%d source_ip=%63s start_port=%d end_port=%d dest_ip=%63s dest_port_type=%d redirectPort=%d addr_type=%d",
                &index,
                &total,
                &protocol_num,
                type_str,
                &is_ipv4,
                source_ip,
                &start_port,
                &end_port,
                dest_ip,
                &dest_port_type,
                &redirect_port,
                &addr_type);

        if (matched != 12) {
            LOG_ERROR("VIR_OPEN_PORT parse error: only matched %d fields\n", matched);
            return -EINVAL;
        }

        info = kmalloc(sizeof(struct NetworkKernelRulesInfo), GFP_KERNEL);
        if (!info) {
            LOG_ERROR("kmalloc failed for rule\n");
            return -ENOMEM;
        }
        if (index == 0) {
            INIT_LIST_HEAD(&virtual_open_port_list);
        }
        memset(info, 0, sizeof(struct NetworkKernelRulesInfo));

        info->sport = start_port;
        info->eport = end_port;
        info->redirectPort = redirect_port;
        // 直接使用传入的数字协议
        info->protocol = (uint8_t)protocol_num;
        info->dest_port_type = dest_port_type &0x1;
        info->addr_type = addr_type &0x1f;
        // 先尝试 IPv4 解析源 IP
        if (is_ipv4 = 1) {
            info->is_ipv4 = 1;
            in4_pton(source_ip, -1, (u8 *)&info->sip.ip4, -1, NULL);
            in4_pton(dest_ip, -1, (u8 *)&info->eip.ip4, -1, NULL);
        } else {
            info->is_ipv4 = 0;
            in6_pton(source_ip, strlen(source_ip), (u8 *)info->sip.ip6, -1, NULL);
            in6_pton(dest_ip, strlen(dest_ip), (u8 *)info->eip.ip6, -1, NULL);
        }


        if (add_net_tcp_udp_list_rcu(info, &virtual_open_port_list)) {
            kfree(info);
            clean_net_tcp_udp_list_rcu(&virtual_open_port_list);
            return -1;
        }


        if (index + 1 == (int)total) {
            clean_net_tcp_udp_list_rcu(&gListTcpPolicy.NETISOLATE_LIST);
            splice_net_tcp_udp_list_rcu(&virtual_open_port_list, &gListTcpPolicy.NETISOLATE_LIST);
            synchronize_rcu(); // 等待读路径完成
            //net_dos_turn_on();
            LOG_INFO("Loaded all %d VIR_OPEN_PORT rules\n", total);
        }
        LOG_INFO("Network Rule:\n");
        LOG_INFO("  Protocol: %d (1=tcp,2=udp,0=other)\n", info->protocol);
        LOG_INFO("%u.%u.%u.%u(%u-%u)-forword to (%u)%u.%u.%u.%u:%u\n", IPQUADS(info->sip.ip4), info->sport, info->eport, info->eip.ip4,IPQUADS(info->eip.ip4), info->redirectPort);
        LOG_INFO("  Dest Port Type: %d\n", info->dest_port_type);
        LOG_INFO("  Addr Type: %d\n", info->addr_type);
        return 0;
    }

    return -EINVAL;
}



static int __net_rulse_build(char *buf, size_t buf_sz, void *info)
{
    
    int ret = 0;
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }


	ret += snprintf(buf + ret, buf_sz - ret, "server ip:%u.%u.%u.%u\n", IPQUADS(server_ip));
	//ret += snprintf(buf + ret, buf_sz - ret, "virtual port:%s\n", vir_open_port);
	return 0;
}
static int __net_rulse_parse(const char *buf, void *info)
{
    net_rules_cmd_parse(buf);
	return 0;
}
static struct var_proc_info net_rules_set =
{
	.parse = __net_rulse_parse,
	.build = __net_rulse_build,
};
//=============

static int __business_ports_build(char *buf, size_t buf_sz, void *info)
{
    int i, bit, ret = 0;
    int first = 1;
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }


    for (i = 0; i < PORT_COUNT / 32 && buf_sz > 1; i++) {
        uint32_t word = businessPortBitMap[i];
        if (word == 0)
            continue;
        for (bit = 0; bit < 32 && buf_sz > 1; bit++) {
            if (word & (1u << bit)) {
                uint16_t port = (uint16_t)(i * 32 + bit);
                if (port == 0)
                    continue;
                if (first) {
                    ret += snprintf(buf + ret, buf_sz - ret, "%u", port);
                    first = 0;
                } else {
                    ret += snprintf(buf + ret, buf_sz - ret, ",%u", port);
                }
            }
        }
    }

    ret += snprintf(buf + ret, buf_sz - ret, "\n");
    return ret;
}
static int __business_ports_parse(const char *buf, void *info)
{
    const char *p = buf;
    long port;
    char *endp;

    clear_business_port();

    while (*p) {
        /* 跳过空白和逗号 */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',' || *p == '\r')
            p++;
        if (*p == '\0')
            break;

        /* 解析数值，过滤异常输入 */
        port = simple_strtol(p, &endp, 10);
        if (endp == p) {
            /* 非法字符，跳过 */
            p++;
            continue;
        }
        p = endp;

        if (port > 0 && port <= 65535)
            set_business_port((uint16_t)port);
    }

    return 0;
}
static struct var_proc_info business_ports_rules_set =
{
        .parse = __business_ports_parse,
        .build = __business_ports_build,
};

//

#if TCP_ECN_FEATURE == 1
static int __tcp_force_ecn_build(char *buf, size_t buf_sz, void *info)
{

    memset(buf, 0, buf_sz);
    snprintf(buf, 1024,  "tcp_force_ecn: %u\n", tcp_force_ecn);
        return 0;
}
static int __tcp_force_ecn_parse(const char *buf, void *info)
{
    if (sscanf(buf, "%u", &tcp_force_ecn) == 1) {
        if (tcp_force_ecn > 1) {
            tcp_force_ecn = 0;
        }
    }
        return 0;
}
static struct var_proc_info tcp_force_ecn_set =
{
        .parse = __tcp_force_ecn_parse,
        .build = __tcp_force_ecn_build,
};
#endif

int network_dos_init(void)
{
    int err = 0;

    if (uc_init) {
        return err;
    }
   
    var_proc_create("net_rules", proc_osec, &net_rules_set);	
#if TCP_ECN_FEATURE == 1
    var_proc_create("tcp_force_ecn", proc_osec, &tcp_force_ecn_set);
#endif
    var_proc_create("business_ports", proc_osec, &business_ports_rules_set);

    //rwlock_init(&g_ntcp_policy_lock);
    spin_lock_init(&g_ntcp_policy_lock);
    //rwlock_init(&g_block_policy_lock);
    spin_lock_init(&g_block_policy_lock);   // Block 策略锁，改为 spinlock_t
    //memset(&gNetBlockPoicy, 0, sizeof(struct NetworkKernelPolicyInfo));
    gNetBlockPoicy = NULL;
    INIT_LIST_HEAD(&gListTcpPolicy.NETISOLATE_LIST);
   // LOG_INFO("=================ncount=%d==============================\n",ARRAY_SIZE(con_callbacks));
    err = register_notify_callback(con_callbacks, ARRAY_SIZE(con_callbacks));
    if (err) {
        LOG_ERROR("network_dos register_notify_callback error");
        return err;
    }
    err = kosecs_register_nf_holds(g_netdos_nf_holds, ARRAY_SIZE(g_netdos_nf_holds));
    if (err) {
        LOG_ERROR("network_dos nf_register_net_holds error");
        unregister_notify_callback(con_callbacks);
        return err;
    }
    LOG_INFO("zero_copy_load_succeed=[%x]\n", zero_copy_load_succeed);

    uc_init = 1;
    LOG_INFO("DRIVER NET INIT MODULE\n");
    return err;
}

int network_dos_exit(void)
{
    struct NetworkKernelPolicyInfo *policy;
    if (uc_init == 0) {
        return 0;
    }
  
    stop_in_netlog_audit_timer();
    stop_out_netlog_audit_timer();
    stop_dns_netlog_audit_timer();
    stop_openport_audit_timer();

    net_dos_turn_off();
    syslog_turn_off();
    net_block_turn_off();
    kosecs_unregister_nf_holds(g_netdos_nf_holds,ARRAY_SIZE(g_netdos_nf_holds));
    unregister_notify_callback(con_callbacks);

    clean_net_tcp_udp_list_rcu(&gListTcpPolicy.NETISOLATE_LIST);
// 清理 Block 策略
    spin_lock_bh(&g_block_policy_lock);
    policy = gNetBlockPoicy;
    gNetBlockPoicy = NULL;
    spin_unlock_bh(&g_block_policy_lock);

    // 等待所有 RCU 读端完成
    synchronize_rcu();

    // 释放 Block 策略内存
    if (policy) {
        kfree(policy);
    }
    var_proc_remove("business_ports", proc_osec);
    var_proc_remove("net_rules", proc_osec);
#if TCP_ECN_FEATURE == 1
    var_proc_remove("tcp_force_ecn", proc_osec);
#endif
    LOG_INFO("DRIVER NET WATER EXIT MODULE\n");
    uc_init = 0;
    return 0;
}

static int get_process_executable_path(struct task_struct *tsk, char *buf, size_t buf_size) 
{
    int len = 0;
    int _len = 0;
    char *exe_name;

    if (!tsk) return -1;
    exe_name = kvd_get_task_pathname(tsk, &len);
    if (IS_ERR(exe_name)) {
        return -1;
    }
    _len = (len + 1) > buf_size ? (buf_size -1):(len + 1);
    snprintf(buf, _len, exe_name);
    kvd_put_pathname(exe_name);
    return 0;
}

void start_in_netlog_audit_timer(void)
{
    if (zero_copy_load_succeed & IN_NETLOG_AUDIT_ENABLE) {
        if (atomic_test_and_set_timer_status(NETLOG_AUDIT_TIMER_ON)) {
            LOG_INFO("in_netlog_audit timer already started, skipping...\n");
            return;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        timer_setup(&netlog_audit_timer, netlog_audit_timer_function, 0);
#else
        setup_timer(&netlog_audit_timer, netlog_audit_timer_function, 0);
#endif
        mod_timer(&netlog_audit_timer, jiffies + 30 * HZ);
        LOG_INFO("start in_netlog_audit timer===============================\n");
    }
}
void stop_in_netlog_audit_timer(void)
{
    if (atomic_test_and_clear_timer_status(NETLOG_AUDIT_TIMER_ON)) {
        del_timer_sync(&netlog_audit_timer); 
        LOG_INFO("stop in_netlog_audit timer===============================\n");
    }    

}

void start_out_netlog_audit_timer(void)
{
    if (zero_copy_load_succeed & OUT_NETLOG_AUDIT_ENABLE) {
        if (atomic_test_and_set_timer_status(OUT_NETLOG_AUDIT_TIMER_ON)) {
            LOG_INFO("out_netlog_audit timer already started, skipping...\n");
            return;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        timer_setup(&out_netlog_audit_timer, out_netlog_audit_timer_function, 0);
#else
        setup_timer(&out_netlog_audit_timer, out_netlog_audit_timer_function, 0);
#endif
        mod_timer(&out_netlog_audit_timer, jiffies + 30 * HZ);
        LOG_INFO("start out_netlog_audit timer===============================\n");
    }

}
void stop_out_netlog_audit_timer(void)
{
    if (atomic_test_and_clear_timer_status(OUT_NETLOG_AUDIT_TIMER_ON)) {
        del_timer_sync(&out_netlog_audit_timer);
        LOG_INFO("stop out_netlog_audit timer===============================\n");
    }
}

void start_dns_netlog_audit_timer(void)
{
    if (zero_copy_load_succeed & DNS_NETLOG_AUDIT_ENABLE) {
        if (atomic_test_and_set_timer_status(DNS_NETLOG_AUDIT_TIMER_ON)) {
            LOG_INFO("dns_netlog_audit timer already started, skipping...\n");
            return;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        timer_setup(&dns_netlog_audit_timer, dns_netlog_audit_timer_function, 0);
#else
        setup_timer(&dns_netlog_audit_timer, dns_netlog_audit_timer_function, 0);
#endif
        mod_timer(&dns_netlog_audit_timer, jiffies + 30 * HZ);
        LOG_INFO("start dns_netlog_audit timer===============================\n");
    }

}
void stop_dns_netlog_audit_timer(void)
{
    if (atomic_test_and_clear_timer_status(DNS_NETLOG_AUDIT_TIMER_ON)) {
        del_timer_sync(&dns_netlog_audit_timer);
        LOG_INFO("stop dns_netlog_audit timer===============================\n");
    }  
}
void start_openport_audit_timer(void)
{
    if (zero_copy_load_succeed & OPENPORT_AUDIT_ENABLE) {
        if (atomic_test_and_set_timer_status(OPENPORT_AUDIT_TIMER_ON)) {
            LOG_INFO("openport_audit timer already started, skipping...\n");
            return;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        timer_setup(&openport_audit_timer, openport_audit_timer_function, 0);
#else
        setup_timer(&openport_audit_timer, openport_audit_timer_function, 0);
#endif
        mod_timer(&openport_audit_timer, jiffies + 30 * HZ);
        LOG_INFO("start openport_audit timer===============================\n");
    }

}
void stop_openport_audit_timer(void)
{
    if (atomic_test_and_clear_timer_status(OPENPORT_AUDIT_TIMER_ON)) {
        del_timer_sync(&openport_audit_timer); 
        LOG_INFO("stop openport_audit timer===============================\n");
    }
}

