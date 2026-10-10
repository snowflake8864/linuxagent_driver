#include <linux/types.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <notify/client_notify.h>
#include "gnHead.h"
#include "netlink.h"
#include "core/gnkernel.h"
#include "core/kvd_core.h"

 //内核中定义groups只要小于32,必定会设置成默认值32
 //我们在调用netlink_kernel_create时设置的groups均是小于32的
 //所以此处我们直接将nl_groups设置为32
// static unsigned int nl_groups = 32;
static int nl_group_no = -1;
static struct sock *sw_netlink_sock = NULL;

static DEFINE_RWLOCK(_nl_st_lock);
static struct vsec_pack_stats _nl_st_in; //from user-space
static struct vsec_pack_stats _nl_st_out; //to user-space

int nl_send_msg(struct sk_buff *skb,u32 portid)
{
    //成功时返回0
 	int rc = netlink_unicast(sw_netlink_sock, skb,portid, MSG_DONTWAIT);
	if (rc >= 0) { rc = 0; return rc; }

    //－ECONNREFUSED表示应用层没有netlink通信端
    if(rc == -ECONNREFUSED) {
        return rc;
    }
    
    //返回EAGAIN我们不认为是完全失败了,这个一般都是因为消息量过大
    if(rc == -EAGAIN) {
        LOG_DEBUG("DRIVER_NETLINK: send netlink msg to user too quickly,and return EAGAIN\n");
    } else {
        LOG_ERROR("DRIVER_NETLINK: send netlink msg to user, because %d \n",rc);
    }

	return rc;
}

int set_nl_msg(struct sk_buff **skb, void *message, int message_len, int cmd)
{
    struct nlmsghdr *nlh = NULL;
    struct vsec_msg_data *nl_data = NULL;
    int recv_len = sizeof(struct vsec_msg_data) + message_len;

    //这里不使用NLMSG_SPACE,因为这个函数会使用4字节对齐
    //导致用户态收到的并不是实际内核发送的数据
    int len = NLMSG_LENGTH(recv_len);

    if (NULL == message) {
        LOG_ERROR("set netlink msg fail: message data is NULL \n");
        return -EINVAL;
    }

    *skb = alloc_skb(len, GFP_ATOMIC);
    if(!(*skb)) {
        LOG_ERROR("set netlink msg fail: alloc_skb fail, cmd (%i) \n", cmd);
        return -ENOMEM;
    }

    nlh = nlmsg_put(*skb, 0, 0, 0, recv_len, 0);
    if (NULL == nlh) {
        kfree_skb(*skb);
        LOG_ERROR("set netlink msg fail, because nlh addr get from skb is invalid \n");
        return -EINVAL;
    }

    nl_data = (struct vsec_msg_data *)NLMSG_DATA(nlh);
    if (NULL == nl_data) {
        kfree_skb(*skb);
        LOG_ERROR("set netlink msg fail, because nl data addr get from skb is invalid \n");
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
    NETLINK_CB(*skb).portid = 0;
#else
    NETLINK_CB(*skb).pid = 0;
#endif
    NETLINK_CB(*skb).dst_group = 0;
    memset(nl_data, 0, recv_len);
    nl_data->data_type = cmd;
    nl_data->data_len = message_len;
    memcpy(nl_data->data, message, message_len);

    return 0;
}

extern int dispath_msg(u16 msg_type, void* data,int data_len,u32 portid);
static int sw_netlink_receive_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    int         rc;
    u32         pid;
    void        *data;
    int         data_len;
    unsigned long flags;
    u16         msg_type = nlh->nlmsg_type;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    pid = NETLINK_CB(skb).portid;
#else
    pid  = NETLINK_CREDS(skb)->pid;
#endif

    data = NLMSG_DATA(nlh);
    data_len = skb->len - NLMSG_HDRLEN;
    //x86 系统上发现pid可能为0
    if(pid == 0) { pid = CURRENT_PID; }
    rc = dispath_msg(msg_type, data, data_len,pid);

    write_lock_irqsave(&_nl_st_lock,flags);
    if(rc == 0) { _nl_st_in.packets++; }
    else { _nl_st_in.drops++; }
    write_unlock_irqrestore(&_nl_st_lock,flags);

    return rc;
}


static void sw_netlink_receive_skb(struct sk_buff *skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static void sw_netlink_receive_sock(struct sock* sk,int len)
{
	struct sk_buff *skb;
	unsigned int qlen = skb_queue_len(&sk->sk_receive_queue);

	for (; qlen && (skb = skb_dequeue(&sk->sk_receive_queue)); qlen--) {
		sw_netlink_receive_skb(skb);
		kfree_skb(skb);
	}
}

static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
	return (struct nlmsghdr *)skb->data;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
void netlink_kernel_release(struct sock* sk)
{
	sock_release(sk->sk_socket);
}
#endif

static void sw_netlink_receive_skb(struct sk_buff *skb)
{
	int len;
	struct nlmsghdr *nlh;

	nlh = nlmsg_hdr(skb);
	len = skb->len;

	while (NLMSG_OK(nlh, len)) {
		sw_netlink_receive_msg(skb, nlh);
		nlh = NLMSG_NEXT(nlh, len);
   }
}

static DEFINE_MUTEX(netlink_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static void sw_netlink_receive(struct sk_buff *skb)
{
    mutex_lock(&netlink_mutex);
    sw_netlink_receive_skb(skb);
    mutex_unlock(&netlink_mutex);
}
#endif

int get_netlink_group(void)
{
    return nl_group_no;
}

static struct sock* do_create_netlink(int protocol)
{
    struct sock* sk = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    struct netlink_kernel_cfg cfg = {
        .input = sw_netlink_receive,
    };
    sk = netlink_kernel_create(&init_net, protocol, &cfg);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    sk = netlink_kernel_create(protocol,0,
		sw_netlink_receive_sock,THIS_MODULE);
#else
    sk = netlink_kernel_create(&init_net, protocol,
        0, sw_netlink_receive, NULL, THIS_MODULE);
#endif

    return sk;
}

static int create_netlink(int protocol)
{
    int rc = -1;
    int i = protocol;
    struct sock* sk = NULL;

    //为了防止netlink protocol被使用
    //在此处我们循环创建
    for(;i <= MAX_LINKS;i++) {
        sk = do_create_netlink(i);
        if(sk) { break; }
    }
    
    if (!sk) {
        LOG_ERROR("netlink create socket error, %d\n", protocol);
    } else {
        rc = 0;
        nl_group_no = i;
        sw_netlink_sock = sk;
        sw_netlink_sock->sk_sndtimeo = MAX_SCHEDULE_TIMEOUT;
        LOG_INFO("netlink system initialize %d ok\n", i);
    }

    return rc;
}

static void release_netlink(void)
{
    netlink_kernel_release(sw_netlink_sock);
    LOG_INFO("release netlink: %d\n",nl_group_no);
}

extern u32 get_snd_portid(void); //defined in gnkernel.c
static int netlink_notify_client(u16 cmd,void* data,u32 nsize)
{
    int rc = 0;
    unsigned long flags;
    struct sk_buff *skb = NULL;
    u32 portid = get_snd_portid();

    rc = set_nl_msg(&skb, data,(int)nsize,(int)cmd);
    if (!rc) {
        rc = nl_send_msg(skb,portid);
    }

    //-ECONNREFUSED表示应用层没有netlink通信端
    //此时我们不再统计，没有什么意义
    if(rc != -ECONNREFUSED) {
        write_lock_irqsave(&_nl_st_lock,flags);
        if(rc == 0) { _nl_st_out.packets++; }
        else { _nl_st_out.drops++; }
        write_unlock_irqrestore(&_nl_st_lock,flags);
    }

    return rc;
}

static client_notifier_t client_notifier = {
    .name = "netlink_notifier",
    .notify = netlink_notify_client,
};

int init_netlink(int protocol)
{
    int rc = 0;

    rc = create_netlink(protocol);
    if(rc) { return rc; }

    rc = vsec_register_client_notifier(&client_notifier);
    if(rc) { release_netlink(); }

    return rc;
}

void uninit_netlink(void)
{
    vsec_unregister_client_notifier(&client_notifier);
    release_netlink();
}

int vsec_netlink_get_stats(struct vsec_pack_stats* st_in,
					struct vsec_pack_stats* st_out)
{
    unsigned long flags;

    read_lock_irqsave(&_nl_st_lock,flags);
    *st_in = _nl_st_in;
    *st_out = _nl_st_out;
    read_unlock_irqrestore(&_nl_st_lock,flags);

    st_in->packets += st_in->drops;
    st_out->packets += st_out->drops;

	return 0;
}

