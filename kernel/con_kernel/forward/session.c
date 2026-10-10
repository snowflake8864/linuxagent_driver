#include <linux/module.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jhash.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <net/tcp.h>
#include <net/inet_ecn.h>
#include <net/arp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/dst.h>
#include <linux/netdevice.h>
#include <linux/inet.h>

#include <linux/net.h>
#include <linux/inet.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip6_checksum.h>


#include "defense/defense_inner.h"
#include "core/kvd_memcache.h"
#include "gnHead.h"
#include "hcache/h_cache.h"
#include "utils/var_proc.h"
#include "utils/utils.h"
#include "forward.h"
#include "session.h"

#ifdef SESSION_IPV6
#define ip46_address_is_ip4(ip46)   (((ip46)->pad[0] | (ip46)->pad[1] | (ip46)->pad[2]) == 0)
#endif
struct socket *g_socket = NULL;
struct sock *g_sock = NULL;
int init_forward = 0;
static uint32_t forward_gateway = 0;
struct proc_dir_entry *proc_session = NULL;
u32 g_hash_initval __read_mostly = 0;
EXPORT_SYMBOL(g_hash_initval);
static char forward_dev_name[32];
struct net_device *dev;
struct session_cache_table
{
    struct h_table h_table;
    struct kmem_cache *mem_cache;
} session_cache_tbl;
struct h_bucket session_cache_base[SESSION_CACHE_HASH_SIZE];


struct session_cache_key
{
    ip46_address_t  sip;
    ip46_address_t  dip;
    ip46_address_t  forward_dip;
    uint16_t  sport;
    uint16_t  dport;
    uint16_t  forward_sport;
    uint16_t  forward_dport;
    uint8_t   l4_proto;
    struct sk_buff *skb;
};
/* Find route for the newly created packet. */

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


static int forward_tcp(struct sk_buff *skb, ip46_address_t *sip, uint16_t sport, ip46_address_t *dip, uint16_t dport)
{
	struct sk_buff *nskb;
	struct iphdr *nih;
	struct tcphdr *nth;
    struct dst_entry *dst = NULL;
    struct rtable *rt = NULL;
    int ip_hdr_len;
    int tcp_hdr_len;
    struct skb_shared_info *shinfo = NULL;
    // 验证输入 SKB
    if (!skb || skb_headlen(skb) < sizeof(struct iphdr)) {
        LOG_ERROR("Invalid SKB\n");
        return -1;
    }

    nskb = skb_clone(skb, GFP_ATOMIC);
	if(unlikely(nskb == NULL))
		return -1;

    nih = ip_hdr(nskb);
    if (nih->ihl < 5 || nih->ihl > 15 || skb_headlen(nskb) < (nih->ihl << 2) + sizeof(struct tcphdr)) {
        LOG_ERROR("Invalid IP header\n");
        kfree_skb(nskb);
        return -1;
    }

    nth = (struct tcphdr *)((__u32 *)nih + nih->ihl);
    if (nth->doff < 5) {
        LOG_ERROR("Invalid TCP header\n");
        kfree_skb(nskb);
        return -1;
    }

    //skb_get(nskb);
    //nskb->sk = g_sock;
    struct osec_cb *cb = OSEC_CB(nskb);
    cb->a = 0xaabbccdd;
	nih->check = 0;
	nih->saddr = sip->ip4;
	nih->daddr = dip->ip4;
	
    //nth = tcp_hdr(nskb);  
	nth->source= sport;
	nth->dest= dport;

#if 1
    if (unlikely(nskb->ip_summed == CHECKSUM_PARTIAL)) {
        nth->check = ~tcp_v4_check(nskb->len, nih->saddr, nih->daddr, 0);
        nskb->csum_start = skb_transport_header(nskb) - nskb->head;
        nskb->csum_offset = offsetof(struct tcphdr, check);

    } else {
        nth->check = 0;
        nskb->csum = 0;
        nth->check = tcp_v4_check(nskb->len - (nih->ihl << 2), nih->saddr, nih->daddr,\
                csum_partial(nth, nskb->len - (nih->ihl << 2), nskb->csum));
//					 tcp_v4_check(nskb->len - ip_hdrlen(nih), nih->saddr, nih->daddr,\
                                csum_partial(nth, nskb->len - ip_hdrlen(nih), nskb->csum));
	}
#endif
    if(unlikely((rt = get_route_by_addr(nih->daddr)) == NULL)) {
		goto free_nskb;
    }
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
	dst = &rt->dst;
#else
    dst = &rt->u.dst;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	skb_dst_set(nskb, dst);
#else
	nskb->dst = dst;
#endif
	//nih->ttl = dst_metric(dst, RTAX_HOPLIMIT);
	nskb->ip_summed = CHECKSUM_NONE;
	/* Never happens */
    uint32_t mtu =  dst_mtu(dst);
    int fin = nth->fin;

    if (likely(nskb->len <= mtu)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        ip_local_out(&init_net, nskb->sk, nskb);	
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        ip_local_out(nskb);	
#else
        ip_local_out(nskb);	
#endif
    } else {
        shinfo = skb_shinfo(nskb);
        ip_hdr_len = nih->ihl << 2;
        tcp_hdr_len = nth->doff << 2;
        //LOG_INFO("Large SKB: len=%d, mtu=%d, ip_hdr_len=%d, tcp_hdr_len=%d, gso_size=%d\n",\
                nskb->len, mtu, ip_hdr_len, tcp_hdr_len, mtu - (ip_hdr_len + tcp_hdr_len));
        shinfo->gso_size = mtu - (ip_hdr_len + tcp_hdr_len);
        shinfo->gso_type = SKB_GSO_TCPV4;
        nskb->ip_summed = CHECKSUM_PARTIAL; // 需确认设备支持

        //        fragment_packet(nskb, mtu, dst);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        ip_local_out(&init_net, nskb->sk, nskb);	
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        ip_local_out(nskb);	
#else
        ip_local_out(nskb);	
#endif
    }
	
	return fin;
	
free_nskb:
	kfree_skb(nskb);
	return -1;
}



#ifdef SESSION_IPV6
#include <linux/version.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <net/tcp.h>

#if 0
static struct rtable *get_route_by_addr_v6(struct in6_addr *addr)
{
    struct rtable *rt = NULL;
    struct flowi6 fl6;
    struct net *net = &init_net;

    memset(&fl6, 0, sizeof(fl6));
    fl6.flowi6_proto = IPPROTO_TCP;
    fl6.daddr = *addr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
    struct fib6_result res = {};
    struct flowi6 fl6_masked;

    memset(&fl6_masked, 0, sizeof(fl6_masked));
    memcpy(&fl6_masked.daddr, &fl6.daddr, sizeof(fl6.daddr));
    fib6_rule_lookup(net, &fl6_masked, &res, 0);
    rt = res.f6i;
#else
    struct dst_entry *dst = ip6_route_output(net, NULL, &fl6);
    if (dst)
        rt = (struct rtable *)dst;
#endif

    return rt;
}
#endif

static int forward_tcp_v6(struct sk_buff *skb, ip46_address_t *sip, uint16_t sport,
                          ip46_address_t *dip, uint16_t dport)
{
    struct sk_buff *nskb;
    struct ipv6hdr *nih;
    struct tcphdr *nth;
    struct dst_entry *dst = NULL;
    struct rt6_info *rt = NULL;


#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
#define DEFAULT_TOS_VALUE   0x0U
    const __u8 tclass = DEFAULT_TOS_VALUE;

    struct flowi6 fl6;
    memset(&fl6, 0, sizeof(fl6));
    fl6.flowi6_proto = IPPROTO_TCP;
    fl6.saddr = sip->ip6;
    fl6.daddr = dip->ip6;
    fl6.fl6_sport = sport;
    fl6.fl6_dport = dport;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0) || SPEC_VERSION_BUILD == 4
    security_skb_classify_flow(skb, flowi6_to_flowi(&fl6));
#else
    security_skb_classify_flow(skb, flowi6_to_flowi_common(&fl6));
#endif

    dst = ip6_route_output(&init_net, NULL, &fl6);
    if (dst == NULL || dst->error) {
        dst_release(dst);
        return -1;
    }
    dst = xfrm_lookup(&init_net, dst, flowi6_to_flowi(&fl6), NULL, 0);
    if (IS_ERR(dst))
        return -1;
//#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
#else
    struct flowi fl;
    memset(&fl, 0, sizeof(fl));
    fl.proto = IPPROTO_TCP;
    ipv6_addr_copy(&fl.fl6_src, &sip->ip6);
    ipv6_addr_copy(&fl.fl6_dst, &dip->ip6);
    fl.fl_ip_sport = sport;
    fl.fl_ip_dport = dport;
    security_skb_classify_flow(skb, &fl);
    dst = ip6_route_output(&init_net, NULL, &fl);
    if (dst == NULL)
        return -1;




#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 28)
#if 0
    dst = xfrm_lookup(&init_net, &dst, &fl, NULL, 0);
    if (IS_ERR(dst))
        return -1;
#else
    if (dst->error || xfrm_lookup(&init_net, &dst, &fl, NULL, 0))
        return -1;
#endif        
#else
    if (dst->error || xfrm_lookup(&dst, &fl, NULL, 0))
        return -1;
#endif
#endif

    nskb = skb_clone(skb, GFP_ATOMIC);
    if (unlikely(!nskb)) {
        net_dbg_ratelimited("cannot alloc skb\n");
        dst_release(dst);
        return -1;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
    skb_dst_set(nskb, dst);
#else
    nskb->dst = dst;
#endif


    struct osec_cb *cb = OSEC_CB(nskb);
    cb->a = 0xaabbccdd;

    nih = ipv6_hdr(nskb);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
    ip6_flow_hdr(nih, tclass, 0);
#endif

#if 0
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
    nih->hop_limit = ip6_dst_hoplimit(dst);
#else
    nih->hop_limit = dst_metric(dst, RTAX_HOPLIMIT);
#endif
#endif

    nth = (struct tcphdr *)((__u8 *)nih + sizeof(struct ipv6hdr));
    nth->source = sport;
    nth->dest = dport;



    nih->nexthdr = IPPROTO_TCP;
    nih->saddr = sip->ip6;
    nih->daddr = dip->ip6;


                   
    if (unlikely(nskb->ip_summed == CHECKSUM_PARTIAL)) {
        nth->check = ~tcp_v6_check(nskb->len, &nih->saddr, &nih->daddr, 0);
        nskb->csum_start = skb_transport_header(nskb) - nskb->head;
        nskb->csum_offset = offsetof(struct tcphdr, check);
    } else {
        nth->check = 0;
        nskb->csum = 0;
        nth->check = tcp_v6_check(nskb->len - sizeof(struct ipv6hdr), &nih->saddr, &nih->daddr,
                                  csum_partial(nth, nskb->len - sizeof(struct ipv6hdr), nskb->csum));
    }

#if 0
    uint32_t mtu =  dst_mtu(dst);
    if (unlikely(nskb->len > mtu)) 
    {
        LOG_INFO("in %pI6:%u-->%pI6:%u Protocol: %d, mtu=%u, skb len:%u\n", \
           &nih->saddr, ntohs(nth->source),&nih->daddr, ntohs(nth->dest), nih->nexthdr, mtu, nskb->len);  
    }
#endif

    nskb->ip_summed = CHECKSUM_NONE;
   
    int fin =  nth->fin;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    ip6_local_out(&init_net, nskb->sk, nskb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    ip6_local_out(nskb);
#else
    ip6_local_out(nskb);
#endif
    return fin;
}

#endif



/*
static u32 session_cache_hash_fn(void *key)
{
    struct session_cache_key *k = (struct session_cache_key *)key;

    uint32_t a = k->sip ^ k->dip;
    uint32_t b = (k->sip + k->dip) & 0xFFFFFFFF;
    uint32_t c = ((k->sport + k->dport)& 0xFFFF) | (a << 24);
    return jhash_3words(a, b, c, g_hash_initval);
}
*/

static u32 session_cache_hash_fn(void *key) {
    struct session_cache_key *k = (struct session_cache_key *)key;
    u32 hash = 0;

#ifdef SESSION_IPV6
    if (ip46_address_is_ip4(&k->sip)) {
		uint32_t a = k->sip.ip4 ^ k->dip.ip4;
		uint32_t b = (k->sip.ip4 + k->dip.ip4) & 0xFFFFFFFF;
		uint32_t c = ((k->sport + k->dport)& 0xFFFF) | (a << 24);
		return jhash_3words(a, b, c, g_hash_initval);

    } else {
        // IPv6地址
        hash = jhash_1word(hash, g_hash_initval);
		hash = jhash(k->sip.ip6.s6_addr32, sizeof(k->sip.ip6.s6_addr32), g_hash_initval);
		hash ^= jhash(k->dip.ip6.s6_addr32, sizeof(k->dip.ip6.s6_addr32), g_hash_initval);
        hash ^= k->sport | (k->dport << 16);
        return jhash_1word(hash, g_hash_initval);
    }
#else
	uint32_t a = k->sip.ip4 ^ k->dip.ip4;
	uint32_t b = (k->sip.ip4 + k->dip.ip4) & 0xFFFFFFFF;
	uint32_t c = ((k->sport + k->dport)& 0xFFFF) | (a << 24);
	return jhash_3words(a, b, c, g_hash_initval);
#endif
}



static int session_cache_comp_key_fn(struct h_cache *he, void *key)
{
    struct session_cache *fc = container_of(he, struct session_cache, h_cache);
    struct session_cache_key *k = (struct session_cache_key *)key;

#ifdef SESSION_IPV6
    return (fc->sip.as_u64[0] ^ k->sip.as_u64[0] || fc->sip.as_u64[1] ^ k->sip.as_u64[1] \
			|| fc->dip.as_u64[0] ^ k->dip.as_u64[0]|| fc->dip.as_u64[1] ^ k->dip.as_u64[1]||\
					fc->sport ^ k->sport ||fc->dport ^ k->dport);
#else
		//LOG_INFO("comp_key %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u\n",\
				IPQUADS(k->sip.ip4), ntohs(k->sport), IPQUADS(k->dip.ip4), ntohs(k->dport));

	return (fc->sip.ip4 ^ k->sip.ip4 || fc->dip.ip4 ^ k->dip.ip4|| fc->sport ^ k->sport ||fc->dport ^ k->dport);
#endif
}


static void session_cache_release_fn(struct h_cache *he)
{
    struct session_cache *tc = container_of(he, struct session_cache, h_cache);
    set_rst_port(tc->dport, 0);
    set_rst_port(tc->sport, 0);
#if 0
	if (ip46_address_is_ip4(&tc->sip)) {
        LOG_INFO("free session, %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u\n",\
        IPQUADS(tc->sip.ip4), ntohs(tc->sport), IPQUADS(tc->dip.ip4), ntohs(tc->dport));
    } else {
		LOG_INFO("free session %pI6:%u-->%pI6:%u\n",
				&tc->sip.ip6, ntohs(tc->sport), 
				&tc->dip.ip6, ntohs(tc->dport));

    }
#endif
    kmem_cache_free(session_cache_tbl.mem_cache, tc);
}

static char *session_cache_build_line_fn(struct h_cache *he, gfp_t flags)
{   
    struct session_cache *tc = container_of(he, struct session_cache, h_cache);
    char s1[20], s2[20],s3[10],s4[10];
    char *line, *dp;
    
    if((line = (char *)kmalloc(150, flags)) == NULL)
        return NULL;
    /* Only XXX bytes max needed. */
    dp = line;
    
    char *proto = "TCP";
    sprintf(dp, "%-4s ", proto);
    dp += strlen(dp);
    
    /* Connection tuple description. */

#ifdef SESSION_IPV6
	if (ip46_address_is_ip4(&tc->sip)) {
		sprintf(dp, "%15s:%4s-->%15s:%4s\n",
				ipv4_nltos(tc->sip.ip4, s1), port_nstos(tc->sport,s3), 
				ipv4_nltos(tc->dip.ip4, s2), port_nstos(tc->dport,s4));
	} else {
    //LOG_INFO("in netdos_tcp_in_v6 process:%s, %pI6:%u-->%pI6:%u Protocol: %d\n", \
          CURRENT_COMM, &ip6h->saddr, ntohs(tcph->source),&ip6h->daddr, ntohs(tcph->dest), ip6h->nexthdr);  
		sprintf(dp, "%pI6:%4s-->%pI6:%4s\n",
				&tc->sip.ip6, port_nstos(tc->sport,s3), 
				&tc->dip.ip6, port_nstos(tc->dport,s4));
	}
#else
	sprintf(dp, "%15s:%4s-->%15s:%4s\n",
			ipv4_nltos(tc->sip.ip4, s1), port_nstos(tc->sport,s3), 
			ipv4_nltos(tc->dip.ip4, s2), port_nstos(tc->dport,s4));

#endif
	dp += strlen(dp);
#if 0   
    /* Statistics information. */
    sprintf(dp, "%lu/%d %lu/%d %d\n",
        (unsigned long)tc->tx_bytes, (unsigned)tc->tx_packets,
        (unsigned long)tc->rx_bytes, (unsigned)tc->rx_packets,
        (unsigned)tc->connections);
#endif
    return line;

}
static struct h_operations session_cache_ops =
{
    .hash        = session_cache_hash_fn,
    .comp_key    = session_cache_comp_key_fn,
    .release     = session_cache_release_fn,
    .build_line  = session_cache_build_line_fn,
};



#include <net/arp.h>
static struct h_cache *session_cache_create_fn(struct h_table *ht, void *key)
{   
    struct session_cache_key *k = (struct session_cache_key *)key;
    struct session_cache *tc;
    if((tc = (struct session_cache *)kvd_mem_cache_zalloc(session_cache_tbl.mem_cache, GFP_ATOMIC)) == NULL)
        return NULL;
    memcpy(&tc->sip, &k->sip, sizeof(ip46_address_t));
    memcpy(&tc->dip, &k->dip, sizeof(ip46_address_t));
    tc->sport = k->sport;
    tc->dport = k->dport;
    tc->forward_sport = k->sport;
    memcpy(&tc->forward_dip, &k->forward_dip, sizeof(ip46_address_t));
#ifdef SESSION_IPV6
    memcpy(&tc->forward_sip, &k->dip, sizeof(ip46_address_t));
#endif
    tc->forward_dport = k->forward_dport;
    tc->forward_sport = k->forward_sport;
    tc->rt = NULL;
    //tc->rt_addr = 0;
    //LOG_INFO("create session, size:%d, %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u,fip:%u.%u.%u.%u, rt=%p\n",\
    sizeof(ip46_address_t), IPQUADS(tc->sip.ip4), ntohs(tc->sport), IPQUADS(tc->dip.ip4), ntohs(tc->dport), IPQUADS(tc->forward_dip.ip4), tc->rt);
    //tc->rt = get_route_by_addr(k->forward_dip);
    struct sk_buff *skb = k->skb;
    if (likely(skb != NULL)) {
#ifdef SESSION_IPV6
		forward_tcp(k->skb, &tc->forward_sip, tc->forward_sport, &tc->forward_dip, tc->forward_dport);
#else
    //LOG_INFO("create session, size:%d, %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u,fip:%u.%u.%u.%u:fsport%u,fdport:%u rt=%p\n",\
    sizeof(ip46_address_t), IPQUADS(tc->sip.ip4), ntohs(tc->sport), IPQUADS(tc->dip.ip4), ntohs(tc->dport), \
	IPQUADS(tc->forward_dip.ip4), ntohs(tc->forward_sport), ntohs(tc->forward_dport), tc->rt);
		forward_tcp(k->skb, &tc->dip, tc->forward_sport, &tc->forward_dip, tc->forward_dport);
#endif
    }
    //spin_lock_init(&tc->lock);

    return &tc->h_cache;
}


struct session_cache *session_cache_try_get(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, uint16_t forward_sport, uint32_t forward_dip, uint16_t forward_dport, struct sk_buff *skb)
{
    struct h_cache *he;
    struct session_cache *tc;
    struct session_cache_key k;
    int rule_mask = 0;
    unsigned long __edata = 0;
	
#ifdef SESSION_IPV6
	k.sip.pad[0] = 0;
	k.sip.pad[1] = 0;
	k.sip.pad[2] = 0;

	k.dip.pad[0] = 0;
	k.dip.pad[1] = 0;
	k.dip.pad[2] = 0;

	k.forward_dip.pad[0] = 0;
	k.forward_dip.pad[1] = 0;
	k.forward_dip.pad[2] = 0;
#endif
    k.sip.ip4 = sip;
    k.sport = sport;
    k.dip.ip4 = dip;
    k.dport = dport;
    k.forward_dip.ip4 = forward_dip;
    k.forward_dport = forward_dport;
    k.forward_sport = forward_sport;
    k.skb = skb;
    if((he = h_entry_try_get(&session_cache_tbl.h_table, &k, 0, session_cache_create_fn, NULL)) == NULL)
        return NULL;
    tc = container_of(he, struct session_cache, h_cache);

    return tc;
}


#ifdef SESSION_IPV6
static struct h_cache *session_cache_create_fn_v6(struct h_table *ht, void *key)
{   
    struct session_cache_key *k = (struct session_cache_key *)key;
    struct session_cache *tc;
    if((tc = (struct session_cache *)kvd_mem_cache_zalloc(session_cache_tbl.mem_cache, GFP_ATOMIC)) == NULL)
        return NULL;
    memcpy(&tc->sip, &k->sip, sizeof(ip46_address_t));
    memcpy(&tc->dip, &k->dip, sizeof(ip46_address_t));
    tc->sport = k->sport;
    tc->dport = k->dport;
    tc->forward_sport = k->sport;
    memcpy(&tc->forward_dip, &k->forward_dip, sizeof(ip46_address_t));
    memcpy(&tc->forward_sip, &k->dip, sizeof(ip46_address_t));
    tc->forward_dport = k->forward_dport;
    tc->forward_sport = k->forward_sport;
    tc->rt = NULL;
    //tc->rt_addr = 0;
    //LOG_INFO("create sessio:%pI6:%u-->%pI6:%u, fip:%pI6 rt:%p\n",\
            &tc->sip.ip6, ntohs(tc->sport), &tc->dip.ip6, ntohs(tc->dport), &tc->forward_dip.ip6, tc->rt);

//    LOG_INFO("create session, size:%d, %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u,fip:%u.%u.%u.%u, rt=%p\n",\
    sizeof(ip46_address_t), IPQUADS(tc->sip.ip4), ntohs(tc->sport), IPQUADS(tc->dip.ip4), ntohs(tc->dport), IPQUADS(tc->forward_dip.ip4), tc->rt);
    //tc->rt = get_route_by_addr(k->forward_dip);
    struct sk_buff *skb = k->skb;
    if (likely(skb != NULL)) {
        //send_reset_v6(&init_net, k->skb);
		forward_tcp_v6(k->skb, &tc->forward_sip, tc->forward_sport, &tc->forward_dip, tc->forward_dport);

    }
    //spin_lock_init(&tc->lock);

    return &tc->h_cache;
}


struct session_cache *session_cache_try_get_v6(struct in6_addr *sip, uint16_t sport, struct in6_addr *dip, uint16_t dport, uint16_t forward_sport, struct in6_addr * forward_dip, uint16_t forward_dport, struct sk_buff *skb)
{
    struct h_cache *he;
    struct session_cache *tc;
    struct session_cache_key k;
    int rule_mask = 0;
    unsigned long __edata = 0;

    memcpy(&k.sip.ip6, sip, sizeof(struct in6_addr));
    k.sport = sport;
    memcpy(&k.dip.ip6, dip, sizeof(struct in6_addr));
    k.dport = dport;
    memcpy(&k.forward_dip.ip6, forward_dip, sizeof(struct in6_addr));
    k.forward_dport = forward_dport;
    k.forward_sport = forward_sport;
    k.skb = skb;
    if((he = h_entry_try_get(&session_cache_tbl.h_table, &k, 0, session_cache_create_fn_v6, NULL)) == NULL)
        return NULL;
    tc = container_of(he, struct session_cache, h_cache);

    return tc;
}
#endif

static void __session_cache_lookup_action(struct h_cache *he, void *key, void *result)
{
    struct session_cache_key *k = (struct session_cache_key *)key;
    struct session_cache *tc = container_of(he, struct session_cache, h_cache);
    int retv = 0;
    if (likely(k->skb != NULL)) {
#ifdef SESSION_IPV6
        retv = forward_tcp(k->skb, &tc->forward_sip, tc->forward_sport, &tc->forward_dip, tc->forward_dport);
#else
        retv = forward_tcp(k->skb, &tc->dip, tc->forward_sport, &tc->forward_dip, tc->forward_dport);
#endif
    }

    *(int *)result = (retv == -1 ? 0:1) | retv << 4;
}



int session_cache_lookup(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, struct sk_buff *skb)
{
    struct h_cache *he = NULL;
    struct session_cache *tc;
    struct session_cache_key k;
    int result = 0;
	
#ifdef SESSION_IPV6
	k.sip.pad[0] = 0;
	k.sip.pad[1] = 0;
	k.sip.pad[2] = 0;

	k.dip.pad[0] = 0;
	k.dip.pad[1] = 0;
	k.dip.pad[2] = 0;
#endif

    k.sip.ip4 = sip;
    k.sport = sport;
    k.dip.ip4 = dip;
    k.dport = dport;
    k.skb = skb;
    h_cache_try_lookup(&session_cache_tbl.h_table, &k, &result, &he, __session_cache_lookup_action);
    if (he != NULL) {
        if (result & 1 << 4) {
            h_entry_put_free(he);
        }
    }
    return result & 0x1;
}



static void tcp_debug(struct sk_buff *skb)
{
	struct iphdr *ih;
	struct tcphdr *th;
	struct dst_entry *dst = NULL;
    struct osec_cb *cb = OSEC_CB(skb);
    ih = ip_hdr(skb);  
    th = tcp_hdr(skb);  
    //LOG_INFO("tcp_debug:%u.%u.%u.%u:%u-->%u.%u.%u.%u:%u, syn:%d,ack:%d,rst:%d, sk:%p\n",\
            IPQUADS(ih->saddr), ntohs(th->source), IPQUADS(ih->daddr), ntohs(th->dest),th->syn,th->ack, th->rst, skb->sk);
	return;
}

static void __session_cache_lookup_action2(struct h_cache *he, void *key, void *result)
{
    struct session_cache_key *k = (struct session_cache_key *)key;
    //LOG_INFO("111111=======lookup2 session, %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u\n",\
    IPQUADS(k->sip), ntohs(k->sport), IPQUADS(k->dip), ntohs(k->dport));

    struct osec_cb *cb = OSEC_CB(k->skb);
    //tcp_debug(k->skb);
    *(int *)result = (cb->a != 0xaabbccdd);
}


int session_cache_lookup2(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, struct sk_buff *skb)
{
    struct h_cache *he = NULL;
    struct session_cache *tc;
    struct session_cache_key k;
    int result = 0;

#ifdef SESSION_IPV6
	k.sip.pad[0] = 0;
	k.sip.pad[1] = 0;
	k.sip.pad[2] = 0;

	k.dip.pad[0] = 0;
	k.dip.pad[1] = 0;
	k.dip.pad[2] = 0;
#endif

    k.sip.ip4 = sip;
    k.sport = sport;
    k.dip.ip4 = dip;
    k.dport = dport;
    k.skb = skb;
    h_cache_try_lookup(&session_cache_tbl.h_table, &k, &result, &he, __session_cache_lookup_action2);
    return result;
    struct osec_cb *cb = OSEC_CB(skb);
    return cb->a != 0xaabbccdd;
}

//=========================
#ifdef SESSION_IPV6
static void __session_cache_lookup_action_v6(struct h_cache *he, void *key, void *result)
{
    struct session_cache_key *k = (struct session_cache_key *)key;
    struct session_cache *tc = container_of(he, struct session_cache, h_cache);
    int retv = 0;
    if (likely(k->skb != NULL)) {
        //send_reset_v6(&init_net, k->skb);
        retv = forward_tcp_v6(k->skb, &tc->forward_sip, tc->forward_sport, &tc->forward_dip, tc->forward_dport);
    }
    
    *(int *)result = (retv == -1? 0: 1) | retv << 4;
}



int session_cache_lookup_v6(struct in6_addr * sip, uint16_t sport, struct in6_addr * dip, uint16_t dport, struct sk_buff *skb)
{
    struct h_cache *he = NULL;
    struct session_cache *tc;
    struct session_cache_key k;
    int result = 0;
	

    memcpy(&k.sip.ip6, sip, sizeof(struct in6_addr));
    k.sport = sport;
    memcpy(&k.dip.ip6, dip, sizeof(struct in6_addr));
    k.dport = dport;
    k.skb = skb;

//    LOG_INFO("===lookup:%pI6:%u-->%pI6:%u skb:%p\n",\
            sip, ntohs(sport), dip, ntohs(dport), skb);
    h_cache_try_lookup(&session_cache_tbl.h_table, &k, &result, &he, __session_cache_lookup_action_v6);
    if (he != NULL) {
        if (result & 1 << 4) {
            h_entry_put_free(he);
        }
    }
    return result & 0x1;
}



static void tcp_debug_v6(struct sk_buff *skb)
{
	struct dst_entry *dst = NULL;
    struct osec_cb *cb = OSEC_CB(skb);
    struct ipv6hdr *ip6h = ipv6_hdr(skb);  
    struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1); 
//    LOG_INFO("tcp_debug:%pI6:%u-->%pI6:%u, syn:%d,ack:%d,rst:%d, sk:%p\n",\
            &ip6h->saddr, ntohs(tcph->source), &ip6h->daddr, ntohs(tcph->dest),tcph->syn,tcph->ack, tcph->rst, skb->sk);

	return;
}

static void __session_cache_lookup_action2_v6(struct h_cache *he, void *key, void *result)
{
    struct session_cache_key *k = (struct session_cache_key *)key;
    //LOG_INFO("111111=======lookup2 session, %u.%u.%u.%u:%u-->%u.%u.%u.%u:%u\n",\
    IPQUADS(k->sip), ntohs(k->sport), IPQUADS(k->dip), ntohs(k->dport));

    struct osec_cb *cb = OSEC_CB(k->skb);
    //tcp_debug(k->skb);
    *(int *)result = (cb->a != 0xaabbccdd);
}


int session_cache_lookup2_v6(struct in6_addr *  sip, uint16_t sport, struct in6_addr *  dip, uint16_t dport, struct sk_buff *skb)
{
    struct h_cache *he = NULL;
    struct session_cache *tc;
    struct session_cache_key k;
    int result = 0;

    memcpy(&k.sip.ip6, sip, sizeof(struct in6_addr));
    k.sport = sport;
    k.dip.ip4 = dip;
    memcpy(&k.dip.ip6, dip, sizeof(struct in6_addr));
    k.dport = dport;
    k.skb = skb;
    h_cache_try_lookup(&session_cache_tbl.h_table, &k, &result, &he, __session_cache_lookup_action2_v6);
    return result;
    struct osec_cb *cb = OSEC_CB(skb);
    return cb->a != 0xaabbccdd;
}
#endif



/*
 * Operations for setting or displaying block gateway.
 */
static int __forward_device_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

	strncpy(buf, forward_dev_name,  buf_sz - 1);
	strcat(buf, "\n");
	return 0;
}
static int __forward_device_parse(const char *buf, void *info)
{
    if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) != 0) {
        return -EINVAL;
    }


	strncpy(forward_dev_name,  buf, sizeof(forward_dev_name));
	dev = dev_get_by_name(&init_net, forward_dev_name);
	return 0;
}
static struct var_proc_info forward_device_vinfo =
{
	.parse = __forward_device_parse,
	.build = __forward_device_build,
};


/*
 * Operations for setting or displaying block gateway.
 */
static int __forward_gateway_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }
	ipv4_hltos(forward_gateway, buf);
	strcat(buf, "\n");
	return 0;
}
static int __forward_gateway_parse(const char *buf, void *info)
{
    if (strncmp(CURRENT_COMM, "MagicArmor_0", 12) != 0) {
        return -EINVAL;
    }


	if(!is_ipv4_addr(buf))
		return -EINVAL;
	forward_gateway = ipv4_stohl(buf);
	return 0;
}
static struct var_proc_info forward_gateway_vinfo =
{
	.parse = __forward_gateway_parse,
	.build = __forward_gateway_build,
};



int session_cache_init(struct proc_dir_entry *proc_parent)
{
    int ret, retv = -1; 
     //g_hash_initval = (u32)CURRENT_TIME_SEC.tv_sec;
     g_hash_initval = (u32)jiffies;

    if((session_cache_tbl.mem_cache = kvd_mem_cache_create("session_cache",
        sizeof(struct session_cache), 0)) == NULL)
    {   
        retv = -ENOMEM;
        goto err_kmem_create;
    }   
    
    if((retv = h_table_create(&session_cache_tbl.h_table, session_cache_base,
        SESSION_CACHE_HASH_SIZE, SESSION_CACHE_MAX_LEN, SESSION_CACHE_TIMEOUT, &session_cache_ops,
        GFP_KERNEL, "session_cache_tbl", proc_parent)) < 0)
    {   
        goto err_session_create;
    }   
    
    VAR_PROC_FS_CREATE(session_cache_tbl.h_table.max_len, SESSION_CACHE_HASH_SIZE / 16, SESSION_CACHE_HASH_SIZE * 16, "session_cache_max", proc_parent);
    VAR_PROC_FS_CREATE(session_cache_tbl.h_table.timeo, 1, 7200, "session_cache_timeo", proc_parent);
	var_proc_create("forward_device", proc_parent, &forward_device_vinfo);	
	var_proc_create("forward_gateway", proc_parent, &forward_gateway_vinfo);	

    #if 0
    int err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &g_socket);
    if (err < 0) {
        LOG_INFO("Failed to create socket:%d\n",err);
    }
    g_sock = g_socket->sk;
    #endif
    init_forward = 1;
    LOG_INFO("session_cache_init success...\n");
    return retv;
err_session_create:
    VAR_PROC_FS_REMOVE("session_cache_timeo", proc_parent);
    VAR_PROC_FS_REMOVE("session_cache_max", proc_parent);
    kmem_cache_destroy(session_cache_tbl.mem_cache);
err_kmem_create:
    return retv;
}

void session_cache_exit(struct proc_dir_entry *proc_parent)
{
    
	var_proc_remove("forward_device", proc_parent);
	var_proc_remove("forward_gateway", proc_parent);
    VAR_PROC_FS_REMOVE("session_cache_timeo", proc_parent);
    VAR_PROC_FS_REMOVE("session_cache_max", proc_parent);
    h_table_release(&session_cache_tbl.h_table);
    kvd_mem_cache_destroy(session_cache_tbl.mem_cache);
//    sock_release(g_socket);
}
