/*
 *netfilter.h: 2019-07-11 created by qudreams
 *a wrapper for netfilter hooks
 */

#ifndef NET_FILTER_H
#define NET_FILTER_H

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netfilter.h>

struct sk_buff;
struct net_device;


//定义这个宏，只是为了下面写代码方便
#ifndef RHEL_RELEASE_CODE 
#define RHEL_RELEASE_CODE 0
#define RHEL_RELEASE_VERSION(a,b) 1
#endif

//so urgly,but it's smaple to use,and cleanly
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
        #define DEFINE_NF_HOOK_FN(fn_name,fn_helper)                        \
            static unsigned int fn_name(void *priv,                         \
                                        struct sk_buff *skb,                \
                                        const struct nf_hook_state *state)  \
            {                                                               \
                unsigned int hooknum = state->hook;                         \
                struct net_device* in = state->in;                          \
                struct net_device* out = state->out;                        \
                unsigned int ret = NF_ACCEPT;                               \
                ret = fn_helper(hooknum, skb, in, out);                     \
                return ret;                                                 \
            }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
        #define DEFINE_NF_HOOK_FN(fn_name,fn_helper)                        \
            static unsigned int fn_name(const struct nf_hook_ops *ops,      \
                                        struct sk_buff *skb,                \
                                        const struct net_device *in,        \
                                        const struct net_device *out,       \
                                        int (*okfn)(struct sk_buff *))      \
            {                                                               \
                unsigned int ret = NF_ACCEPT;                               \
                unsigned int hooknum = ops->hooknum;                        \
                ret = fn_helper(hooknum, skb, in, out);                     \
                return ret;                                                 \
            }
#elif RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2)  
        //此处不首先判断RHEL_RELEASE_CODE宏，完全是因为像Neokylin7.0这些系统
        //本身是基于RedHat改的，但却没有完全将RHEL_RELEASE_CODE宏给去掉，
        //导致我们判断不正常
        #ifndef __GNKSYMS__
            #define LAST_NF_HOOK_ARG  const struct nf_hook_state *state
        #else
            #define LAST_NF_HOOK_ARG  int (*okfn)(struct sk_buff *)
        #endif

        #define DEFINE_NF_HOOK_FN(fn_name,fn_helper)                        \
            static unsigned int fn_name(const struct nf_hook_ops *ops,      \
                                        struct sk_buff *skb,                \
                                        const struct net_device *in,        \
                                        const struct net_device *out,       \
                                        LAST_NF_HOOK_ARG                    \
                                    )                                       \
            {                                                               \
                unsigned int ret = NF_ACCEPT;                               \
                unsigned int hooknum = ops->hooknum;                        \
                ret = fn_helper(hooknum, skb, in, out);                     \
                return ret;                                                 \
            }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)                                  
        #define DEFINE_NF_HOOK_FN(fn_name,fn_helper)                        \
            static unsigned int fn_name(unsigned int hooknum,               \
                                        struct sk_buff *skb,                \
                                        const struct net_device *in,        \
                                        const struct net_device *out,       \
                                        int (*okfn)(struct sk_buff *))      \
            {                                                               \
                unsigned int ret = NF_ACCEPT;                               \
                ret = fn_helper(hooknum, skb, in, out);                     \
                return ret;                                                 \
            }
#else       
        #define DEFINE_NF_HOOK_FN(fn_name,fn_helper)                        \
            static unsigned int fn_name(unsigned int hooknum,               \
                                        struct sk_buff **pskb,              \
                                        const struct net_device *in,        \
                                        const struct net_device *out,       \
                                        int (*okfn)(struct sk_buff *))      \
            {                                                               \
                struct sk_buff   *skb = *pskb;                              \
                unsigned int ret = NF_ACCEPT;                               \
                ret =fn_helper(hooknum, skb, in, out);                      \
                return ret;                                                 \
            }
#endif
        
//对于我们自行定义的RHEL_RELEASE_CODE宏其值一定为0,
//使用完后，我们取消它的定义
#if RHEL_RELEASE_CODE == 0
#undef RHEL_RELEASE_CODE
#undef RHEL_RELEASE_VERSION
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
    #define OSEC_NF_INET_LOCAL_OUT NF_INET_LOCAL_OUT
    #define OSEC_NF_INET_LOCAL_IN  NF_INET_LOCAL_IN
    #define OSEC_NF_INET_PRE_ROUTING  NF_INET_PRE_ROUTING
    #define OSEC_NF_INET_POST_ROUTING  NF_INET_POST_ROUTING
#else
    #define OSEC_NF_INET_LOCAL_OUT NF_IP_LOCAL_OUT
    #define OSEC_NF_INET_LOCAL_IN  NF_IP_LOCAL_IN
    #define OSEC_NF_INET_PRE_ROUTING  NF_IP_PRE_ROUTING
    #define OSEC_NF_INET_POST_ROUTING  NF_IP_POST_ROUTING
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
    #define KOSEC_NFPROTO_ARP       NFPROTO_ARP
#else
    #define KOSEC_NFPROTO_ARP       NF_ARP
#endif

//4.13及以后的版本全部没有了nf_register_hooks
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13, 0)
    #define kosecs_register_nf_holds(nf_hooks,hooks_size) \
            nf_register_hooks(nf_hooks,hooks_size)
    
    #define kosecs_unregister_nf_holds(nf_hooks,hooks_size) \
            nf_unregister_hooks(nf_hooks,hooks_size)
#else
    #define kosecs_register_nf_holds(nf_hooks,hooks_size) \
            nf_register_net_hooks(&init_net,nf_hooks,hooks_size)

    #define kosecs_unregister_nf_holds(nf_hooks,hooks_size) \
            nf_unregister_net_hooks(&init_net,nf_hooks,hooks_size)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    #define kosecs_ip_hdr(skb) ip_hdr(skb)
    #define kosecs_udp_hdr(skb) udp_hdr(skb)
    #define kosecs_arp_hdr(skb) arp_hdr(skb)
#else
    #define kosecs_ip_hdr(skb) (skb->h.ipiph)
    #define kosecs_udp_hdr(skb) (skb->h.uh)
    #define kosecs_arp_hdr(skb) (skb->nh.arph)
#endif

#endif
