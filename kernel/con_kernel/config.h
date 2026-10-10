#ifndef KOSEC_CONFIG_H
#define KOSEC_CONFIG_H

#include <linux/version.h>

//简化一下宏长度,少打点字
#if defined(CONFIG_FIREWIRE_NET) || defined(CONFIG_FIREWIRE_NET_MODULE)
#define KOSEC_CONFIG_FIREWIRE_NET 1
#endif

#if defined(CONFIG_BRIDGE_NETFILTER) || defined(CONFIG_BRIDGE_NETFILTER_MODULE)
#define KOSEC_CONFIG_BRIDGE_NETFILTER 1
#endif

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#define KOSEC_CONFIG_IPV6 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
#define SYS_SOCKET_MAX      SYS_SENDMMSG 
#else 
#define SYS_SOCKET_MAX      SYS_RECVMSG
#endif 

#endif
