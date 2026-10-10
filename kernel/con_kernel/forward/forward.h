#ifndef __FORWARD_FORWARD_H__
#define __FORWARD_FORWARD_H__
#include "session.h"

struct osec_cb{
    uint32_t a;
};
#define OSEC_CB(skb) ((struct osec_cb *)(skb)->cb)  
#define RST_PORT_COUNT 65536
static uint32_t rstPortBitMap[RST_PORT_COUNT/32];

static inline void set_rst_port(uint16_t port, int v) 
{  
    int index = port / 32;  
    int bit = port % 32;  
    rstPortBitMap[index] |= v << bit;  
}  
static inline void clear_rst_port(void) 
{  
    int i;
    for (i = 0; i < RST_PORT_COUNT / 32; i++) {
        rstPortBitMap[i] = 0;
    }
}
// 检查端口是否在位图中被标记为已使用  
static inline int is_rst_port(uint16_t port) {  
    int index = port / 32;  
    int bit = port % 32;  
    return (rstPortBitMap[index] & (1 << bit)) != 0;  
}  



struct session_cache *session_cache_try_get(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, uint16_t forward_sport, uint32_t forward_dip, uint16_t forward_dport, struct sk_buff *skb);
int session_cache_lookup(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, struct sk_buff *skb);
int session_cache_lookup2(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, struct sk_buff *skb);

struct session_cache *session_cache_try_get_v6(struct in6_addr *sip, uint16_t sport, struct in6_addr *dip, uint16_t dport, uint16_t forward_sport, struct in6_addr *forward_dip, uint16_t forward_dport, struct sk_buff *skb);
int session_cache_lookup_v6(struct in6_addr *sip, uint16_t sport, struct in6_addr *dip, uint16_t dport, struct sk_buff *skb);
int session_cache_lookup2_v6(struct in6_addr *sip, uint16_t sport, struct in6_addr *dip, uint16_t dport, struct sk_buff *skb);

int forward_init(void);
void forward_exit(void);
#endif
