#ifndef KOSEC_CTRL_CENTER_H
#define KOSEC_CTRL_CENTER_H

enum {
    CC_IPV4_CHANGED = 1, //控制中心ipv4地址变更通知
    CC_IPV6_CHANGED = 2, //控制中心ipv6地址变更通知
};

int register_cc_notifier(struct notifier_block* notifier);
void unregister_cc_notifier(struct notifier_block* notifier);

#endif
