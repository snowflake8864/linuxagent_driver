#include <linux/types.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include "client_notify.h"
#include "gnHead.h"


static DEFINE_RWLOCK(notify_locker);
static struct list_head client_notifiers;

typedef int (*notify_fn)(u16,void*,u32);

int vsec_notify_client(u16 cmd,void* data,u32 len)
{
    int res = 0;
    int rc = -EINVAL;
    unsigned long flags;
    notify_fn notify = NULL;
    rwlock_t* plocker = NULL;
    client_notifier_t* cur = NULL;
    client_notifier_t* next = NULL;
    struct list_head* plist = NULL;

    if(!data || (len == 0)) {
        return rc; 
    }

    rc = -EFAULT;
    plocker = &notify_locker;
    plist = &client_notifiers;

    read_lock_irqsave(plocker,flags);
    list_for_each_entry_safe(cur,next,
                        plist,lh)
    {
        if(!cur->notify) { continue; }

        notify = cur->notify;
        read_unlock_irqrestore(plocker,flags);
        res = notify(cmd,data,len);
        read_lock_irqsave(plocker,flags);
        //一个发送生成就视为整个成功,
        //全部失败才认为是失败
        if(!res) { rc = res; break; }
    }
    read_unlock_irqrestore(plocker,flags);

    return rc;
}

int vsec_register_client_notifier(client_notifier_t* notifier)
{
    int rc = -EINVAL;
    unsigned long flags;
    client_notifier_t* cur = NULL;
    client_notifier_t* next = NULL;
    struct list_head* plist = NULL;

    if(!notifier || !notifier->name || !notifier->notify) { 
        return rc; 
    }

    rc = 0;
    plist = &client_notifiers;
    write_lock_irqsave(&notify_locker,flags);
    list_for_each_entry_safe(cur,next,
                        plist,lh)
    {
        if(!strcmp(notifier->name,cur->name)) {
            rc = -EBUSY;
            break;
        }
    }

    if(!rc) { list_add_tail(&notifier->lh,plist); }
    write_unlock_irqrestore(&notify_locker,flags);

    LOG_INFO("register client notifier %s,rc: %d\n",
                notifier->name,rc);

    return rc;
}

int vsec_unregister_client_notifier(client_notifier_t* notifier)
{
    int rc = -EINVAL;
    unsigned long flags;
    client_notifier_t* cur = NULL;
    client_notifier_t* next = NULL;
    struct list_head* plist = NULL;

    if(!notifier || !notifier->name) { 
        return rc; 
    }

    plist = &client_notifiers;
    write_lock_irqsave(&notify_locker,flags);
    list_for_each_entry_safe(cur,next,
                        plist,lh)
    {
        if(!strcmp(notifier->name,cur->name)) {
            rc = 0;
            list_del(&cur->lh);
            break;
        }
    }
    write_unlock_irqrestore(&notify_locker,flags);

    LOG_INFO("unregister client notifier %s,rc: %d\n",
                        notifier->name,rc);

    return rc;
}

static void clean_notifiers(struct list_head* head)
{
    int count = 0;
    client_notifier_t* cur = NULL;
    client_notifier_t* next = NULL;

    list_for_each_entry_safe(cur,next,
                        head,lh)
    {
        count++;
        list_del(&cur->lh);
    }

    LOG_INFO("clean up client notifiers,"
        "affect items: %d\n",count);
}

void vsec_init_client_notifer(void)
{
    INIT_LIST_HEAD(&client_notifiers);
    LOG_INFO("init client notifier\n");
}

void vsec_uninit_client_notifier(void)
{
    unsigned long flags;
    struct list_head dup_list;

    INIT_LIST_HEAD(&dup_list);

    write_lock_irqsave(&notify_locker,flags);
    list_splice_init(&client_notifiers,&dup_list);
    write_unlock_irqrestore(&notify_locker,flags);

    clean_notifiers(&dup_list);
    LOG_INFO("uninit client notifier\n");    
}
