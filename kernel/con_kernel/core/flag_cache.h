/*
 * flag_cache.h
 * 2016.11.16
 */

#ifndef _FLAG_CACHE_H_
#define _FLAG_CACHE_H_

#include <linux/version.h>
#include <linux/types.h>
#include <linux/list.h>
// #if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
// #include <linux/semaphore.h>
// #else
#include <linux/completion.h>
// #endif

typedef void (*Tkerncallback)(void* extra);
// 内核hook事件后的等待标记结构体
struct wait_flag {
    void* key; //wait_flag元素咱一标识
    atomic_t ref;  //引用计数
    struct completion comp;
    void* extra;
    struct list_head node;
    Tkerncallback callback;
};

struct wait_flag* get_wait_flag(void* extra, Tkerncallback callback);
int waiting_flag(struct wait_flag* p_wait_flag);
void no_waiting(struct wait_flag* p_wait_flag);
void put_wait(void* key);

void wake_wait_flag(void* key);
void* get_wait_extra(void* key);

void wake_all_wait_flags(void);
int init_wait_flags(void);
void uninit_wait_flags(void);
#endif
