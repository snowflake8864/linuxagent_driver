#ifndef __KVD_SYSCALL_DEF_H__
#define __KVD_SYSCALL_DEF_H__

#include <linux/types.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/module.h>

#if defined(__sw_64__) || (defined(__aarch64__) && (LINUX_VERSION_CODE == KERNEL_VERSION(4,19,232)))
    #include <asm/unistd.h> //for NR_SYSCALLS
#else
    #include <asm/asm-offsets.h> //for NR_syscalls,__NR_syscalls,__NR_syscall_max
#endif

//调用者不要直接使用__NR_SYSCALLS，
//用下面的KVD_NR_SYSCALLS宏
#ifdef NR_syscalls
    #define __NR_SYSCALLS    NR_syscalls
#elif defined(__NR_syscalls)
    #define __NR_SYSCALLS    __NR_syscalls
#elif defined(__NR_syscall_max)
    #define __NR_SYSCALLS    (__NR_syscall_max + 1)
#elif defined(NR_SYSCALLS)
    #define __NR_SYSCALLS    NR_SYSCALLS
#endif

//在2.6.27.5-117.fc10.i686内核上发现的，前面的定义都匹配不上
#ifndef __NR_SYSCALLS
    #warning "__NR_SYSCALLS not defined,so we define it 325"
    #define __NR_SYSCALLS   325
#endif

#ifdef __aarch64__
/*
 *arm64平台上这些宏都没有定义
 *  __NR_open
    __NR_link
    __NR_unlink
    __NR_chmod
    __NR_chown
    __NR_mkdir
    __NR_rmdir
    __NR_lchown
    __NR_rename
    __NR_utimes
    __NR_futimesat
    __NR_umount
 */
#ifndef __NR_open
    #warning "__NR_open not defined,so we define it -1"
    #define __NR_open -1
#endif
#ifndef __NR_link
    #warning "__NR_link not defined,so we define it -1"
    #define __NR_link -1
#endif
#ifndef __NR_unlink
    #warning "__NR_unlink not defined,so we define it -1"
    #define __NR_unlink -1
#endif

#ifndef __NR_chmod
    #warning "__NR_chmod not defined,so we define it -1"
    #define __NR_chmod -1
#endif

#ifndef __NR_chown
    #warning "__NR_chown not defined,so we define it -1"
    #define __NR_chown -1
#endif

#ifndef __NR_lchown
    #warning "__NR_lchown not defined,so we define it -1"
    #define __NR_lchown -1
#endif

#ifndef __NR_mkdir
    #warning "__NR_mkdir not defined,so we define it -1"
    #define __NR_mkdir -1
#endif

#ifndef __NR_rmdir
    #warning "__NR_rmdir not defined,so we define it -1"
    #define __NR_rmdir -1
#endif

#ifndef __NR_rename
    #warning "__NR_rename not defined,so we define it -1"
    #define __NR_rename -1
#endif

#ifndef __NR_utimes
    #warning "__NR_utimes not defined,so we define it -1"
    #define __NR_utimes -1
#endif

#ifndef __NR_futimesat
    #warning "__NR_futimesat not defined,so we define it -1"
    #define __NR_futimesat -1
#endif

#ifndef __NR_umount
    #warning "__NR_umount not defined,so we define it -1"
    #define __NR_umount -1
#endif


#define KVD_SYSCALL_INDEX(snr) snr
#define KVD_NR_SYSCALLS __NR_SYSCALLS
#define KVD_SC_NR(nr) (nr)
#endif /* __aarch64__ */

#ifdef __x86_64__
#ifndef __NR_umount
    #warning "__NR_umount not defined,so we define it -1"
    #define __NR_umount -1
#endif

#define KVD_SYSCALL_INDEX(snr) snr
#define KVD_NR_SYSCALLS __NR_SYSCALLS
#define KVD_SC_NR(nr) (nr)
#endif  /* __x86_64__ */

#ifdef __i386__
#define KVD_SYSCALL_INDEX(snr) snr
#define KVD_NR_SYSCALLS __NR_SYSCALLS
#define KVD_SC_NR(nr) (nr)

#ifndef __NR_connect
    #warning "__NR_connect not defined,so we define it -1"
    #define __NR_connect -1
#endif

#ifndef __NR_bind
    #warning "__NR_bind not defined,so we define it -1"
    #define __NR_bind -1
#endif

#ifndef __NR_socket
    #warning "__NR_socket not defined,so we define it -1"
    #define __NR_socket -1
#endif

#ifndef __NR_accept
    #warning "__NR_accept not defined,so we define it -1"
    #define __NR_accept -1
#endif

#endif  /* __i386__ */

#ifdef __mips__
#ifndef __NR_umount
    #warning "__NR_umount not defined,so we define it -1"
    #define __NR_umount -1
#endif

/*
 *Mips的syscall的值获取的宏以内核版本5.0.0区分
 *5.0之下__NR_Linux_syscalls
 *5.0及以上__NR_syscalls
 * 2.6.32内核源码有__NR_Linux_syscalls
 * 但NeoKylin头文件无这个宏，发现syscall的值是在__NR_Linux的基础上向上加的
 * 目前适配 只有2.6.32 和 3.10版本的，无法通过头文件区分，先以3.0.0区分吧
 * 所以，小于3.0.0版本我们在计算syscall索引时要减去相应值
 */
#define KVD_SYSCALL_INDEX(snr) (snr - __NR_Linux)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#define KVD_NR_SYSCALLS (__NR_syscalls)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
/* 3.x至4.x内核上__NR_Linux_syscalls为最大的系统调用号, 系统调用数需加1 */
#define KVD_NR_SYSCALLS (__NR_Linux_syscalls+1)
#else 
#define KVD_NR_SYSCALLS (__NR_SYSCALLS - __NR_Linux)
#endif
#define KVD_SC_NR(nr) ((nr) + __NR_Linux)
#endif  /* __mips__ */


//龙芯3A500
#ifdef __loongarch64

#ifndef __NR_bind
    #warning "__NR_bind not defined,so we define it -1"
    #define __NR_bind -1
#endif


#ifndef __NR_mount
    #warning "__NR_mount not defined,so we define it -1"
    #define __NR_mount -1
#endif


#ifndef __NR_umount
    #warning "__NR_umount not defined,so we define it -1"
    #define __NR_umount -1
#endif

#ifndef __NR_link
    #warning "__NR_link not defined,so we define it -1"
    #define __NR_link -1
#endif

#ifndef __NR_unlink
    #warning "__NR_unlink not defined,so we define it -1"
    #define __NR_unlink -1
#endif


#ifndef __NR_renameat
    #warning "__NR_renameat not defined,so we define it -1"
    #define __NR_renameat -1
#endif


#ifndef __NR_rename
    #warning "__NR_rename not defined,so we define it -1"
    #define __NR_rename -1
#endif


#ifndef __NR_bind
    #warning "__NR_bind not defined,so we define it -1"
    #define __NR_bind -1
#endif



#ifndef __NR_mkdir
    #warning "__NR_mkdir not defined,so we define it -1"
    #define __NR_mkdir -1
#endif


#ifndef __NR_open
    #warning "__NR_open not defined,so we define it -1"
    #define __NR_open -1
#endif


#ifndef __NR_chmod
    #warning "__NR_chmod not defined,so we define it -1"
    #define __NR_chmod -1
#endif

#ifndef __NR_chown
    #warning "__NR_chown not defined,so we define it -1"
    #define __NR_chown -1
#endif

#ifndef __NR_lchown
    #warning "__NR_lchown not defined,so we define it -1"
    #define __NR_lchown -1
#endif

#ifndef __NR_utimes
    #warning "__NR_utimes not defined,so we define it -1"
    #define __NR_utimes -1
#endif

#ifndef __NR_futimesat
    #warning "__NR_futimesat not defined,so we define it -1"
    #define __NR_futimesat -1
#endif

#define KVD_SYSCALL_INDEX(snr) snr
#define KVD_NR_SYSCALLS __NR_SYSCALLS
#define KVD_SC_NR(nr) (nr)
#endif




//SW 64
#ifdef __sw_64__
#ifndef __NR_umount2
    #warning "__NR_umount2 not defined,so we define it -1"
    #define __NR_umount2 -1
#endif

#define KVD_SYSCALL_INDEX(snr) snr
#define KVD_NR_SYSCALLS __NR_SYSCALLS
#define KVD_SC_NR(nr) (nr)
#endif

//3.15以下版本的内核是没有renameat2的
#ifndef __NR_renameat2
    #warning "__NR_renameat2 not defined,so we define it -1"
    #define __NR_renameat2 -1
#endif


#ifndef __NR_utimensat
    #warning "__NR_utimensat not defined,so we define it -1"
    #define __NR_utimensat -1
#endif

#ifndef __NR_getdents
    #warning "__NR_getdents not defined,so we define it -1"
    #define __NR_getdents -1
#endif

#ifndef __NR_getdents64
    #warning "__NR_getdents64 not defined,so we define it -1"
    #define __NR_getdents64 -1
#endif

//mmap2这个系统调用在x86-64上肯定是没有的
#ifndef __NR_mmap2
#warning "__NR_mmap2 not defined,so we define it -1"
#define __NR_mmap2 -1
#endif

#ifndef __NR_accept4
#warning "__NR_accept4 not defined,so we define it -1"
#define __NR_accept4 -1
#endif

//socketcall这个系统调用在x86-64上是没有的
#ifndef __NR_socketcall
#warning "__NR_socketcall not defined,so we define it -1"
#define __NR_socketcall -1
#endif

/////////////////////////////////////////////////////////////////////////////////

#endif  /* __SYSCALL_DEF_H__ */
