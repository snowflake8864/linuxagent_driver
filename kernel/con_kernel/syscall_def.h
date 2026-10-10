#ifndef __SYSCALL_DEF_H__
#define __SYSCALL_DEF_H__

#include "hookframe/khookframe.h"

#define SYS_OPEN_INDEX      KVD_SYSCALL_INDEX(__NR_open)
#define SYS_OPENAT_INDEX    KVD_SYSCALL_INDEX(__NR_openat)

#define SYS_CLOSE_INDEX     KVD_SYSCALL_INDEX(__NR_close)

#define SYS_TRUNCATE_INDEX  KVD_SYSCALL_INDEX(__NR_truncate)
#define SYS_FTRUNCATE_INDEX  KVD_SYSCALL_INDEX(__NR_ftruncate)

#define SYS_LINK_INDEX      KVD_SYSCALL_INDEX(__NR_link)
#define SYS_LINKAT_INDEX    KVD_SYSCALL_INDEX(__NR_linkat)

#define SYS_UNLINK_INDEX    KVD_SYSCALL_INDEX(__NR_unlink)
#define SYS_UNLINKAT_INDEX  KVD_SYSCALL_INDEX(__NR_unlinkat)

#define SYS_CHMOD_INDEX     KVD_SYSCALL_INDEX(__NR_chmod)
#define SYS_FCHMOD_INDEX    KVD_SYSCALL_INDEX(__NR_fchmod)
#define SYS_FCHMODAT_INDEX  KVD_SYSCALL_INDEX(__NR_fchmodat)

#define SYS_CHOWN_INDEX     KVD_SYSCALL_INDEX(__NR_chown)
#define SYS_LCHOWN_INDEX    KVD_SYSCALL_INDEX(__NR_lchown)
#define SYS_FCHOWN_INDEX    KVD_SYSCALL_INDEX(__NR_fchown)
#define SYS_FCHOWNAT_INDEX  KVD_SYSCALL_INDEX(__NR_fchownat)

#define SYS_MKDIR_INDEX     KVD_SYSCALL_INDEX(__NR_mkdir)
#define SYS_MKDIRAT_INDEX   KVD_SYSCALL_INDEX(__NR_mkdirat)

#define SYS_RENAME_INDEX    KVD_SYSCALL_INDEX(__NR_rename)
#define SYS_RENAMEAT_INDEX  KVD_SYSCALL_INDEX(__NR_renameat)
#define SYS_RENAMEAT2_INDEX KVD_SYSCALL_INDEX(__NR_renameat2)

#define SYS_MOUNT_INDEX     KVD_SYSCALL_INDEX(__NR_mount)
//此处要使用__NR_umount2，2.6.18以后的内核上全部采用的它
#define SYS_UMOUNT_INDEX    KVD_SYSCALL_INDEX(__NR_umount2)
#define SYS_OLDUMOUNT_INDEX KVD_SYSCALL_INDEX(__NR_umount)

#define SYS_KILL_INDEX      KVD_SYSCALL_INDEX(__NR_kill)
#define SYS_PTRACE_INDEX    KVD_SYSCALL_INDEX(__NR_ptrace)


#define SYS_IOCTL_INDEX     KVD_SYSCALL_INDEX(__NR_ioctl)

#define SYS_UTIMENSAT_INDEX KVD_SYSCALL_INDEX(__NR_utimensat)

#define SYS_FUTIMESAT_INDEX KVD_SYSCALL_INDEX(__NR_futimesat) 
#define SYS_UTIMES_INDEX    KVD_SYSCALL_INDEX(__NR_utimes) 
#define SYS_MMAP_INDEX      KVD_SYSCALL_INDEX(__NR_mmap)
#define SYS_MMAP2_INDEX      KVD_SYSCALL_INDEX(__NR_mmap2)

#define SYS_GETDENTS_INDEX      KVD_SYSCALL_INDEX(__NR_getdents)
#define SYS_GETDENTS64_INDEX    KVD_SYSCALL_INDEX(__NR_getdents64)
//在mips和arm64上发现__NR_socketcall，所以在非i386上面，定义系统编号为-1
#if defined(__i386__) && defined(__ARCH_WANT_SYS_SOCKETCALL)
#define SYS_SOCKETCALL_INDEX     KVD_SYSCALL_INDEX(__NR_socketcall)
#else 
#define SYS_SOCKETCALL_INDEX     -1
#endif
#define SYS_ACCEPT_INDEX        KVD_SYSCALL_INDEX(__NR_accept)
#define SYS_BIND_INDEX          KVD_SYSCALL_INDEX(__NR_bind)
#define SYS_CONNECT_INDEX       KVD_SYSCALL_INDEX(__NR_connect)
#define SYS_SOCKET_INDEX        KVD_SYSCALL_INDEX(__NR_socket)
#define SYS_ACCEPT4_INDEX       KVD_SYSCALL_INDEX(__NR_accept4) 
#define SYS_DELETE_MODULE_INDEX  KVD_SYSCALL_INDEX(__NR_delete_module)

#endif  /* __SYSCALL_DEF_H__ */
