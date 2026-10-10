/*
 *exe_cmdline.h: 2019-08-07 created by qudreams
 *获取程序的命令行参数
 *Note:
 *1.vsec_get_exe_cmdline只适用于在register_binfmt回调用中获取命令行参数，
 *  其他情况下不要使用vsec_get_exe_cmdline，
 *2.vsec_get_user_pages只有在CONFIG_MMU宏开启时才起作用
 */
#ifndef EXE_CMDLINE_H
#define EXE_CMDLINE_H

#include <linux/types.h>

struct linux_binprm;
typedef struct cmd_argv_s {
    u_short len;
    char* argv;
} vsec_cmd_argv_t;

char* vsec_get_exe_cmdline(struct linux_binprm *bprm,
        char* buf,unsigned* plen);

//返回本次获取的参数个数，出错时返回小于0的值
//args标识的参数列表指向buffer标识的缓冲区
//每个参数使用NUL字符分隔
int vsec_get_exe_args(struct linux_binprm* bprm,
        char* buffer,size_t buflen,
        vsec_cmd_argv_t args[16],int args_count);

char* vsec_get_exe_env(struct linux_binprm *bprm,char* buff,unsigned* plen);

//成功返回对应环境变量的长度，否则返回小于0的值
int vsec_get_exe_env2(struct linux_binprm *bprm,
        void* ctx,bool (*find_cb)(char*env,unsigned,void*));

#endif //enddef EXE_CMDLINE_H
