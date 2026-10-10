/*
 *task_cmdline.h: 2019-08-07 created by qudreams
 *获取已运行的进程命令参数
 *Note:
 *1.对于在register_binfmt回调用中获取命令行参数，
 *  不要使用vsec_get_task_cmdline，这个函数不适用于此种情况
 *2.vsec_get_user_pages只有在CONFIG_MMU宏开启时才起作用
 *plen-->是一个输入输出参数，作为输入参数用于指定buf的长度;
 *作为输出参数用于指定返回的命令行参数字长串长度
 */
#ifndef TASK_CMDLINE_H
#define TASK_CMDLINE_H

char* vsec_get_task_cmdline(struct task_struct* tsk,char* buf,unsigned* plen);

/*将命令行解析成单个参数的形式;
 *pargc返回参数个数; argv返回每个参数的指针,argv的指针指向buf缓存区
 *另外argv的大小要足够容纳所有参数
 **plen-->是一个输入输出参数，作为输入参数用于指定buf的长度;
 *    作为输出参数用于指定返回的命令行参数字长串长度
 * pargc-->是一个输入输出参数，作为输入参数用于指定argv的大小，
 *    作为输出参数用于返回实际命令行参数个数
 */
char* vsec_get_task_cmdline2(struct task_struct* tsk,char* buf,unsigned* plen,
                            unsigned* pargc,char* argv[]);

/*获取进程的环境变量: 
 *这个函数只适用于已经运行的进程，该函数不适用于在register_binfmt注册的回调用中获取进程的环境参数
 *因为register_binfmt注册的回调用中，进程用于存放环境参数的内存结构(task->mm)根本就没有构造好
 *
 *plen-->是一个输入输出参数，作为输入参数用于指定buf的长度;作为输出参数用于指定返回的环境参数字长串长度
 */
char* vsec_get_task_env(struct task_struct* tsk,char* buf,unsigned* plen);

/*将环境变量解析成单个参数的形式;
 *penvc返回参数个数; envs返回每个参数的指针,envs的指针指向buf缓存区
 *另外envs的大小要足够容纳所有参数
 **plen-->是一个输入输出参数，作为输入参数用于指定buf的长度;
 *    作为输出参数用于指定返回的命令行参数字长串长度
 * penvc-->是一个输入输出参数，作为输入参数用于指定envs的大小，
 *    作为输出参数用于返回实际命令行参数个数
 */
char* vsec_get_task_env2(struct task_struct* tsk,char* buf,unsigned* plen,
                            unsigned* penvc,char* envs[]);

#endif //enddef TASK_CMDLINE_H
