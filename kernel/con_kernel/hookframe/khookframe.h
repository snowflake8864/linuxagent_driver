#ifndef KHOOK_FRAME_H
#define KHOOK_FRAME_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include "log_manager/log_mgr.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0)
#include <asm/syscall.h> //for syscall_set_arguments
#endif

#if defined(__sw_64__) || (defined(__aarch64__) && (LINUX_VERSION_CODE == KERNEL_VERSION(4,19,232)))
    #include <asm/unistd.h> //for NR_SYSCALLS
#else
    #include <asm/asm-offsets.h> //for NR_syscalls,__NR_syscalls,__NR_syscall_max
#endif

#include "hook/kvd_syscall.h"
#if 0
#ifndef LOG_INFO  
#define LOG_INFO(fmt, args...) printk(KERN_INFO "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
#endif

#ifndef LOG_ERROR
#define LOG_ERROR(fmt, args...) printk(KERN_ERR "[%s][%d]: "fmt, __FUNCTION__, __LINE__, ##args)
#endif
#ifndef LOG_DEBUG
#ifdef DEBUG_FLAG
    extern unsigned long debug_flag;
    #ifdef DEBUG
        #define LOG_DEBUG(fmt, args...) printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
    #else
        #define LOG_DEBUG(fmt, args...) {if (test_bit(0,&debug_flag)) {printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__, ##args);}}
    #endif
#else
    #ifdef DEBUG
        #define LOG_DEBUG(fmt, args...) printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
    #else
        #define LOG_DEBUG(fmt, args...) 
    #endif
#endif
#endif //end-define LOG_DEBUG

#endif

//////////////////////////////////////////////////////////////////
//每个系统调用最多只允许注册16个hook,再多了可能会影响性能了,
//16个本质上也有可能导致性能下降
#define KVD_HOOK_OPS_SIZE 16

typedef struct {
    void* data;
}kvd_hook_ctx_t;

/*
*目前我们最多支持6个参数，
*x86上最多是6个参数，但在4.16发现arm32上最多是7个
*而在arm64上最多又变成6个了
*/
#define KVD_SYSCALL_MAX_ARGS 6

//hook stop operations
enum {
    KVD_FLAG_STOP_NONE = 0,
    KVD_FLAG_STOP_NEXT = 1, //停止调用下一个hook点
    KVD_FLAG_STOP_ORG = 2,//停止调用原始系统调用
    KVD_FLAG_USE_RC = 4,//使用HOOK回调的返回值
    KVD_FLAG_STOP_POST = 8,//停止调用post-call
};

typedef struct kvd_regs_s {
    //要保证参数是按系统调用顺序传入的
    u_long args[KVD_SYSCALL_MAX_ARGS]; //我们最多支持6个参数
    u_int argc; //当前调用的参数个数
    long rc; //返回值
    u_int flag; // KVD_FLAG_XXX
    int syscall_idx; //系统调用索引号: SYS_xxxx_INDEX，不是实际的系统调用编号
}kvd_regs_t;

#define KVD_REGS_INIT(kvd_regs)         \
    kvd_regs.argc = 0;                  \
    kvd_regs.rc = 0;                    \
    kvd_regs.syscall_idx = -1;          \
    kvd_regs.flag = KVD_FLAG_STOP_NONE; \
    memset(kvd_regs.args,0,             \
        sizeof(kvd_regs.args))


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    #define __MAP0(m,...)
    #define __MAP1(m,t,a,...) m(t,a)
    #define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
    #define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
    #define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
    #define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
    #define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
    #define __MAP(n,...) __MAP##n(__VA_ARGS__)
    #define __SC_DECL(t, a)	t a
    #define __SC_CAST(t, a)	(t)a
    #define __SC_LONG(t,a) __typeof(0L) a
    #define __SC_ARGS(t, a)	a
#endif

#define __KVD_ARG_TO_REG0(kvd_regs,a) 
#define __KVD_ARG_TO_REG1(kvd_regs,a) (kvd_regs)->args[0] = (u_long)a
#define __KVD_ARG_TO_REG2(kvd_regs,a,b) __KVD_ARG_TO_REG1(kvd_regs,a), (kvd_regs)->args[1] = (u_long)b
#define __KVD_ARG_TO_REG3(kvd_regs,a,b,c) __KVD_ARG_TO_REG2(kvd_regs,a,b), (kvd_regs)->args[2] = (u_long)c
#define __KVD_ARG_TO_REG4(kvd_regs,a,b,c,d) __KVD_ARG_TO_REG3(kvd_regs,a,b,c), (kvd_regs)->args[3] = (u_long)d
#define __KVD_ARG_TO_REG5(kvd_regs,a,b,c,d,e) __KVD_ARG_TO_REG4(kvd_regs,a,b,c,d), (kvd_regs)->args[4] = (u_long)e
#define __KVD_ARG_TO_REG6(kvd_regs,a,b,c,d,e,f) __KVD_ARG_TO_REG5(kvd_regs,a,b,c,d,e), (kvd_regs)->args[5] = (u_long)f

#define KVD_ARG_TO_REG(x,kvd_regs,...) __KVD_ARG_TO_REG##x(kvd_regs,__VA_ARGS__)


#define __KVD_REG_TO_ARGS0(kvd_regs) \
        	__MAP(0,__SC_ARGS)

#define __KVD_REG_TO_ARGS1(kvd_regs) \
        	__MAP(1,__SC_ARGS \
			,,kvd_regs->args[0])

#define __KVD_REG_TO_ARGS2(kvd_regs) \
        	__MAP(2,__SC_ARGS \
			,,kvd_regs->args[0] \
			,,kvd_regs->args[1])

#define __KVD_REG_TO_ARGS3(kvd_regs) \
        	__MAP(3,__SC_ARGS \
			,,kvd_regs->args[0] \
			,,kvd_regs->args[1] \
            ,,kvd_regs->args[2])

#define __KVD_REG_TO_ARGS4(kvd_regs) \
        	__MAP(4,__SC_ARGS \
			,,kvd_regs->args[0] \
			,,kvd_regs->args[1] \
           	,,kvd_regs->args[2] \
			,,kvd_regs->args[3])

#define __KVD_REG_TO_ARGS5(kvd_regs) \
        	__MAP(5,__SC_ARGS \
			,,kvd_regs->args[0] \
			,,kvd_regs->args[1] \
           	,,kvd_regs->args[2] \
           	,,kvd_regs->args[3] \
			,,kvd_regs->args[4])

#define __KVD_REG_TO_ARGS6(kvd_regs) \
        	__MAP(6,__SC_ARGS \
			,,kvd_regs->args[0] \
			,,kvd_regs->args[1] \
           	,,kvd_regs->args[2] \
           	,,kvd_regs->args[3] \
           	,,kvd_regs->args[4] \
			,,kvd_regs->args[5])

#define KVD_REG_TO_ARGS(x,kvd_regs) \
	__KVD_REG_TO_ARGS##x(kvd_regs)


#define __KVD_REG_CAST_TO_ARGS1(args,t,a) \
        	t a = (t)(args[0]);           \
            (void)a

#define __KVD_REG_CAST_TO_ARGS2(args,t,a,...) \
        	t a = (t)(args[0]);               \
            __KVD_REG_CAST_TO_ARGS1((args + 1),__VA_ARGS__); \
            (void)a

#define __KVD_REG_CAST_TO_ARGS3(args,t,a,...)  \
        	t a = (t)(args[0]);                \
            __KVD_REG_CAST_TO_ARGS2((args + 1),__VA_ARGS__); \
            (void)a

#define __KVD_REG_CAST_TO_ARGS4(args,t,a,...) \
        	t a = (t)(args[0]);               \
            __KVD_REG_CAST_TO_ARGS3((args + 1),__VA_ARGS__); \
            (void)a

#define __KVD_REG_CAST_TO_ARGS5(args,t,a,...)  \
        	t a = (t)(args[0]);                \
            __KVD_REG_CAST_TO_ARGS4((args + 1),__VA_ARGS__); \
            (void)a

#define __KVD_REG_CAST_TO_ARGS6(args,t,a,...)       \
            t a = (t)(args[0]);                     \
            __KVD_REG_CAST_TO_ARGS5((args + 1),__VA_ARGS__); \
            (void)a


#define KVD_REG_CAST_TO_ARGS(x,kvd_regs,...) \
	__KVD_REG_CAST_TO_ARGS##x((kvd_regs->args),__VA_ARGS__)


//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
extern void kvd_precall_hook_ops(kvd_regs_t* regs,
                kvd_hook_ctx_t ctxs[KVD_HOOK_OPS_SIZE]);

extern void kvd_postcall_hook_ops(kvd_regs_t* regs,
                kvd_hook_ctx_t ctxs[KVD_HOOK_OPS_SIZE]);

#define __KVD_HOOK_BEGIN(x,name,sc_idx,...)                             \
    {                                                                   \
        long rc = 0;                                                    \
        int gotmod = 0;                                                 \
        /*prehook是否被调用过，只有调用过prehook*/                      \
        /*才能调用posthook,两者是配对出现的*/                           \
        int bprehooked = 0;                                             \
        kvd_regs_t kvd_regs;                                            \
        kvd_hook_ctx_t hook_ctxs[KVD_HOOK_OPS_SIZE];                    \
                                                                        \
        KVD_REGS_INIT(kvd_regs);                                        \
        kvd_regs.argc = x;                                              \
        kvd_regs.syscall_idx = sc_idx;                                  \
        KVD_ARG_TO_REG(x,&kvd_regs,__MAP(x,__SC_ARGS,__VA_ARGS__));     \
        gotmod = try_module_get(THIS_MODULE);                           \
        if(!gotmod) { goto org_syscall; }                               \
                                                                        \
        memset(hook_ctxs,0,sizeof(hook_ctxs));                          \
        kvd_precall_hook_ops(&kvd_regs,hook_ctxs);                      \
        bprehooked = 1;                                                 \
        /*KVD_FLAG_STOP_ORG被置位我们不再调用原始系统调用直接结束 */    \
        if(kvd_regs.flag & KVD_FLAG_STOP_ORG) { goto out; }  


#define __KVD_HOOK_END(x,name,syscall_idx,...)                      \
    out:                                                            \
        if(bprehooked && (!(kvd_regs.flag & KVD_FLAG_STOP_POST))) { \
            kvd_postcall_hook_ops(&kvd_regs,hook_ctxs);             \
        }                                                           \
        rc = kvd_regs.rc; /*返回值可能被修改过*/                    \
        if(gotmod) { module_put(THIS_MODULE); }                     \
        return rc;                                                  \
    }


#define __KVD_HOOK_DEFINE(x,name,syscall_idx,...)       \
    __KVD_HOOK_BEGIN(x,name,syscall_idx,__VA_ARGS__);   \
    __KVD_DO_REAL_SYSCALL(x,name,__VA_ARGS__);          \
    __KVD_HOOK_END(x,name,__VA_ARGS__);


/////////////////////////////////////////////////////////////////////////////////////////
//针对ftrace的情况

//只有同时开启下面这两个宏时才使用ftrace hook
//因为如果CONFIG_DYNAMIC_FTRACE_WITH_REGS就无法修改pc/ip值来达到hook syscall的目地
#if SPEC_VERSION_BUILD != 5
#if defined(CONFIG_DYNAMIC_FTRACE) && \
    defined(CONFIG_DYNAMIC_FTRACE_WITH_REGS)
#define FTRACE_HOOK_ENABLED 1
#endif
#endif

#define __KVD_FTRACE_HOOK_BEGIN(x,name,sc_idx,...)                      \
    {                                                                   \
        long rc = 0;                                                    \
        int gotmod = 0;                                                 \
        /*prehook是否被调用过，只有调用过prehook*/                      \
        /*才能调用posthook,两者是配对出现的*/                           \
        int bprehooked = 0;                                             \
        kvd_regs_t kvd_regs;                                            \
        kvd_hook_ctx_t hook_ctxs[KVD_HOOK_OPS_SIZE];                    \
                                                                        \
        KVD_REGS_INIT(kvd_regs);                                        \
        kvd_regs.argc = x;                                              \
        kvd_regs.syscall_idx = sc_idx;                                  \
        KVD_ARG_TO_REG(x,&kvd_regs,__MAP(x,__SC_ARGS,__VA_ARGS__));     \
        gotmod = try_module_get(THIS_MODULE);                           \
        if(!gotmod) { goto org_syscall; }                               \
        memset(hook_ctxs,0,sizeof(hook_ctxs));                          \
        kvd_precall_hook_ops(&kvd_regs,hook_ctxs);                      \
        bprehooked = 1;                                                 \
        /*KVD_FLAG_STOP_ORG被置位我们不再调用原始系统调用直接结束 */    \
        if(kvd_regs.flag & KVD_FLAG_STOP_ORG) { goto out; }  


#define __KVD_FTRACE_HOOK_END(x,name,syscall_idx,...)               \
    out:                                                            \
        if(bprehooked && (!(kvd_regs.flag & KVD_FLAG_STOP_POST))) { \
            kvd_postcall_hook_ops(&kvd_regs,hook_ctxs);             \
        }                                                           \
        rc = kvd_regs.rc; /*返回值可能被修改过*/                    \
        if(gotmod) { module_put(THIS_MODULE); }                     \
        return rc;                                                  \
    }


#define __KVD_FTRACE_HOOK_DEFINE(x,name,syscall_idx,...)        \
    __KVD_FTRACE_HOOK_BEGIN(x,name,syscall_idx,__VA_ARGS__);    \
    __KVD_DO_REAL_SYSCALL(x,name,__VA_ARGS__);                  \
    __KVD_FTRACE_HOOK_END(x,name,__VA_ARGS__);


////////////////////////////////////////////////////////////////////////////////

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
        static inline void
        kvd_syscall_set_arguments(struct task_struct* task,
                struct pt_regs* org_regs, struct pt_regs *new_regs,
                u_int i, u_int n, u_long* new_args)
        {
            memcpy(new_regs, org_regs, sizeof(*new_regs));
        }
	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
		static inline void 
		kvd_syscall_set_arguments(struct task_struct* task,
                                struct pt_regs* org_regs,
								struct pt_regs *new_regs,
								u_int i, u_int n,
								u_long* new_args)	
		{
			u_long __tmpargs[KVD_SYSCALL_MAX_ARGS] = {0};

			if(i + n > KVD_SYSCALL_MAX_ARGS) {
					return;
			}

			//先获取一下旧参数
			syscall_get_arguments(task,org_regs,__tmpargs);
			//更新新参数
			for(;i < n;i++) {
				__tmpargs[i] = new_args[i];
			}
				
			syscall_set_arguments(task,new_regs,__tmpargs);
		}
	#else
        static inline void 
        kvd_syscall_set_arguments(struct task_struct* task,
								struct pt_regs* org_regs,
								struct pt_regs *new_regs,
								u_int i, u_int n,
								u_long* new_args)
        {
			if(i + n > KVD_SYSCALL_MAX_ARGS) {
					return;
			}

            //先获取一下旧参数
            memcpy(new_regs,org_regs,sizeof(*new_regs));
            //更新新参数
            syscall_set_arguments(task,new_regs,i,n,new_args);
        }
	#endif


    #ifdef __aarch64__

        #define __KVD_SYSCALL_WRAPPER_DEFINEx(x, name, ...)                                \
            static asmlinkage long __hook_##name(struct pt_regs *regs) {                   \
                return __se_wrapper_##name(SC_ARM64_REGS_TO_ARGS(x,__VA_ARGS__), regs);	   \
            }

    #endif//__aarch64__

    #ifdef __x86_64__

        #define __KVD_SYSCALL_WRAPPER_DEFINEx(x, name, ...)                               \
            static asmlinkage long __hook_##name(struct pt_regs *regs)                    \
            {                                                                             \
                return __se_wrapper_##name(SC_X86_64_REGS_TO_ARGS(x,__VA_ARGS__), regs);  \
            }                                                                                                 

    #endif//__x86_64__

    ///*使用临时变量，不然在有些系统上会有问题,比如uos-server .19.34-1deepin-generic #636*/ 
    #define __KVD_DO_REAL_SYSCALL(x,name,...)                                            \
        org_syscall:                                                                     \
            if(!(kvd_regs.flag & KVD_FLAG_STOP_ORG)) {                                   \
                struct pt_regs  tmp_regs;                                                \
                BUG_ON(__real_##name == NULL);                                           \
                memset(&tmp_regs,0,sizeof(tmp_regs));                                    \
                kvd_syscall_set_arguments(current,regs,&tmp_regs,0,x,kvd_regs.args);     \
                rc = __real_##name(&tmp_regs);                                           \
                kvd_regs.rc = rc; /*有些hook会关心原始系统调用返回值*/                   \
            }

    #define __KVD_SYSCALL_DEFINEx(x, name,syscall_idx,...)                               \
        static long __se_wrapper_##name(__MAP(x,__SC_LONG,__VA_ARGS__),                  \
                                    struct pt_regs *regs);		                         \
        __KVD_SYSCALL_WRAPPER_DEFINEx(x,name,__VA_ARGS__);                               \
        ALLOW_ERROR_INJECTION(__hook_##name, ERRNO);			                         \
        static asmlinkage long (*__real_##name)(struct pt_regs *regs);                   \
        static inline long __do_wrapper_##name(__MAP(x,__SC_DECL,__VA_ARGS__),           \
                                            struct pt_regs *regs);                       \
        long __se_wrapper_##name(__MAP(x,__SC_LONG,__VA_ARGS__),                         \
                                    struct pt_regs *regs)		                         \
        {                                                                                \
            return __do_wrapper_##name(__MAP(x,__SC_CAST,__VA_ARGS__), regs);            \
        }                                                                                \
                                                                                         \
        inline long __do_wrapper_##name(__MAP(x,__SC_DECL,__VA_ARGS__),                  \
                                            struct pt_regs *regs)                        \
        __KVD_HOOK_DEFINE(x,name,syscall_idx,__VA_ARGS__)

    ////////////////////////////////////////////////////////////////////////////////////////
    //针对ftrace
    #define __KVD_FTRACE_SYSCALL_DEFINEx(x, name,syscall_idx,...)                        \
        static long __se_wrapper_##name(__MAP(x,__SC_LONG,__VA_ARGS__),                  \
                                    struct pt_regs *regs);		                         \
        __KVD_SYSCALL_WRAPPER_DEFINEx(x,name,__VA_ARGS__);                               \
        ALLOW_ERROR_INJECTION(__hook_##name, ERRNO);			                         \
        static asmlinkage long (*__real_##name)(struct pt_regs *regs);                   \
        static inline long __do_wrapper_##name(__MAP(x,__SC_DECL,__VA_ARGS__),           \
                                            struct pt_regs *regs);                       \
        long __se_wrapper_##name(__MAP(x,__SC_LONG,__VA_ARGS__),                         \
                                    struct pt_regs *regs)		                         \
        {                                                                                \
            return __do_wrapper_##name(__MAP(x,__SC_CAST,__VA_ARGS__), regs);            \
        }                                                                                \
                                                                                         \
        inline long __do_wrapper_##name(__MAP(x,__SC_DECL,__VA_ARGS__),                  \
                                            struct pt_regs *regs)                        \
        __KVD_FTRACE_HOOK_DEFINE(x,name,syscall_idx,__VA_ARGS__)


        #define KVD_CALL_SYS_FUNC_DIRECT(func,...) func(regs)

        #define KVD_CALL_SYS_FUNC(n,func,...)                   \
            ({                                                  \
                __TO_REG##n(__VA_ARGS__);                       \
                KVD_CALL_SYS_FUNC_DIRECT(func,__VA_ARGS__);     \
            })
#else/* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */
   
    #define __KVD_DO_REAL_SYSCALL(x,name,...)                           \
        org_syscall:                                                    \
            if(!(kvd_regs.flag & KVD_FLAG_STOP_ORG))                    \
            {                                                           \
                BUG_ON(__real_##name == NULL);                          \
                rc = __do_real_##name(&kvd_regs);                       \
                kvd_regs.rc = rc; /*有些hook会关心原始系统调用返回值*/  \
            }

    #define __KVD_SYSCALL_DEFINEx(x, name,sc_idx,...)                               \
        static asmlinkage long (*__real_##name)(__MAP(x,__SC_DECL,__VA_ARGS__));    \
        static long __do_se_##name(__MAP(x,__SC_LONG,__VA_ARGS__))                  \
        {                                                                           \
            return __real_##name(__MAP(x,__SC_CAST,__VA_ARGS__));                   \
        }                                                                           \
                                                                                    \
        static asmlinkage long __do_real_##name(kvd_regs_t* kvd_regs)               \
        {                                                                           \
            return __do_se_##name(KVD_REG_TO_ARGS(x,kvd_regs));                     \
        }                                                                           \
                                                                                    \
        static asmlinkage long __hook_##name(__MAP(x,__SC_DECL,__VA_ARGS__))        \
        __KVD_HOOK_DEFINE(x,name,sc_idx,__VA_ARGS__)
      
        ///////////////////////////////////////////////////////////////////////////////
        //针对ftrace
    #define __KVD_FTRACE_SYSCALL_DEFINEx(x, name,sc_idx,...)                        \
        static asmlinkage long (*__real_##name)(__MAP(x,__SC_DECL,__VA_ARGS__));    \
        static long __do_se_##name(__MAP(x,__SC_LONG,__VA_ARGS__))                  \
        {                                                                           \
            return __real_##name(__MAP(x,__SC_CAST,__VA_ARGS__));                   \
        }                                                                           \
                                                                                    \
        static asmlinkage long __do_real_##name(kvd_regs_t* kvd_regs)               \
        {                                                                           \
            return __do_se_##name(KVD_REG_TO_ARGS(x,kvd_regs));                     \
        }                                                                           \
                                                                                    \
        static asmlinkage long __hook_##name(__MAP(x,__SC_DECL,__VA_ARGS__))        \
        __KVD_FTRACE_HOOK_DEFINE(x,name,sc_idx,__VA_ARGS__)
      


        #define KVD_CALL_SYS_FUNC_DIRECT(func, args...) func(args)

        #define KVD_CALL_SYS_FUNC(n,func,...) \
                KVD_CALL_SYS_FUNC_DIRECT(func,__VA_ARGS__)
#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */
////////////////////////////////////////////////////////////////////////////////////////////
#define KVD_HOOK_SYSCALL_DEFINEx(x, name,syscall_idx,...)     \
        __KVD_SYSCALL_DEFINEx(x, name,syscall_idx,__VA_ARGS__);                     

#define KVD_HOOK_SYSCALL_DEFINE1(name,syscall_idx,...)  \
    KVD_HOOK_SYSCALL_DEFINEx(1, name,syscall_idx, __VA_ARGS__)

#define KVD_HOOK_SYSCALL_DEFINE2(name,syscall_idx, ...)  \
    KVD_HOOK_SYSCALL_DEFINEx(2, name,syscall_idx, __VA_ARGS__)

#define KVD_HOOK_SYSCALL_DEFINE3(name,syscall_idx, ...)  \
    KVD_HOOK_SYSCALL_DEFINEx(3, name,syscall_idx, __VA_ARGS__)

#define KVD_HOOK_SYSCALL_DEFINE4(name,syscall_idx, ...)  \
    KVD_HOOK_SYSCALL_DEFINEx(4, name,syscall_idx, __VA_ARGS__)

#define KVD_HOOK_SYSCALL_DEFINE5(name,syscall_idx, ...)  \
    KVD_HOOK_SYSCALL_DEFINEx(5, name,syscall_idx, __VA_ARGS__)

#define KVD_HOOK_SYSCALL_DEFINE6(name,syscall_idx, ...)  \
    KVD_HOOK_SYSCALL_DEFINEx(6, name,syscall_idx, __VA_ARGS__)

//////////////////////////////////////////////////////////////////////////
//针对ftrace
#ifdef FTRACE_HOOK_ENABLED
    #define KVD_FTRACE_HOOK_SYSCALL_DEFINEx(x, name,syscall_idx,...)     \
            __KVD_FTRACE_SYSCALL_DEFINEx(x, name,syscall_idx,__VA_ARGS__);
#else
    #define KVD_FTRACE_HOOK_SYSCALL_DEFINEx(x, name,syscall_idx,...)     \
            __KVD_SYSCALL_DEFINEx(x, name,syscall_idx,__VA_ARGS__);                     
#endif

#define KVD_FTRACE_HOOK_SYSCALL_DEFINE1(name,syscall_idx,...)  \
    KVD_FTRACE_HOOK_SYSCALL_DEFINEx(1, name,syscall_idx, __VA_ARGS__)   

#define KVD_FTRACE_HOOK_SYSCALL_DEFINE2(name,syscall_idx, ...)  \
    KVD_FTRACE_HOOK_SYSCALL_DEFINEx(2, name,syscall_idx, __VA_ARGS__)

#define KVD_FTRACE_HOOK_SYSCALL_DEFINE3(name,syscall_idx, ...)  \
    KVD_FTRACE_HOOK_SYSCALL_DEFINEx(3, name,syscall_idx, __VA_ARGS__)

#define KVD_FTRACE_HOOK_SYSCALL_DEFINE4(name,syscall_idx, ...)  \
    KVD_FTRACE_HOOK_SYSCALL_DEFINEx(4, name,syscall_idx, __VA_ARGS__)

#define KVD_FTRACE_HOOK_SYSCALL_DEFINE5(name,syscall_idx, ...)  \
    KVD_FTRACE_HOOK_SYSCALL_DEFINEx(5, name,syscall_idx, __VA_ARGS__)

#define KVD_FTRACE_HOOK_SYSCALL_DEFINE6(name,syscall_idx, ...)  \
    KVD_FTRACE_HOOK_SYSCALL_DEFINEx(6, name,syscall_idx, __VA_ARGS__)


////////////////////////////////////////////////////////////////////////////////
//kvd_register_sc_hook/kvd_unregister_sc_hook用于注册系统调用的回调
//不要直接调用下面这两个函数，使用对应的宏进行调用
//register_sc_hook只允许在模块初始化时调用
extern int __kvd_register_sc_hook(int syscall_idx,
            void* hook_fn,void** pporg_fn);
//不支持在模块运行时进行unregister
extern void __kvd_unregister_sc_hook(int syscall_idx);


extern void __set_syscall_name(int syscall_idx,
                            const char* name);

#define KVD_REGISTER_SC_HOOK(name,syscall_idx)          \
    (__set_syscall_name(syscall_idx,#name),             \
    __kvd_register_sc_hook(syscall_idx,(void*)__hook_##name,(void**)&__real_##name))

#define KVD_UNREGISTER_SC_HOOK(syscall_idx)          \
    __kvd_unregister_sc_hook(syscall_idx)

#ifdef FTRACE_HOOK_ENABLED
    /*
    *下面这些hook接口支持ftrace hook系统调用,并且在ftrace未开启时采用常规syscall-hook
    *目前ftrace hook只支持x64与arm64,其他平台不支持
    */
    #ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
        #ifdef __x86_64__
            #define KVD_REGISTER_SC_FTRACE_HOOK(name,syscall_idx)          \
                (__set_syscall_name(syscall_idx,"__x64_sys_"#name), \
                __kvd_register_sc_hook(syscall_idx,(void*)__hook_sys_##name,(void**)&__real_sys_##name))
        #elif defined(__aarch64__)
            #define KVD_REGISTER_SC_FTRACE_HOOK(name,syscall_idx)              \
                (__set_syscall_name(syscall_idx,"__arm64_sys_"#name),   \
                __kvd_register_sc_hook(syscall_idx,(void*)__hook_sys_##name,(void**)&__real_sys_##name))
            
        #else
            #define KVD_REGISTER_SC_FTRACE_HOOK(name,syscall_idx)    \
                (__set_syscall_name(syscall_idx,"SyS_"#name),             \
                __kvd_register_sc_hook(syscall_idx,(void*)__hook_sys_##name,(void**)&__real_sys_##name))
        #endif
    #else
        #define KVD_REGISTER_SC_FTRACE_HOOK(name,syscall_idx)    \
            (__set_syscall_name(syscall_idx,"SyS_"#name),             \
            __kvd_register_sc_hook(syscall_idx,(void*)__hook_sys_##name,(void**)&__real_sys_##name))
    #endif
#else
    #define KVD_REGISTER_SC_FTRACE_HOOK(name,syscall_idx)    \
            (__set_syscall_name(syscall_idx,"sys_"#name),             \
            __kvd_register_sc_hook(syscall_idx,(void*)__hook_sys_##name,(void**)&__real_sys_##name))
#endif

#define KVD_UNREGISTER_SC_FTRACE_HOOK \
        __kvd_unregister_sc_hook

////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////

//hook prority
enum {
    KVD_OPS_PRI_FIRST = INT_MIN,
    KVD_OPS_PRI_SECOND = 0,
    KVD_OPS_PRI_LAST = INT_MAX,
};


struct kvd_hook_ops {
    struct list_head lh;
    void (*pre_cb)(kvd_regs_t* regs,kvd_hook_ctx_t* ctx);
    void (*post_cb)(kvd_regs_t* regs,kvd_hook_ctx_t* ctx);
    int syscall_idx;
    int prority; //KVD_OPS_PRI_XXX
    uint8_t idx; //该hook_ops在对应系统调用注册链表中的编号,由注册函数自动分配
};

#define KVD_INIT_HOOK_OPS(__pre_cb,__post_cb,__sc_idx,__pri) \
    {                                                        \
        .pre_cb = __pre_cb,                                  \
        .post_cb = __post_cb,                                \
        .syscall_idx = __sc_idx,                             \
        .prority = __pri,                                    \
    }

#define KVD_INIT_PREHOOK_OPS(__pre_cb,__sc_idx,__pri)   \
        KVD_INIT_HOOK_OPS(__pre_cb,NULL,__sc_idx,__pri)

#define KVD_INIT_HOOK_FIRST_OPS(__pre_cb,__post_cb,__sc_idx)   \
        KVD_INIT_HOOK_OPS(__pre_cb,__post_cb,__sc_idx,KVD_OPS_PRI_FIRST)

#define KVD_INIT_PREHOOK_FIRST_OPS(__pre_cb,__sc_idx)  \
        KVD_INIT_PREHOOK_OPS(__pre_cb,__sc_idx,KVD_OPS_PRI_FIRST)

#define KVD_INIT_PREHOOK_SECOND_OPS(__pre_cb,__sc_idx)  \
        KVD_INIT_PREHOOK_OPS(__pre_cb,__sc_idx,KVD_OPS_PRI_SECOND)

#define KVD_INIT_PREHOOK_LAST_OPS(__pre_cb,__sc_idx)  \
        KVD_INIT_PREHOOK_OPS(__pre_cb,__sc_idx,KVD_OPS_PRI_LAST)


#define KVD_INIT_POSTHOOK_OPS(__post_cb,__sc_idx,__pri)   \
        KVD_INIT_HOOK_OPS(NULL,__post_cb,__sc_idx,__pri)

#define KVD_INIT_POSTHOOK_FIRST_OPS(__post_cb,__sc_idx)  \
        KVD_INIT_POSTHOOK_OPS(__post_cb,__sc_idx,KVD_OPS_PRI_FIRST)

#define KVD_INIT_POSTHOOK_SECOND_OPS(__post_cb,__sc_idx)  \
        KVD_INIT_POSTHOOK_OPS(__post_cb,__sc_idx,KVD_OPS_PRI_SECOND)

#define KVD_INIT_POSTHOOK_LAST_OPS(__post_cb,__sc_idx)  \
        KVD_INIT_POSTHOOK_OPS(__post_cb,__sc_idx,KVD_OPS_PRI_LAST)


int kvd_init(const char* sysmaps[],size_t size);
int kvd_init_with_ftrace(const char* sysmaps[],size_t size,
                    u_int fh_if_supprted);
void kvd_uninit(void);

/* 接入通用LSM框架初始化接口 */
int kvd_init_ftrace_commlsm(const char* sysmaps[],
        size_t size, u_int fh_if_supported);
/* 增加在syscall-hook被占用时是否仍强制启用syscall-hook的接口 */
int kvd_init_ftrace_commlsm2(const char* sysmaps[],
        size_t size, u_int fh_if_supported, int force_syscall_hook);
void kvd_uninit_ftrace_commlsm(void);

//当前框架正在启用的系统调用hook方式
const char* kvd_sc_hook_mode(void);

/*
 *此处的opses是一个数组，count为该数组的大小
 *用于注册系统调用hook操作分别有precall/postcall
 *调用下面这两个函数的情况是:
 *只能在模块初始化函数中调用,一旦注册完成就不能在模块运行时更改，
 *只能在模块反初始化函数中进行反注册;因为我们的框架中多处理要依赖于prehook与posthook的配合出现
 *尤其在处理precall/postcall的上下文时，如果存在模块运行时动态进行register/unregister的情况
 *极有可能出现上下文无法正常释放或者乱掉的情况
 */
int kvd_register_hook_ops(struct kvd_hook_ops* opses,int count);
//不支持在模块运行时进行unregister
void kvd_unregister_hook_ops(struct kvd_hook_ops* opses,int count);

/*
 *Note:
 *下面这两个函数的调用应该在kvd_register_sc_hook/kvd_register_hook_ops之后
 *基本的调用步骤应当是:
 *1.kvd_register_sc_hook注册系统调用回调
 *2.kvd_register_hook_ops注册针对每个系统调用的operations
 *3.调用kvd_hook_syscalls执行实际的系统调用hook
 *
 *对于反注册:
 *1.先调用kvd_cleanup_syscalls,移除实际的系统调用hook点
 *2.再调用kvd_unregister_hook_ops移除针对每个系统调用的operations
 *3.最后调用kvd_unregister_sc_hook移除所有的系统调用回调
 *
 *对于2,3只能在模块卸载时执行，不支持在模块运行中执行;
 *模块卸载时2,3也可以不做，不会有什么影响
 */
//执行实际的系统调用hook
int kvd_hook_syscalls(void);
//清除实际系统调用hook
void kvd_cleanup_syscalls(void);

int kvd_sc_hook_start(void);
void kvd_sc_hook_stop(void);

//注册应用重定向
typedef struct kvd_exec_fake_s {
    struct list_head lh;
    const char* fake; //重定向目标应用完整路径
    //重定向检查函数: 返回0时表示不需要进行重定向，其他非0值表示需要进行重定向
    int (*fake_check)(const char* exec_path,
                       const char* comm);
    int (*fake_check2)(struct linux_binprm *bprm,
            const char* exec_path,const char* comm);
} kvd_exec_fake_t;

int kvd_register_exec_fake(kvd_exec_fake_t* exec_fake);
 //不支持在模块运行时进行unregister
void kvd_unregister_exec_fake(kvd_exec_fake_t* exec_fake);
u_int kvd_fh_enabled(void);
enum {
    KVD_FH_DISABLED = 0, //关闭ftrace-hook
    KVD_FH_SUPPOSED = 1, //建议开启ftrace-hook,此标识设置时只有在syscall-hook已被他人使用时才会使用ftrace-hook
    KVD_FH_PREFERENCE = 2, //ftrace-hook优先,此标识设置后内核直接优先使用ftrace-hook
};

/*
 *1. kylin lsm开启后默认使用hook lsm,不使用syscall-hook
 *2. SECURITY_WRITEABLE_HOOKS开启后采用lsm
 */
#if defined(CONFIG_SECURITY_KYLIN_EXTEND) || \
        defined(CONFIG_SECURITY_WRITABLE_HOOKS)
    #define KOSEC_LSM_HOOK_ENABLED 1
#endif

int kvd_syscall_hook_forced(void);
//修改写保护是否因驱动冲突等原因关闭
int kvd_wp_disabled(void);

#if defined(CONFIG_ARM64) && defined(CONFIG_KYLINOS_SERVER) && \
        (LINUX_VERSION_CODE == KERNEL_VERSION(4,19,90))
  #define KOSEC_IGNORE_EXEC_CMDLINE 1
#endif

#endif
