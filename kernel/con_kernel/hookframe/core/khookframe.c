#include "hook/kvd_hook.h"
#include "lsm/kvd_lsm.h"
#include "exec/exec_fake.h"
#include "khookframe.h"
#include "lsm/kvd_commlsm.h"

int kvd_init_sc_hook(u_int fh_if_supported);
int kvd_init_sc_hook2(u_int fh_if_supported, int force_syscall_hook);
void kvd_uninit_sc_hook(void);

/*
 *Note:
 *kvd_init是默认不开启ftrace hook功能的
 *kvd_init_with_ftrace默认是通过传入参数控制ftrace hook功能是否开启
 *
 *上面这样做目地是为了让hookframe框架在调用者使用时保持兼容
 *因为hookframe同时支持新旧不同版本的驱动
 */
int kvd_init(const char* sysmaps[],
            size_t size)
{
    int rc = 0;

    rc = kvd_hook_init(sysmaps,size);
    if(rc) { return rc; }
    
    rc = kvd_init_sc_hook(0);
    if(rc < 0) {
        kvd_hook_exit();
        goto out;
    }

    rc = kvd_init_lsm_hook();
    if(rc) {
        kvd_uninit_sc_hook();
        kvd_hook_exit();
        goto out;
    }

    rc = kvd_init_exec_fake();
    if(rc) {
        kvd_uninit_lsm_hook();
        kvd_uninit_sc_hook();
        kvd_hook_exit();
        goto out;
    }

out:
    return rc;
}

int kvd_init_with_ftrace(const char* sysmaps[],
            size_t size,u_int fh_if_supported)
{
    int rc = 0;

    rc = kvd_hook_init(sysmaps,size);
    if(rc) { return rc; }
    
    rc = kvd_init_sc_hook(fh_if_supported);
    if(rc < 0) {
        kvd_hook_exit();
        goto out;
    }

    rc = kvd_init_lsm_hook();
    if(rc) {
        kvd_uninit_sc_hook();
        kvd_hook_exit();
        goto out;
    }

    rc = kvd_init_exec_fake();
    if(rc) {
        kvd_uninit_lsm_hook();
        kvd_uninit_sc_hook();
        kvd_hook_exit();
        goto out;
    }

out:
    return rc;
}

void kvd_uninit(void)
{
    kvd_uninit_exec_fake();
    kvd_uninit_lsm_hook();
    kvd_uninit_sc_hook();
    kvd_hook_exit();
}

int kvd_init_ftrace_commlsm(const char* sysmaps[],
        size_t size,u_int fh_if_supported)
{
    int rc = 0;

    rc = kvd_hook_init(sysmaps,size);
    if(rc) { return rc; }

    rc = kvd_init_sc_hook(fh_if_supported);
    if(rc < 0) {
        kvd_hook_exit();
        goto out;
    }

    rc = kvd_init_commlsm_hook();
    if(rc) {
        kvd_uninit_sc_hook();
        kvd_hook_exit();
        goto out;
    }

    rc = kvd_init_exec_fake();
    if(rc) {
        kvd_uninit_commlsm_hook();
        kvd_uninit_sc_hook();
        kvd_hook_exit();
        goto out;
    }

out:
    return rc;
}

/* HOOK优先级:
 * 1. 优先使用lsm-hook: 依据系统决定是使用系统lsm还是kernel-lsm;
 * 2. 其次使用syscall-hook: syscall-hook未被占用, 或强制使用的情况;
 * 3. 最后使用ftrace-hook: syscall-hook被占用且未强制指定syscall-hook的情况;
 * */
int kvd_init_ftrace_commlsm2(const char* sysmaps[],
        size_t size,u_int fh_if_supported, int force_syscall_hook)
{
    int rc = 0;

    rc = kvd_hook_init(sysmaps,size);
    if(rc) { return rc; }

    rc = kvd_init_sc_hook2(fh_if_supported, force_syscall_hook);
    if(rc < 0) {
        kvd_hook_exit();
        goto out;
    }

    rc = kvd_init_commlsm_hook();
    if(rc) {
        kvd_uninit_sc_hook();
        kvd_hook_exit();
        goto out;
    }
    //kvd_enable_commlsm_hook();
    rc = kvd_init_exec_fake();
    if(rc) {
        kvd_uninit_commlsm_hook();
        kvd_uninit_sc_hook();
        kvd_hook_exit();
        goto out;
    }

out:
    return rc;
}

void kvd_uninit_ftrace_commlsm(void)
{
    kvd_uninit_exec_fake();
    kvd_uninit_commlsm_hook();
    kvd_uninit_sc_hook();
    kvd_hook_exit();
}
