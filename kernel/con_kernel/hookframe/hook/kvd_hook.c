#include "khookframe.h"
#include "hook_ops.h"
#include "hook_ksyms.h"
#include "kvd_hook.h"
#include "arch/hook_arch.h"
#include "hook/kallsyms.h"
#include "core/kvd_core.h"

int init_system_call_hook(void);
int uinit_system_call_hook(void);

static u_long _wp_disabled = 0;

int kvd_wp_disabled(void)
{
    return test_bit(0, &_wp_disabled);
}

static void wp_disabled_clear(void)
{
    clear_bit(0, &_wp_disabled);
}

static int wp_disabled_modules(const char *data, size_t len)
{
    int i, n;
    char *p, kmod[128] = {0};
    static char *mods[] = {
        //椒图驱动
        "syshook_linux", "secmodel_linux", "resguard_linux",
    };

    n = sscanf(data, "%*x %*c %*s %s", kmod);
    if (n != 1) return 0;

    p = kmod;
    if (kmod[0] == '[') p++;
    n = strlen(p);
    if (p[n-1] == ']') p[n-1] = '\0';

    for (i = 0; i < sizeof(mods)/sizeof(mods[0]); i++) {
        if (strcmp(p, mods[i]) == 0) {
            set_bit(0, &_wp_disabled);
            LOG_INFO("Conflict with an existing driver: %s!!!\n", p);
            return 1;
        }
    }
    return 0;
}

static void wp_disabled_check(void)
{
    int rc = 0, need_check = 0;
    char kallsyms[256] = {0};

    //发现在arm64平台,麒麟服务器系统: 4.19.90-23.8.v2101.ky10.aarch64-20210517
    //存在椒图驱动情况下,操作写保护引起崩溃,针对此情况做检查处理
#if defined(CONFIG_ARM64) && defined(CONFIG_KYLINOS_SERVER)
    need_check = 1;
#endif
    if (!need_check) return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    do {
        unsigned len = 0;
        const char *appcwd;
        appcwd = kvd_get_pwd_pathname(&len);
        if(IS_ERR(appcwd)) { return; }

        kvd_snprintf(kallsyms, sizeof(kallsyms),
                "%s/Data/kallsyms", appcwd);
        kvd_put_pathname(appcwd);
    } while (0);
#else
    strcpy(kallsyms, "/proc/kallsyms");
#endif

    kvd_load_kallsyms(kallsyms, wp_disabled_modules);
}

int kvd_hook_init(const char* sysmaps[],size_t size)
{
    int rc = 0;
    
    rc = init_hook_arch();
    if(rc) { return rc; }

    wp_disabled_check();
	init_syms_opt(sysmaps,size);
    rc = init_system_call_hook();
    if (rc) {
        uninit_hook_arch();
        LOG_INFO("init_system_call_hook error,"
                "because %d \n", rc);
        return rc;
    }


    return rc;
}

void kvd_hook_exit(void)
{   
    uinit_system_call_hook();
	clear_syms_opt();
    wp_disabled_clear();
    uninit_hook_arch();
}
