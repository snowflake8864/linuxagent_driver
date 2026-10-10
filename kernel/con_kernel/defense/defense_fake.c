#include <linux/types.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/ctype.h>

#include "utils/utils.h"
#include "core/kvd_core.h"
#include "utils/exe_cmdline.h"
#include "khookframe.h"
#include "gnHead.h"
#include "defense_inner.h"

#define DEFENSE_FAKE_NAME "MagicArmor_0"
#define SERVICE_SCRIPT_NAME "MagicArmor_0"

static char _service_script_fake[256] = {0};
static const char _service_script[] = "/etc/init.d/"SERVICE_SCRIPT_NAME;

static int do_defense_fake_check(const char* exec_path,
                        const char *exec_name)
{
    return (!strcmp(exec_name,SERVICE_SCRIPT_NAME) &&
            !strcmp(exec_path,_service_script));
}

static bool is_faked_task(const char* comm)
{
    return (!strcmp(comm,DEFENSE_FAKE_NAME));
}

static bool defense_fake_precheck(struct linux_binprm* bprm,
                const char* exec_path,const char* exec_name)
{
    int rc = 0;
    pid_t ppid = 0;
    bool bfake = false;
    char buf[512] = {0};
    vsec_cmd_argv_t args[2];
    char comm[TASK_COMM_LEN] = {0};

    ppid = vsec_get_ppid(current);

//    DEFENSE_LOG_DEBUG("%s,%s;ppid: %d,argc: %d\n",\
           exec_path,exec_name,ppid,bprm->argc);

    if((ppid != 1) || (bprm->argc != 2) || 
        strcmp(exec_path,_service_script))
    {
        return bfake;
    }

    vsec_get_task_comm(comm,
        sizeof(comm) - 1,current);
    //是不是已经被重定向过
    bfake = !is_faked_task(comm);
    if(!bfake) { return bfake; }

    rc = vsec_get_exe_args(bprm,
        buf,sizeof(buf) - 1,
        args,2);
    if(rc == 2) {
        LOG_DEBUG("check arg: %s,len: %u;%s,len: %u\n",
            args[0].argv,args[0].len,args[1].argv,args[1].len);
        bfake = (!strcmp(args[1].argv,"stop") &&
                !strcmp(args[0].argv,_service_script));
    }

    return bfake;
}

static int defense_fake_check(struct linux_binprm* bprm,
            const char* exec_path,const char* exec_name)
{
    int rc = 0;
    bool bfake = false;
    bfake = defense_fake_precheck(bprm,
                    exec_path,exec_name);
   
    if(bfake) {
        rc = do_defense_fake_check(exec_path,exec_name);
        if(rc) {
            DEFENSE_LOG_DEBUG("fake: %s,%s\n",exec_path,exec_name);
        }
    }

    return rc;
}

static kvd_exec_fake_t defense_exec_fake = {
        .fake = _service_script_fake,
        .fake_check2 = defense_fake_check,
};

extern const char* vsec_get_appcwd(unsigned* len);
static void init_defense_fakes(void)
{
    unsigned len = 0;
    const char* cwd = NULL;

    cwd = vsec_get_appcwd(&len);
    kvd_snprintf(_service_script_fake,
        sizeof(_service_script_fake),"%s/%s",
        cwd,DEFENSE_FAKE_NAME);
}

int defense_exec_fake_init(void)
{
    DEFENSE_LOG_INFO("defense exec fake init\n");

    init_defense_fakes();
    return kvd_register_exec_fake(&defense_exec_fake);
}

void defense_exec_fake_uninit(void)
{
    kvd_unregister_exec_fake(&defense_exec_fake);
}
