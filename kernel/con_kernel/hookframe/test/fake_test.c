#include "khookframe.h"

static int test_fake_check(const char* exec_path,
                        const char* comm)
{
    LOG_INFO("test fake check : %s,comm: %s\n",
            exec_path,comm);
    
    //ls命令进行重向到gedit
    return (strcmp(exec_path,"/usr/bin/ls") == 0);
}

static kvd_exec_fake_t test_fake = {
        .fake = "/usr/bin/gedit",
        .fake_check = test_fake_check,
    };


void init_fake_test(void)
{
    kvd_register_exec_fake(&test_fake);
}

void uninit_fake_test(void)
{
    kvd_unregister_exec_fake(&test_fake);
}
