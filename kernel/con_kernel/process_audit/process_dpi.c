#include <linux/module.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include "gnHead.h"
#include "process_dpi.h"
#include "dpi_rules.h"
#include "dpi_pattern_tbl.h"
static struct proc_dir_entry *proc_dpi = NULL;
//extern struct proc_dir_entry *proc_osec;
static int dpi_init_finish = 0;

int process_dpi_init(struct proc_dir_entry *proc_osec)
{
    int retv = 0;
    //return retv;
    if((proc_dpi = proc_mkdir("process_dpi", proc_osec)) == NULL)
    {   
        LOG_INFO("dpi: creating proc_fs directory failed.\n");
        retv = -1;
        goto err1;
    }   
    if ((retv = process_pattern_init(proc_dpi)) != 0) {
        LOG_INFO("pattern: creating proc_fs directory failed.\n");
        goto err2;
    }
    if (retv = process_dpi_rules_init(proc_dpi) != 0) {
        LOG_INFO("rules: creating proc_fs directory failed.\n");
        goto err3;
    }

    dpi_init_finish = 1;
    return retv;
err3:
    process_pattern_exit(proc_dpi);
err2:
    remove_proc_entry("process_dpi", proc_osec);
err1:
    return retv;
}

void process_dpi_exit(struct proc_dir_entry *proc_osec)
{
    //return;
    if (dpi_init_finish != 1) {
        return;
    }
    process_dpi_rules_exit(proc_dpi);
    process_pattern_exit(proc_dpi);
    remove_proc_entry("process_dpi", proc_osec);
}
