#include <linux/module.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include "gnHead.h"
#include "dpi.h"
#include "rules.h"
#include "true_process_tbl.h"
#include "pattern_tbl.h"
static struct proc_dir_entry *proc_dpi = NULL;
//extern struct proc_dir_entry *proc_osec;
static int dpi_init_finish = 0;

int dpi_init(struct proc_dir_entry *proc_osec)
{
    int retv = 0;
    if((proc_dpi = proc_mkdir("dpi", proc_osec)) == NULL)
    {   
        LOG_INFO("dpi: creating proc_fs directory failed.\n");
        retv = -1;
        goto err1;
    }   
    if ((retv = pattern_init(proc_dpi)) != 0) {
        LOG_INFO("pattern: creating proc_fs directory failed.\n");
        goto err2;
    }
    if ((retv = dpi_rules_init(proc_dpi)) != 0) {
        LOG_INFO("rules: creating proc_fs directory failed.\n");
        goto err3;
    }
    if ((retv = true_process_init(proc_dpi)) != 0) {
        LOG_INFO("rules: creating proc_fs directory failed.\n");
        goto err4;
    }


    dpi_init_finish = 1;
    return retv;
err4:
    dpi_rules_exit(proc_dpi);
err3:
    pattern_exit(proc_dpi);
err2:
    remove_proc_entry("dpi", proc_osec);
err1:
    return retv;
}

void dpi_exit(struct proc_dir_entry *proc_osec)
{
    if (dpi_init_finish != 1) {
        return;
    }
    true_process_exit(proc_dpi);
    dpi_rules_exit(proc_dpi);
    pattern_exit(proc_dpi);
    remove_proc_entry("dpi", proc_osec);
}
