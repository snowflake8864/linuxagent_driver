#include <linux/types.h>
#include <linux/version.h>
#include <asm/atomic.h>
#include "gnHead.h"
#include "core/kvd_core.h"
#include "pks_wp.h"

#if defined(CONFIG_ARM64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
#include <linux/kallsyms.h>

    struct pks_wp_data {
        unsigned long addr;
        void * data;
        unsigned long length;
    };

    enum {
        PKS_WP_OP_SET = 1, //替换
        PKS_WP_OP_RESET = 2, //还原
    };

    typedef int (*pks_wp_ctrl_fn_t)(struct pks_wp_data* data,int num,int flag);
    pks_wp_ctrl_fn_t pks_wp_ctrl_fn = NULL;

    void pks_wp_init(void)
    {
        void* fn = NULL;
        const char* fn_name = "modify_mem_data";
        
        fn = (void*)kallsyms_lookup_name(fn_name);
        if(!fn) {
            LOG_INFO("pks_wp_init: not find %s\n",fn_name);
            return;
        }
        
        pks_wp_ctrl_fn = fn;
    }

    void pks_wp_uninit(void)
    {
        pks_wp_ctrl_fn = NULL;
    }

    bool is_pks_wp_enabled(void)
    {
        return (pks_wp_ctrl_fn != NULL);
    }

    //替换
    int pks_wp_set(unsigned long addr,void* data,size_t len)
    {
        struct pks_wp_data wp_data;

        if(!pks_wp_ctrl_fn) { 
            return -ENOTSUPP; 
        }

        wp_data.addr = addr;
        wp_data.data = data;
        wp_data.length = len;

        return pks_wp_ctrl_fn(&wp_data,1,PKS_WP_OP_SET);
    }

    //还原
    int pks_wp_reset(unsigned long addr,void* data,size_t len)
    {
        struct pks_wp_data wp_data;

        if(!pks_wp_ctrl_fn) { 
            return -ENOTSUPP;
        }

        wp_data.addr = addr;
        wp_data.data = data;
        wp_data.length = len;

        return pks_wp_ctrl_fn(&wp_data,1,PKS_WP_OP_RESET);
    }

#else
    void pks_wp_init(void) { return; }
    void pks_wp_uninit(void) {}

    bool is_pks_wp_enabled(void) { return false; }
    //替换
    int pks_wp_set(unsigned long addr,void* data,size_t len)
    { return 0; }
    //还原
    int pks_wp_reset(unsigned long addr,void* data,size_t len)
    { return 0; }
#endif
