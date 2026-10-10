#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
 #include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "utils/utils.h"
#include "iptree/ipv4_rules.h"
#include "iptree/ipv6_rules.h"
#include "conn_block_rules.h"

#include "defense/defense_inner.h"
#include "utils/var_proc.h"

struct proc_dir_entry *proc_osec_conn = NULL;
static struct ipv4_rules block_saddr_rt;
static int block_switch = 0;

static int __block_switch_parse(const char *buf, void *info)
{
    if (sscanf(buf, "%d", &block_switch) == 1) {
        if (block_switch >=1) {
           net_block_turn_on();
        } else {
           net_block_turn_off();
        }       
    } 
    return 0;
}

/*  
 * Operations for setting or displaying block gateway.
 */
static int __block_switch_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }
 
    memset(buf, 0, buf_sz);
    snprintf(buf, 1024,  "block_switch: %u\n", block_switch);
    return 0;
}

static struct var_proc_info block_switch_vinfo =
{
    .parse = __block_switch_parse,
    .build = __block_switch_build,
};

int conn_block_init(struct proc_dir_entry *proc_parent)
{
    int retv = 0;
    if((proc_osec_conn = proc_mkdir("osec_conn", proc_parent)) == NULL)
    {   
        printk(KERN_ERR "conn_block: creating proc_fs directory failed.\n");
        return -1;
    }   

    ipv4_rules_init(&block_saddr_rt, "block_saddr_rt", proc_osec_conn);
    ipv6_block_cache_init(proc_osec_conn);
    var_proc_create("block_switch", proc_osec_conn, &block_switch_vinfo);


    return retv;
}

void conn_block_exit(struct proc_dir_entry *proc_parent)
{
    var_proc_remove("block_switch", proc_osec_conn);
    ipv4_rules_purge(&block_saddr_rt);
    ipv6_block_cache_exit(proc_osec_conn);

    remove_proc_entry("osec_conn", proc_parent);
}

bool conn_block_check(__u32 ip)
{
    return  ipv4_rules_check(&block_saddr_rt, ip, NULL);
}

int add_conn_block_rules(__u32 ip)
{
    return ipv4_rules_add_single(&block_saddr_rt, ip);
}

bool conn_block_check_v6(struct in6_addr *ip)
{
    return ipv6_block_cache_lookup(ip);
}

