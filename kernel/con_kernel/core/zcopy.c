#include <linux/module.h>
#include <linux/uio_driver.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>
#include "utils/var_proc.h"
#include "gnHead.h"
#include "zcopy.h"
#include "defense/defense_inner.h"
 
#define DRV_NAME "uio_zcopy"
#define MEM_SIZE 0x1000

int  zero_copy_load_succeed = 0; //   
struct circular_cache {
    void *buffer;
    u16 data_size;
    u32 data_count;
    u32 prev_index;
    u32 index;
	struct mutex lock;
};
//extern struct proc_dir_entry *proc_osec;
struct proc_dir_entry *proc_zcopy = NULL;
int in_netlog_audit_data_count = 1024;
int out_netlog_audit_data_count = 1024;
int openport_audit_data_count = 2048;
int dns_netlog_audit_data_count = 512;
int process_audit_data_count=1024;
int file_audit_data_count = 1024;

module_param(in_netlog_audit_data_count, int,S_IRUSR);
module_param(out_netlog_audit_data_count, int,S_IRUSR);
module_param(openport_audit_data_count, int,S_IRUSR);
module_param(dns_netlog_audit_data_count, int,S_IRUSR);
module_param(process_audit_data_count, int,S_IRUSR);
module_param(file_audit_data_count, int,S_IRUSR);
static struct circular_cache in_netlog_audit_cir_cache;
static struct circular_cache out_netlog_audit_cir_cache;
static struct circular_cache openport_audit_cir_cache;
static struct circular_cache dns_netlog_audit_cir_cache;
static struct circular_cache process_audit_cir_cache;
static struct circular_cache file_audit_cir_cache;
static DEFINE_RWLOCK(in_netlog_audit_locker);
static DEFINE_RWLOCK(out_netlog_audit_locker);
static DEFINE_RWLOCK(openport_audit_locker);
static DEFINE_RWLOCK(dns_netlog_audit_locker);
static DEFINE_RWLOCK(process_audit_locker);
static DEFINE_RWLOCK(file_audit_locker);



//static int drv_zcopy_mmap(struct file *filep, struct vm_area_struct *vma);
static struct uio_info zcopy_uio_info = {
    .name = DRV_NAME,
    .version = "0.1",
    .irq = UIO_IRQ_NONE,
//    .mmap = &drv_zcopy_mmap,
};

static int drv_zcopy_probe(struct platform_device *pdev)
{
    if (zero_copy_load_succeed & IN_NETLOG_AUDIT_ENABLE) {
        in_netlog_audit_cir_cache.data_count = in_netlog_audit_data_count;
        in_netlog_audit_cir_cache.data_size = sizeof(struct osec_network_report);
        in_netlog_audit_cir_cache.prev_index = 0;
        in_netlog_audit_cir_cache.index = 0;

        zcopy_uio_info.mem[0].name = "zcopy_mem0";
        zcopy_uio_info.mem[0].addr = (unsigned long)in_netlog_audit_cir_cache.buffer;
        zcopy_uio_info.mem[0].size = sizeof(struct osec_network_report) * (in_netlog_audit_data_count + out_netlog_audit_data_count);
        zcopy_uio_info.mem[0].memtype = UIO_MEM_LOGICAL;
    }
    if (zero_copy_load_succeed & OUT_NETLOG_AUDIT_ENABLE) {
        out_netlog_audit_cir_cache.data_count = out_netlog_audit_data_count;
        out_netlog_audit_cir_cache.data_size = sizeof(struct osec_network_report);
        out_netlog_audit_cir_cache.prev_index = 0;
        out_netlog_audit_cir_cache.index = 0;
    }
    if (zero_copy_load_succeed & OPENPORT_AUDIT_ENABLE) {
        openport_audit_cir_cache.data_count = openport_audit_data_count;
        openport_audit_cir_cache.data_size = sizeof(struct osec_openport_report);
        openport_audit_cir_cache.prev_index = 0;
        openport_audit_cir_cache.index = 0;
        zcopy_uio_info.mem[1].name = "zcopy_mem1";
        zcopy_uio_info.mem[1].addr = (unsigned long)openport_audit_cir_cache.buffer;
        //zcopy_uio_info.mem[1].internal_addr = zcopy_uio_info.mem[0].addr;
        zcopy_uio_info.mem[1].size = sizeof(struct osec_openport_report) * openport_audit_data_count;
        zcopy_uio_info.mem[1].memtype = UIO_MEM_LOGICAL;
    }
    if (zero_copy_load_succeed & DNS_NETLOG_AUDIT_ENABLE) {
        dns_netlog_audit_cir_cache.data_count = dns_netlog_audit_data_count;
        dns_netlog_audit_cir_cache.data_size = sizeof(struct osec_dns_report);
        dns_netlog_audit_cir_cache.prev_index = 0;
        dns_netlog_audit_cir_cache.index = 0;
        zcopy_uio_info.mem[2].name = "zcopy_mem2";
        zcopy_uio_info.mem[2].addr = (unsigned long)dns_netlog_audit_cir_cache.buffer;
        //zcopy_uio_info.mem[1].internal_addr = zcopy_uio_info.mem[0].addr;
        zcopy_uio_info.mem[2].size = sizeof(struct osec_dns_report) * dns_netlog_audit_data_count;
        zcopy_uio_info.mem[2].memtype = UIO_MEM_LOGICAL;
    }
    if (zero_copy_load_succeed & PROCESS_AUDIT_ENABLE) {
        process_audit_cir_cache.data_count = process_audit_data_count;
        process_audit_cir_cache.data_size = sizeof(struct av_process_info);
        process_audit_cir_cache.prev_index = 0;
        process_audit_cir_cache.index = 0;
        zcopy_uio_info.mem[3].name = "zcopy_mem3";
        zcopy_uio_info.mem[3].addr = (unsigned long)process_audit_cir_cache.buffer;
        //zcopy_uio_info.mem[1].internal_addr = zcopy_uio_info.mem[0].addr;
        zcopy_uio_info.mem[3].size = sizeof(struct av_process_info) * process_audit_data_count;
        zcopy_uio_info.mem[3].memtype = UIO_MEM_LOGICAL;
    }

    if (zero_copy_load_succeed & FILE_AUDIT_ENABLE) {
        file_audit_cir_cache.data_count = file_audit_data_count;
        file_audit_cir_cache.data_size = sizeof(struct av_file_info);
        file_audit_cir_cache.prev_index = 0;
        file_audit_cir_cache.index = 0;
        zcopy_uio_info.mem[4].name = "zcopy_mem4";
        zcopy_uio_info.mem[4].addr = (unsigned long)file_audit_cir_cache.buffer;
        //zcopy_uio_info.mem[1].internal_addr = zcopy_uio_info.mem[0].addr;
        zcopy_uio_info.mem[4].size = sizeof(struct av_file_info) * file_audit_data_count;
        zcopy_uio_info.mem[4].memtype = UIO_MEM_LOGICAL;
    }
    if( uio_register_device(&pdev->dev, &zcopy_uio_info))
        return -ENODEV;

    return 0;
}

static int drv_zcopy_remove(struct platform_device *pdev)
{
#if 0
    if (zcopy_uio_info.mem[0].addr)
        kfree(zcopy_uio_info.mem[0].addr);
    if (zcopy_uio_info.mem[1].addr)
        kfree(zcopy_uio_info.mem[1].addr);
    if (zcopy_uio_info.mem[2].addr)
        kfree(zcopy_uio_info.mem[2].addr);

#endif
	uio_unregister_device(&zcopy_uio_info);
	return 0;
}
#if 0
static int drv_zcopy_mmap(struct file *filep, struct vm_area_struct *vma)
{
    struct uio_mem *mem = NULL;
    LOG_INFO("vma->vm_pgoff=%d\n",vma->vm_pgoff);
    // Determine which mem block to map based on vma->vm_pgoff
    if (vma->vm_pgoff == 0) {
        mem = &zcopy_uio_info.mem[0]; // mem[0] for the first region
    } else if (vma->vm_pgoff == 1) {
        mem = &zcopy_uio_info.mem[1]; // mem[1] for the second region
    } else if (vma->vm_pgoff == 2) {
        mem = &zcopy_uio_info.mem[2]; // mem[2] for the third region
    } else {
        return -EINVAL; // Invalid offset
    }

    LOG_INFO("vma->vm_end - vma->vm_start =%u, mem->size=%u\n",vma->vm_end - vma->vm_start,mem->size );
    // Check if requested size matches the mem block size
    if (vma->vm_end - vma->vm_start != mem->size) {
        return -EINVAL;
    }

    if (remap_pfn_range(vma, vma->vm_start, mem->addr >> PAGE_SHIFT, vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
        return -EAGAIN;
    }

    return 0;
}

#endif

static struct platform_driver zcopy_device_driver = {
    .probe = drv_zcopy_probe,
    .remove = drv_zcopy_remove,
    .driver = {
        .name = DRV_NAME,
    },
};

 
/*
 * Operations for setting or displaying zcopy.
 */
static int __in_netlog_audit_queue_size_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

	sprintf(buf, "%u\n", in_netlog_audit_data_count);
	return 0;
}

static struct var_proc_info in_netlog_audit_queue_size_vinfo =
{
	.build = __in_netlog_audit_queue_size_build,
};

static int __out_netlog_audit_queue_size_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }

	sprintf(buf, "%u\n", out_netlog_audit_data_count);
	return 0;
}

static struct var_proc_info out_netlog_audit_queue_size_vinfo =
{
	.build = __out_netlog_audit_queue_size_build,
};

static int __openport_audit_queue_size_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }
	sprintf(buf, "%u\n", openport_audit_data_count);
	return 0;
}

static struct var_proc_info openport_audit_queue_size_vinfo =
{
	.build = __openport_audit_queue_size_build,
};

static int __dns_netlog_audit_queue_size_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }
	sprintf(buf, "%u\n", dns_netlog_audit_data_count);
	return 0;
}

static struct var_proc_info dns_netlog_audit_queue_size_vinfo =
{
	.build = __dns_netlog_audit_queue_size_build,
};

static int __process_audit_queue_size_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }
	sprintf(buf, "%u\n", process_audit_data_count);
	return 0;
}

static struct var_proc_info process_audit_queue_size_vinfo =
{
	.build = __process_audit_queue_size_build,
};


static int __file_audit_queue_size_build(char *buf, size_t buf_sz, void *info)
{
    if (is_enable_show_proc() == 0) {
        return -EINVAL;
    }
	sprintf(buf, "%u\n", file_audit_data_count);
	return 0;
}

static struct var_proc_info file_audit_queue_size_vinfo =
{
	.build = __file_audit_queue_size_build,
};

static int zcopy_proc_init = 0;
static struct platform_device *uio_zcopy_dev;
int  zcopy_init(const struct proc_dir_entry *base_proc)
{
    int ret = 0;
    zero_copy_load_succeed = 0;
    do {
        in_netlog_audit_cir_cache.buffer = kzalloc( sizeof(struct osec_network_report) * (in_netlog_audit_data_count + out_netlog_audit_data_count), GFP_KERNEL);
        if (in_netlog_audit_cir_cache.buffer) {
            out_netlog_audit_cir_cache.buffer = (struct osec_network_report *)in_netlog_audit_cir_cache.buffer + in_netlog_audit_data_count; 
            zero_copy_load_succeed |= IN_NETLOG_AUDIT_ENABLE;
            zero_copy_load_succeed |= OUT_NETLOG_AUDIT_ENABLE;
            break;
        }
        in_netlog_audit_data_count = in_netlog_audit_data_count/2;
        out_netlog_audit_data_count = out_netlog_audit_data_count/2;
    } while(in_netlog_audit_data_count > 128);
    if (zero_copy_load_succeed & IN_NETLOG_AUDIT_ENABLE) {
        LOG_INFO("zero-copy allocate memory for in netlog audit, count is %d\n",in_netlog_audit_data_count);
    }

    if (zero_copy_load_succeed & OUT_NETLOG_AUDIT_ENABLE) {
        LOG_INFO("zero-copy allocate memory for out netlog audit, count is %d\n",out_netlog_audit_data_count);
    }

    do {
        openport_audit_cir_cache.buffer = kzalloc( sizeof(struct osec_openport_report) * openport_audit_data_count, GFP_KERNEL);
        if (openport_audit_cir_cache.buffer) {
            zero_copy_load_succeed |= OPENPORT_AUDIT_ENABLE;
            break;
        }
        openport_audit_data_count = openport_audit_data_count / 2;
    } while(openport_audit_data_count > 64);

    if (zero_copy_load_succeed & OPENPORT_AUDIT_ENABLE) {
        LOG_INFO("zero-copy allocate memory for open port audit, count is %d\n",openport_audit_data_count);
    }

    do {
        dns_netlog_audit_cir_cache.buffer = kzalloc( sizeof(struct osec_dns_report) * dns_netlog_audit_data_count, GFP_KERNEL);
        if (dns_netlog_audit_cir_cache.buffer) {
            zero_copy_load_succeed |= DNS_NETLOG_AUDIT_ENABLE;
            break;
        }
        dns_netlog_audit_data_count = dns_netlog_audit_data_count / 2;
    } while(dns_netlog_audit_data_count > 64);

    if (zero_copy_load_succeed & DNS_NETLOG_AUDIT_ENABLE) {
        LOG_INFO("zero-copy allocate memory for dns audit, count is %d\n",dns_netlog_audit_data_count);
    }
    do {
        process_audit_cir_cache.buffer = kzalloc( sizeof(struct av_process_info) * process_audit_data_count, GFP_KERNEL);
        if (process_audit_cir_cache.buffer) {
            zero_copy_load_succeed |= PROCESS_AUDIT_ENABLE;
            break;
        }
        process_audit_data_count = process_audit_data_count / 2;
    } while(process_audit_data_count > 32);
    if (zero_copy_load_succeed & PROCESS_AUDIT_ENABLE) {
        LOG_INFO("zero-copy allocate memory for process audit, count is %d\n",process_audit_data_count);
    }
    do {
        file_audit_cir_cache.buffer = kzalloc( sizeof(struct av_file_info) * file_audit_data_count, GFP_KERNEL);
        if (file_audit_cir_cache.buffer) {
            zero_copy_load_succeed |= FILE_AUDIT_ENABLE;
            break;
        }
        file_audit_data_count = file_audit_data_count / 2;
    } while(file_audit_data_count > 32);

    if (zero_copy_load_succeed & FILE_AUDIT_ENABLE) {
        LOG_INFO("zero-copy allocate memory for file audit, count is %d\n",file_audit_data_count);
    }
    if (unlikely(zero_copy_load_succeed == 0)) {
        return 0;
    }

    if((proc_zcopy = proc_mkdir("zcopy", base_proc)) == NULL)
    {   
        printk(KERN_ERR "zcopy: creating proc_fs directory failed.\n");
    } else {
        LOG_INFO("creating zcopy proc_fs directory success\n");
        if (zero_copy_load_succeed & IN_NETLOG_AUDIT_ENABLE) {
            var_proc_create("in_netlog_audit_queue_size", proc_zcopy, &in_netlog_audit_queue_size_vinfo);	
        }
        if (zero_copy_load_succeed & OUT_NETLOG_AUDIT_ENABLE) {
	        var_proc_create("out_netlog_audit_queue_size", proc_zcopy, &out_netlog_audit_queue_size_vinfo);	
        }
        if (zero_copy_load_succeed & OPENPORT_AUDIT_ENABLE) {
            var_proc_create("openport_audit_queue_size", proc_zcopy, &openport_audit_queue_size_vinfo);	
        }
        if (zero_copy_load_succeed & DNS_NETLOG_AUDIT_ENABLE) {
            var_proc_create("dns_netlog_audit_queue_size", proc_zcopy, &dns_netlog_audit_queue_size_vinfo);	
        }
        if (zero_copy_load_succeed & PROCESS_AUDIT_ENABLE) {
            var_proc_create("process_audit_queue_size", proc_zcopy, &process_audit_queue_size_vinfo);	
        }
        if (zero_copy_load_succeed & FILE_AUDIT_ENABLE) {
            var_proc_create("file_audit_queue_size", proc_zcopy, &file_audit_queue_size_vinfo);	
        }
        zcopy_proc_init = 1;
    }

    uio_zcopy_dev = platform_device_register_simple(DRV_NAME, -1, NULL, 0);
    return platform_driver_register(&zcopy_device_driver);
}
 
void zcopy_exit(const struct proc_dir_entry *base_proc)
{
	if (uio_zcopy_dev) {
		platform_device_unregister(uio_zcopy_dev);
        platform_driver_unregister(&zcopy_device_driver);

	}
    if (zcopy_proc_init == 1) {

        if (zero_copy_load_succeed & IN_NETLOG_AUDIT_ENABLE) {
	        var_proc_remove("in_netlog_audit_queue_size", proc_zcopy);	
        }
        if (zero_copy_load_succeed & OUT_NETLOG_AUDIT_ENABLE) {
	        var_proc_remove("out_netlog_audit_queue_size", proc_zcopy);	
        }
        if (zero_copy_load_succeed & OPENPORT_AUDIT_ENABLE) {
	        var_proc_remove("openport_audit_queue_size", proc_zcopy);	
        }
        if (zero_copy_load_succeed & DNS_NETLOG_AUDIT_ENABLE) {
	        var_proc_remove("dns_netlog_audit_queue_size", proc_zcopy);	
        }
        if (zero_copy_load_succeed & PROCESS_AUDIT_ENABLE) {
	        var_proc_remove("process_audit_queue_size", proc_zcopy);	
        }
        if (zero_copy_load_succeed & FILE_AUDIT_ENABLE) {
	        var_proc_remove("file_audit_queue_size", proc_zcopy);	
        }
        if (likely(zero_copy_load_succeed != 0)) {
            remove_proc_entry("zcopy", base_proc);
        }
    }
    if (out_netlog_audit_cir_cache.buffer) {
        //kfree(out_netlog_audit_cir_cache.buffer);
        out_netlog_audit_cir_cache.buffer = NULL;
    }
    if (in_netlog_audit_cir_cache.buffer) {
        kfree(in_netlog_audit_cir_cache.buffer);
        in_netlog_audit_cir_cache.buffer = NULL;
    }
    if (openport_audit_cir_cache.buffer) {
        kfree(openport_audit_cir_cache.buffer);
        openport_audit_cir_cache.buffer = NULL;
    }
    if (dns_netlog_audit_cir_cache.buffer) {
        kfree(dns_netlog_audit_cir_cache.buffer);
        dns_netlog_audit_cir_cache.buffer = NULL;
    }
    if (process_audit_cir_cache.buffer) {
        kfree(process_audit_cir_cache.buffer);
        process_audit_cir_cache.buffer = NULL;
    }
    if (file_audit_cir_cache.buffer) {
        kfree(file_audit_cir_cache.buffer);
        file_audit_cir_cache.buffer = NULL;
    }
    LOG_INFO("zcopy_exit\n");
}
uint32_t get_in_netlog_audit_data(struct osec_network_report ** info)
{

	uint32_t idx = 0;
    unsigned long flags;
    write_lock_irqsave(&in_netlog_audit_locker,flags);
	idx = in_netlog_audit_cir_cache.index ++;
    idx %=in_netlog_audit_cir_cache.data_count;
	//*info = (struct osec_network_report *)in_netlog_audit_cir_cache.buffer + idx;
	*info = (struct osec_network_report *)zcopy_uio_info.mem[0].addr + idx;
    write_unlock_irqrestore(&in_netlog_audit_locker,flags);
	return idx;
}

uint32_t get_in_netlog_audit_idx(uint32_t *prev_idx, uint32_t *idx)
{
    uint32_t loopback = 0;
    unsigned long flags;
    write_lock_irqsave(&in_netlog_audit_locker,flags);
	*idx = in_netlog_audit_cir_cache.index % in_netlog_audit_cir_cache.data_count;
	*prev_idx = in_netlog_audit_cir_cache.prev_index % in_netlog_audit_cir_cache.data_count;
    if (likely(*idx > *prev_idx)) {
        in_netlog_audit_cir_cache.prev_index = in_netlog_audit_cir_cache.index;
    } else if (unlikely(*idx < *prev_idx)) {
        in_netlog_audit_cir_cache.prev_index = in_netlog_audit_cir_cache.index;
        loopback = in_netlog_audit_cir_cache.data_count;
    }
    write_unlock_irqrestore(&in_netlog_audit_locker,flags);
    return loopback;
}


uint32_t get_out_netlog_audit_data(struct osec_network_report ** info)
{

	uint32_t idx = 0;
    unsigned long flags;
    write_lock_irqsave(&out_netlog_audit_locker,flags);
	idx = out_netlog_audit_cir_cache.index ++;
    idx %=out_netlog_audit_cir_cache.data_count;
	*info = (struct osec_network_report *)zcopy_uio_info.mem[0].addr + in_netlog_audit_data_count + idx;
    write_unlock_irqrestore(&out_netlog_audit_locker,flags);
	return idx;
}

uint32_t get_out_netlog_audit_idx(uint32_t *prev_idx, uint32_t *idx)
{
    uint32_t loopback = 0;
    unsigned long flags;
    write_lock_irqsave(&out_netlog_audit_locker,flags);
    *idx = out_netlog_audit_cir_cache.index % out_netlog_audit_cir_cache.data_count;
    *prev_idx = out_netlog_audit_cir_cache.prev_index % out_netlog_audit_cir_cache.data_count;
    if (likely(*idx > *prev_idx)) {
        out_netlog_audit_cir_cache.prev_index = out_netlog_audit_cir_cache.index;
    } else if (unlikely(*idx < *prev_idx)){
        out_netlog_audit_cir_cache.prev_index = out_netlog_audit_cir_cache.index;
        loopback = out_netlog_audit_cir_cache.data_count;
    }
    write_unlock_irqrestore(&out_netlog_audit_locker,flags);
    return loopback;
}


uint32_t get_openport_audit_data(struct osec_openport_report ** info)
{

	uint32_t idx = 0;
    unsigned long flags;
    write_lock_irqsave(&openport_audit_locker,flags);
	idx = openport_audit_cir_cache.index ++;
    idx %=openport_audit_cir_cache.data_count;
	//*info = (struct osec_openport_report *)openport_audit_cir_cache.buffer + idx;
	*info = (struct osec_openport_report *)zcopy_uio_info.mem[1].addr + idx;
    write_unlock_irqrestore(&openport_audit_locker,flags);
	return idx;
}

uint32_t get_openport_audit_idx(uint32_t *prev_idx, uint32_t *idx)
{
    uint32_t loopback = 0;
    unsigned long flags;
    write_lock_irqsave(&openport_audit_locker,flags);
    *idx = openport_audit_cir_cache.index %openport_audit_cir_cache.data_count;
    *prev_idx = openport_audit_cir_cache.prev_index %openport_audit_cir_cache.data_count;
    if (likely(*idx > *prev_idx)) {
        openport_audit_cir_cache.prev_index = openport_audit_cir_cache.index;
    } else if (unlikely(*idx < *prev_idx)) {
        openport_audit_cir_cache.prev_index = openport_audit_cir_cache.index;
        loopback = openport_audit_cir_cache.data_count;
    }
    write_unlock_irqrestore(&openport_audit_locker,flags);
    return loopback;
}

//==
uint32_t get_dns_netlog_audit_data(struct osec_dns_report ** info)
{

	uint32_t idx = 0;
    unsigned long flags;
    write_lock_irqsave(&dns_netlog_audit_locker,flags);
	idx = dns_netlog_audit_cir_cache.index ++;
    idx %=dns_netlog_audit_cir_cache.data_count;
	//*info = (struct osec_openport_report *)openport_audit_cir_cache.buffer + idx;
	*info = (struct osec_dns_report *)zcopy_uio_info.mem[2].addr + idx;
    write_unlock_irqrestore(&dns_netlog_audit_locker,flags);
	return idx;
}

uint32_t get_dns_netlog_audit_idx(uint32_t *prev_idx, uint32_t *idx)
{

    uint32_t loopback = 0;
    unsigned long flags;
    write_lock_irqsave(&dns_netlog_audit_locker,flags);
    *idx = dns_netlog_audit_cir_cache.index %dns_netlog_audit_cir_cache.data_count;
    *prev_idx = dns_netlog_audit_cir_cache.prev_index %dns_netlog_audit_cir_cache.data_count;
    if (likely(*idx > *prev_idx)) {
        dns_netlog_audit_cir_cache.prev_index = dns_netlog_audit_cir_cache.index;
    } else if (unlikely(*idx < *prev_idx)) {
        dns_netlog_audit_cir_cache.prev_index = dns_netlog_audit_cir_cache.index;
        loopback = dns_netlog_audit_cir_cache.data_count;
    }

    write_unlock_irqrestore(&dns_netlog_audit_locker,flags);
    return loopback;
}

//==
uint32_t get_process_audit_data(struct av_process_info ** info)
{

	uint32_t idx = 0;
    unsigned long flags;
    write_lock_irqsave(&process_audit_locker,flags);
	idx = process_audit_cir_cache.index ++;
    idx %=process_audit_cir_cache.data_count;
	//*info = (struct osec_openport_report *)openport_audit_cir_cache.buffer + idx;
	*info = (struct av_process_info *)zcopy_uio_info.mem[3].addr + idx;
    write_unlock_irqrestore(&process_audit_locker,flags);
	return idx;
}

uint32_t get_process_audit_idx(uint32_t *prev_idx, uint32_t *idx)
{

    uint32_t loopback = 0;
    unsigned long flags;
    write_lock_irqsave(&process_audit_locker,flags);
    *idx = process_audit_cir_cache.index %process_audit_cir_cache.data_count;
    *prev_idx = process_audit_cir_cache.prev_index %process_audit_cir_cache.data_count;
    if (likely(*idx > *prev_idx)) {
        process_audit_cir_cache.prev_index = process_audit_cir_cache.index;
    } else if (unlikely(*idx < *prev_idx)) {
        process_audit_cir_cache.prev_index = process_audit_cir_cache.index;
        loopback = process_audit_cir_cache.data_count;
    }

    write_unlock_irqrestore(&process_audit_locker,flags);
    return loopback;
}


uint32_t get_file_audit_data(struct av_file_info ** info)
{

	uint32_t idx = 0;
    unsigned long flags;
    write_lock_irqsave(&file_audit_locker,flags);
	idx = file_audit_cir_cache.index ++;
    idx %=file_audit_cir_cache.data_count;
	//*info = (struct osec_openport_report *)openport_audit_cir_cache.buffer + idx;
	*info = (struct av_file_info *)zcopy_uio_info.mem[4].addr + idx;
    write_unlock_irqrestore(&file_audit_locker,flags);
	return idx;
}

uint32_t get_file_audit_idx(uint32_t *prev_idx, uint32_t *idx)
{

    uint32_t loopback = 0;
    unsigned long flags;
    write_lock_irqsave(&file_audit_locker,flags);
    *idx = file_audit_cir_cache.index %file_audit_cir_cache.data_count;
    *prev_idx = file_audit_cir_cache.prev_index %file_audit_cir_cache.data_count;
    if (likely(*idx > *prev_idx)) {
        file_audit_cir_cache.prev_index = file_audit_cir_cache.index;
    } else if (unlikely(*idx < *prev_idx)) {
        file_audit_cir_cache.prev_index = file_audit_cir_cache.index;
        loopback = file_audit_cir_cache.data_count;
    }

    write_unlock_irqrestore(&file_audit_locker,flags);
    return loopback;
}

