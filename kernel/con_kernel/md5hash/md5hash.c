#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <crypto/hash.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/err.h>    // for IS_ERR
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/namei.h>
#include "md5hash.h"
#include "gnHead.h"
#include "core/kvd_memcache.h"

#define MD5_DIGEST_SIZE 16
#define MD5_HASH_NAME "md5"

static spinlock_t shash_desc_lock;
static struct kmem_cache *shash_desc_cache;

int md5_calculate_file(const char *filepath, char *md5_result)
{
    struct file *file;
    struct crypto_shash *md5_tfm;
    struct shash_desc *shash;
    char *buf;
    loff_t offset = 0;
    int bytes, ret = 0;

    file = filp_open(filepath, O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("Failed to open file: %s\n", filepath);
        return PTR_ERR(file);
    }

    buf = vzalloc(PAGE_SIZE);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    md5_tfm = crypto_alloc_shash(MD5_HASH_NAME, 0, 0);
    if (IS_ERR(md5_tfm)) {
        LOG_ERROR("Failed to allocate MD5 transform\n");
        ret = PTR_ERR(md5_tfm);
        goto out_free;
    }

    spin_lock(&shash_desc_lock);
    shash = kmem_cache_alloc(shash_desc_cache, GFP_ATOMIC);
    spin_unlock(&shash_desc_lock);

    if (!shash) {
        ret = -ENOMEM;
        goto out_free_md5;
    }

    shash->tfm = md5_tfm;
    ret = crypto_shash_init(shash);
    if (ret) {
        LOG_ERROR("Failed to initialize MD5 shash\n");
        goto out_free_shash;
    }
   /* Kernel version compatibility for file reading */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    while ((bytes = kernel_read(file, buf, PAGE_SIZE, &offset)) > 0) {
#else
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    while ((bytes = vfs_read(file, buf, PAGE_SIZE, &offset)) > 0) {
#endif
        ret = crypto_shash_update(shash, buf, bytes);
        if (ret) {
            pr_err("Failed to update MD5 hash\n");
            goto out_free_shash;
        }
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    set_fs(old_fs);
#endif

    // 完成 MD5 计算
    ret = crypto_shash_final(shash, md5_result);
    if (ret) {
        LOG_ERROR("Failed to finalize MD5 hash\n");
    }

out_free_shash:
    // 保护内存池释放的操作
    spin_lock(&shash_desc_lock);
    kmem_cache_free(shash_desc_cache, shash);
    spin_unlock(&shash_desc_lock);

out_free_md5:
    crypto_free_shash(md5_tfm);
out_free:
    vfree(buf);
out:
    filp_close(file, NULL);
    return ret;
}

int md5_module_init(void)
{
    spin_lock_init(&shash_desc_lock);

    shash_desc_cache = kvd_mem_cache_create("shash_desc_cache",
                                         sizeof(struct shash_desc) + crypto_shash_descsize(crypto_alloc_shash(MD5_HASH_NAME, 0, 0)),
                                         0);

    if (!shash_desc_cache)
        return -ENOMEM;

    LOG_INFO("File MD5 module loaded with memory pool\n");
    return 0;
}

void md5_module_exit(void)
{
    // 销毁内存池
    if (shash_desc_cache)
        kmem_cache_destroy(shash_desc_cache);

    LOG_INFO("File MD5 module unloaded and memory pool destroyed\n");
}
