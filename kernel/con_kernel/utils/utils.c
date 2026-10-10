#include <linux/types.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <linux/netdevice.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h> //fo get_task_struct,put_task_struct
#include <linux/sched/mm.h> //fo get_task_mm,mmput
#endif

#include "core/gnkernel.h"
#include "core/kvd_core.h"
#include "core/kvd_blm.h"
#include "utils.h"
#include "gnHead.h"

#define NULL_BYTE_SIZE 1

////////////////////////////////////////////////////////////////////////////////

//Note: we must hold the lock,before call the function
struct task_struct* get_parent(struct task_struct* tsk)
{
	struct task_struct* parent = NULL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	parent = tsk->real_parent;
#else
    parent = tsk->parent;
#endif
	return parent;
}

int match_task_family(struct task_struct* ts, int root_pid)
{
    pid_t pid;
    int ret = 0;

    rcu_read_lock();

    do {
        pid = PID(ts);
        if (pid == root_pid) {
            ret = 1;
            break;
        }

        ts = get_parent(ts);
    } while(ts != NULL && ts != get_parent(ts) && pid > 2);

    rcu_read_unlock();

    return ret;
}

int match_task_family_locked(struct task_struct* ts, int root_pid)
{
    pid_t pid;
    int ret = 0;

    do {
        pid = PID(ts);
        if (pid == root_pid) {
            ret = 1;
            break;
        }

        ts = get_parent(ts);
    } while(ts != NULL && ts != get_parent(ts) && pid > 2);

    return ret;
}

int match_pid_family(int pid, int root_pid)
{
    int bmatch = 0;
    struct task_struct* task = NULL;

    rcu_read_lock();
    task = kvd_get_task_struct_locked(pid);
    if(task) {
        bmatch = match_task_family_locked(task,root_pid);
    }
    rcu_read_unlock();

    return bmatch;
}

///////////////////////////////////////////////////////////////////////////////
int string_include(const char* s, const char* tmpl)
{
    while (*tmpl) {
        if (*tmpl != *s) {
            return 0;
        }

        tmpl++;
        s++;
    }

    return 1;
}


int string_ment_include(const char* s, const char* tmpl)
{
    int i = strlen(tmpl) - 1;
    s = s + strlen(s) - 1;
    tmpl = tmpl + i;
    while (i >= 0) {
        if (*tmpl != *s) {
            return 0;
        }

        tmpl--;
        s--;
        i--;
    }
    return 1;
}

// 此代码不会修改 tcp_data 指针指向的值
bool get_http_host(unsigned char *tcp_data,size_t tcp_data_len, 
                char **host, int *psize) 
{
    char* start = NULL;
    char* end = NULL;
    size_t len = 0;
    char* data_end = NULL;
    static const char HOST_TITLE[] = "\nHost: ";


    if (tcp_data == NULL || host == NULL )
        return false;

    data_end = tcp_data + tcp_data_len;
    // [:端口号] 表示可能会出现

    //    \n
    //    Host: abc.com[:80]\r\n
    //    Accept: */*\r\n
    //    \r\n
    start = kvd_strnstr(tcp_data,HOST_TITLE,tcp_data_len);

    if (!start) { return false; }
    //    \n
    //    Host: abc.com[:80]
    end = strnchr(start,data_end - start,'\r');
    if(NULL == end) {
        return false;
	}

    //\nHost: abc.com[:80] ==> abc.com[:80]
    start += sizeof(HOST_TITLE) - 1;
    len = end - start;

    // one more character for \0
    *host = (char*) kzalloc(len + NULL_BYTE_SIZE, GFP_ATOMIC);
    if(*host == NULL) { return false; }

    memcpy(*host, start, len);
    // abc.com:80 -> abc.com
    // 处理 Host 值中的端口号
    // 要考虑host为ipv6的情况: [::]:80
    end = strrchr(*host, ']');
    if (end) {
        end += 1;
        if (*end == ':') {
            len = end - *host;
            *end = '\0';
        }
    } else {
        //ipv4 or domain: 1.1.1.1:80 or abc.com:80
        //不能直接strchr(host, ':'), 因为ipv6可能还有此种情况: 1::1
        end = strchr(*host, '.');
        if (end) {
            end = strrchr(*host, ':');
            if (end) {
                len = end - *host;
                *end = '\0';
            }
        }
    }
    if (psize) { *psize = len; }

    return true;
}

//外围调用者保证hex_buf大小足够
size_t hex_str_mac(u_char mac[ETH_ALEN],
                    char* hex_buf)
{
    size_t len = 0;
    size_t size = ETH_ALEN;
    static char hex[] = "0123456789ABCDEF";

    while(size--) {
        if(len > 0) { hex_buf[len++] = ':'; }
        hex_buf[len++] = hex[*mac >> 4];
        hex_buf[len++] = hex[*mac++ & 0xf];
    }

    return len;
}

static const char* http_methods[] = {
    "GET","HEAD","POST","PUT",
    "DELETE","MKCOL","COPY",
    "MOVE","OPTIONS","PROPFIND",
    "PROPPATCH","LOCK","UNLOCK",
    "PATCH",
};

static kvd_blm_hval_t http_methods_blm;

bool is_http_method(const char* method,size_t len)
{
    size_t i = 0;
    bool bhit = false;
    size_t size = ARRAY_SIZE(http_methods);
    char up_method[sizeof("PROPPATCH")] = {0};

    for(i = 0;i < len;i++) 
        up_method[i] = toupper(method[i]);

    //先做一下简单的布隆过滤，这样快
    bhit = kvd_check_blm_hval(up_method,len,
                        &http_methods_blm);
    if(!bhit) { return bhit; }

    for(i = 0;i < size;i++) {
        bhit = (!strncmp(http_methods[i],
                    up_method,len));
        if(bhit) { break; }
    }

    return bhit;
}

bool try_get_http_host(u_char* tcp_data,size_t tcp_data_len,
                        char** phost,int* host_len,int* bhttp)
{
    bool ok = false;
    u_char* p = NULL;
    u_char* p1 = NULL;
    u_char* pend = NULL;
    char method[32] = {0};
	//may be HTTP/1.0 or HTTP/1.1
    static const char http_prefix[] = "HTTP/1.";
	size_t http_prefix_len = sizeof(http_prefix) - 1;

	//may be HTTP/1.0 or HTTP/1.1,including \r\n
    size_t http_flag_len = http_prefix_len + 1 +
						   sizeof("\r\n") - 1;
    size_t min_len = sizeof("GET / ") - 1 + 
                        http_flag_len;
    size_t max_method_len = sizeof("PROPPATCH") - 1;

    if(tcp_data_len <= min_len) { 
        return ok; 
    }

    p = tcp_data;
    pend = tcp_data + max_method_len;
    while(!isspace(*p) && (p < pend)) p++;
    if(p > pend) { 
        return ok; 
    }

    memcpy(method,tcp_data,p - tcp_data);
    ok = is_http_method(method,p - tcp_data);
    if(!ok) { return ok; }

    p++;
    ok = false;
    //不要用字符串查找，此处不是字符串呢!!!
    p1 = memchr(p,'\r',tcp_data_len);
    if(p1 == NULL)  { return ok; }

    pend = tcp_data + tcp_data_len;
    if(p1 >= pend) { return ok; }

    if(*(p1 + 1) != '\n') { return ok; }

    if((p1 - p + 1) <= http_flag_len) {
        return ok;
    }

    p1++; //pointer to \n
	//pointer to HTTP/1.x
	p = p1 - http_flag_len + 1;
	//compare HTTP/1.
    ok = !memcmp(p,http_prefix,
			http_prefix_len);
    if(!ok) { return ok; }
    
	//check HTTP/1.1\r\n or HTTP\1.0\r\n
	ok = ((p1 - p + 1) == http_flag_len); 
	if(!ok) { return ok; }

    //到此处我们就认为是http报文了
    *bhttp = 1;

    // p1++; //保留\n
    ok = false;
    if(p1 >= pend) { return ok; }

    //Note:此处的p1指向的是\nHost: xxxx
    //因为get_http_host需要这种形式
    ok = get_http_host((char*)p1,pend - p1,
                phost,host_len);

    return ok;
}

pid_t vsec_get_ppid(struct task_struct* tsk)
{
    pid_t ppid = 0;
	struct task_struct* parent = NULL;

    rcu_read_lock();
    #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
    	parent = tsk->real_parent;
    #else
        parent = tsk->parent;
    #endif
    if(parent) { ppid = PID(parent); }
    rcu_read_unlock();

	return ppid;
}

char* vsec_get_task_comm(char* buf,size_t buf_size,
                    struct task_struct* task)
{
    struct task_struct* leader = NULL;
    BUG_ON(buf_size < (TASK_COMM_LEN - 1));
    
    leader = task->group_leader;
    task_lock(leader);
    strncpy(buf,leader->comm,buf_size);
	task_unlock(leader);

    return buf;
}

int vsec_get_exec_comm(char comm[TASK_COMM_LEN],
                const char* exe,unsigned exelen)
{
    int len = 0;
    int rc = -EINVAL;
    const char* p = NULL;

    if(!exe || !exelen) {
        return rc;
    }

    p = strrchr(exe,'/');
    if(p) { p++; }
    else { p = exe; }

    len = (exe + exelen) - p;
    if(len >= TASK_COMM_LEN) {
        len = TASK_COMM_LEN - 1;
    }

    strncpy(comm,p,len);
    comm[len] = '\0';

    return len;
}

int vsec_is_kthread(struct task_struct* task)
{
    int bkth = 0;
    struct mm_struct* mm = NULL;

    if(task) {
        mm = get_task_mm(task);
        if(!mm) { bkth = 1; }
        else { mmput(mm); }
    }

    return bkth;
}

int parse_char_sep_data(void* data,size_t data_len,u_char sep,
    int (*cb)(void* item,size_t len,void* ctx),void* ctx)
{
    u_char* p = NULL;
    u_char* pstart = data;
    u_char* pend = pstart + data_len;

    if(!data || (data_len == 0)) {
        return -EINVAL;
    }

    for(p = pstart;p < pend;p++) {
        if(*p != sep) { continue; }

        cb(pstart,p - pstart,ctx);
        pstart = p + 1;
    }

    if(pstart < pend) {
        cb(pstart,pend - pstart,ctx);
    }

    return 0;
}

uint64_t vsec_get_now_nsec(void)
{
	uint64_t nsec = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	struct timespec64 ts;
	ktime_get_ts64(&ts);
#else
	struct timespec ts;
	ktime_get_ts(&ts);
#endif
	
	nsec = ts.tv_sec * 1000000000 + ts.tv_nsec;
	return nsec;
}

uint64_t vsec_get_now_sec(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	struct timespec64 ts;
	ktime_get_ts64(&ts);
#else
	struct timespec ts;
	ktime_get_ts(&ts);
#endif
	
	return ts.tv_sec; 
}

uint64_t vsec_get_seconds(void)
{
    uint64_t ctime = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
    ctime = ktime_get_real_seconds(); 
#else
    ctime = get_seconds(); 
#endif

    return ctime;
}

bool vsec_path_equal(const struct path* path1,
                    const struct path* path2)
{
	return ((path1->mnt == path2->mnt) && 
		(path1->dentry == path2->dentry));
}

void vsec_disable_preempt(void)
{
    preempt_disable();
    barrier();
}

void vsec_enable_preempt(void)
{
    barrier();
    preempt_enable();
}

///dev/loopxxx
bool vsec_is_devloop(const char* name)
{
    bool bdevloop = false;
    const char devloop_flag[] = "/dev/loop";

    if(!name) { return bdevloop; }

    bdevloop = !strncmp(devloop_flag,name,
                sizeof(devloop_flag) - 1);
    if(!bdevloop) { return bdevloop; }

    name = name + sizeof(devloop_flag) - 1;

    while(*name && bdevloop) {
        bdevloop = isalnum(*name);
        name++;
    }

    return bdevloop;
}

void* vsec_kmap_atomic(struct page *page)
{
    void* kaddr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
    kaddr = kmap_atomic(page);
#else
    kaddr = kmap_atomic(page, KM_USER0);
#endif

    return kaddr;
}

void vsec_kunmap_atomic(void* kaddr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
    kunmap_atomic(kaddr);
#else
    kunmap_atomic(kaddr, KM_USER0);
#endif
}

char* get_realpath(const char* pathname,
                unsigned* plen,struct kstat* pst)
{
    int rc = 0;
    struct path path;
    unsigned len = 0;
    char* realpath = ERR_PTR(-ENOENT);
		
    rc = kvd_path_lookup(pathname,0,&path);
    if(rc) { goto out; }

    realpath = kvd_get_pathname(&path,&len);
    if(!IS_ERR(realpath)) {
        *plen = len;
        rc = kvd_vfs_getattr(&path,pst);
    }
    kvd_path_put(&path);

out:
    if(rc) {
        if(!IS_ERR(realpath)) {
            kvd_put_pathname(realpath);
        }
        realpath = ERR_PTR(rc); 
    }
    return realpath; 
}

void vsec_utils_init(void)
{
    kvd_array_blm_hval(http_methods,
            ARRAY_SIZE(http_methods),
            &http_methods_blm);
}

void vsec_utils_uninit(void)
{

}

static int kernel_file_read(const char *path, size_t plen, char **pres, size_t *dlen)
{
    int rc;
    char *buf;
    loff_t pos;
    struct file *fp;
    struct kstat st;
    struct path _path;

    fp = filp_open(path, O_RDONLY, 0400);
    if (KVD_IS_ERR_OR_NULL(fp)) {
        return PTR_ERR(fp);
    }
    do {
        rc = kvd_filp_path(fp, &_path);
        if (rc) break;
        rc = kvd_vfs_getattr(&_path, &st);
        kvd_path_put(&_path);
        if (rc) break;

        buf = vmalloc(plen + st.size + 1);
        if (!buf) {
            rc = -ENOMEM;
            break;
        }
        *pres = buf;
        //前plen为配置文件路径
        memcpy(buf, path, plen);
        buf += plen;
        pos = 0;
        while (pos < st.size) {
            ssize_t n = kvd_kernel_read(fp, buf+pos, st.size-pos, &pos);
            if (n < 0) {
                rc = n;
                break;
            }
            if (n == 0) break;
        }
    } while (0);
    filp_close(fp, NULL);

    if (rc || pos < st.size) {
        buf = *pres;
        *pres = NULL;
        vfree(buf);
    } else {
        *dlen = pos;
        memset(buf+pos, 0, st.size+1-pos);
    }

    return rc;
}

int vsec_file_read(const char *file, size_t flen,
        char **pres, size_t *plen, size_t *dlen)
{
    int ret;
    unsigned len;
    char *pathname;
    struct path path;

    if ((!file || flen == 0) ||
            (!pres || *pres) ||
            (!plen || !dlen)) {
        return -EINVAL;
    }
    if (flen >= KOSEC_PATH_LEN) {
        return -E2BIG;
    }

    ret = kvd_path_lookup(file, 0, &path);
    if (ret) {
        return ret;
    }
    pathname = kvd_get_pathname(&path, &len);
    kvd_path_put(&path);
    if (KVD_IS_ERR_OR_NULL(pathname)) {
        return PTR_ERR(pathname);
    }
    if (len >= KOSEC_PATH_LEN) {
        ret = -E2BIG;
        goto out;
    }
    *plen = len;
    ret = kernel_file_read(pathname, len, pres, dlen);

out:
    kvd_put_pathname(pathname);
    return ret;
}


#if 0
#include <crypto/hash.h>
// 声明一个全局的rwlock
static DEFINE_RWLOCK(md5_rwlock);

// 读取文件并计算 MD5
int md5_calculate_file(const char *filename, char *digest)
{
    struct file *file;
    loff_t pos = 0;
    char *buf;
    ssize_t bytes;
    struct shash_desc *desc;
    struct crypto_shash *tfm;
    int err = 0;

    // 分配MD5加密句柄
    tfm = crypto_alloc_shash("md5", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate MD5 tfm\n");
        return PTR_ERR(tfm);
    }

    // 为shash描述符分配内存
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    // 初始化shash算法
    if (crypto_shash_init(desc)) {
        printk(KERN_ERR "Failed to initialize shash\n");
        kfree(desc);
        crypto_free_shash(tfm);
        return -EIO;
    }

    // 打开文件
    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open file: %s\n", filename);
        kfree(desc);
        crypto_free_shash(tfm);
        return PTR_ERR(file);
    }

    // 分配缓冲区
    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Failed to allocate buffer\n");
        filp_close(file, NULL);
        kfree(desc);
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    // 循环读取文件内容并更新 MD5 值
    while ((bytes = kernel_read(file, buf, PAGE_SIZE, &pos)) > 0) {
        // 加锁计算 MD5
        write_lock(&md5_rwlock);
        err = crypto_shash_update(desc, buf, bytes);
        write_unlock(&md5_rwlock);

        if (err) {
            printk(KERN_ERR "Failed to update MD5\n");
            kfree(buf);
            filp_close(file, NULL);
            kfree(desc);
            crypto_free_shash(tfm);
            return err;
        }
    }

    if (bytes < 0) {
        printk(KERN_ERR "Error reading file: %ld\n", bytes);
        err = bytes;
    } else {
        // 最终计算 MD5
		write_lock(&md5_rwlock); // 加锁用于 MD5 计算的最后一步
		err = crypto_shash_final(desc, digest);
		write_unlock(&md5_rwlock);
        if (err) {
            printk(KERN_ERR "Failed to finalize MD5\n");
        }
    }

    // 释放资源
    kfree(buf);
    filp_close(file, NULL);
    kfree(desc);
    crypto_free_shash(tfm);

    return err;
}
#endif
