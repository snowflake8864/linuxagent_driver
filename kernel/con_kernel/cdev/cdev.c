#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include "utils/utils.h"
#include "core/kvd_memcache.h"
#include "core/kvd_core.h"
#include "notify/client_notify.h"
#include "core/gnkernel.h"

#include "cdev.h"
#include "gnHead.h"


#ifdef OSECXXXX

#define COUNT   1
#define BUFF_SIZE_MAX 256

typedef struct {
    struct list_head lh;
    uint16_t len;
    char data[KOSEC_NEW_DATA_MAX];
} cdev_cache_elem_t;


//memory cache for cdev communication packet data
static struct kmem_cache* cdev_cachep = NULL;

static void* calloc_cdev_cache(unsigned int size)
{
    void* data = ERR_PTR(-EMSGSIZE);

    if(size > sizeof(cdev_cache_elem_t)) {
        return data;
    }

    data = kvd_mem_cache_zalloc(cdev_cachep,
                            GFP_ATOMIC);
    if(!data) { data = ERR_PTR(-ENOMEM); }

    return data;
}

static void free_cdev_cache(void* data)
{
    if(!data || IS_ERR(data)) { return; }
    kvd_mem_cache_free(cdev_cachep,data);
}

static int init_cdev_cache(void)
{
    int rc = -ENOMEM;
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0)
        //4.16以上的内核一定要用这个，不然会直接崩溃
        //因为我们这块内存在在copy_from_user/copy_to_user时使用
		cdev_cachep = kmem_cache_create_usercopy("cdev_cache",
						sizeof(cdev_cache_elem_t),0, 0,
						offsetof(cdev_cache_elem_t,data),
						KOSEC_NEW_DATA_MAX,NULL);
	#else
		cdev_cachep = kvd_mem_cache_create("cdev_cache",
                        sizeof(cdev_cache_elem_t),0);
	#endif
    if(!cdev_cachep) { return rc; }
    rc = 0;

    return rc;
}

static void destroy_cdev_cache(void)
{
    if(cdev_cachep) {
        kvd_mem_cache_destroy(cdev_cachep);
        cdev_cachep = NULL;
    }
}

static void clean_cdev_cache_elems(struct list_head* head)
{
    int count = 0;
    cdev_cache_elem_t* cur = NULL;
    cdev_cache_elem_t* next = NULL;

    list_for_each_entry_safe(cur,next,
                head,lh)
    {
        count++;
        list_del(&cur->lh);
        free_cdev_cache(cur);
    }

    LOG_INFO("clean up cdev cache items,"
        "affect items: %d\n",count);
}

typedef struct  {
    dev_t devid; //用于存放设备号
    struct cdev cdev;
    struct semaphore sem;              /* mutual exclusion semaphore */
    size_t buff_size;
    struct list_head rbuff;          //read buffer
    struct file* filp;

    struct vsec_pack_stats st_in; // from user-space
    struct vsec_pack_stats st_out; // to user-space
    wait_queue_head_t waits;
}vsec_cdev_t;

/*
 * Open and close
 */
static int cdev_open (struct inode *inode, struct file *filp)
{
    int rc = -EINVAL;
	vsec_cdev_t *dev = NULL; /* device information */

    if ( (filp->f_flags & O_ACCMODE) != O_RDWR) {
        return rc;
    }

    rc = -EPERM;
    if(!capable(CAP_SYS_ADMIN)) {
        return rc;
    }

	/*  Find the device */
    rc = -EAGAIN;
	dev = container_of(inode->i_cdev,vsec_cdev_t, cdev);
	if (down_interruptible(&dev->sem))
		return rc;

	if(!dev->filp) {
        rc = 0;
        dev->filp = filp;
    }
	up (&dev->sem);

    if(!rc) { filp->private_data = dev; }

	return rc;
}

static int cdev_release (struct inode *inode, struct file *filp)
{
    int rc = -EINVAL;
	vsec_cdev_t *dev = NULL;
    struct list_head dup_list;
    
    dev = filp->private_data;
    if(!dev) { return rc; }

    INIT_LIST_HEAD(&dup_list);

    rc = 0;
	down(&dev->sem);
    dev->filp = NULL;
    dev->buff_size = 0;
    list_splice_init(&dev->rbuff,&dup_list);
	up(&dev->sem);
    clean_cdev_cache_elems(&dup_list);

    LOG_INFO("cdev fd release\n");

	return rc;
}

extern int dispath_msg(u16 msg_type, void* data,int data_len,u32 portid);

//如有第三个参数，则arg的值为用户进程ioctl调用时传进来的地址
long cdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    vsec_data_t data;
    int rc = -EINVAL;
    cdev_cache_elem_t* elem = NULL;
    void __user* argp = (void __user*)arg;
    vsec_cdev_t* dev = filp->private_data;
    
    
    //如果ioctl命令的类型不是KOSEC_IOC_MAGIC则退出
    if (KOSEC_IOC_MAGIC != _IOC_TYPE(cmd))
        return rc;

    if(cmd != KOSEC_IOC_SETVAL) {
        return rc;
    }

    rc = -EFAULT;
    if(copy_from_user(&data,argp,sizeof(data))) {
        return rc;
    }

    rc = -EMSGSIZE;
    if(data.len > KOSEC_NEW_DATA_MAX) {
        return rc;
    }
    
    rc = -ENOMEM;
    elem = calloc_cdev_cache(data.len);
    if(IS_ERR(elem)) { return rc; }

    rc = -EFAULT;
    if(copy_from_user(elem->data,data.addr,data.len)) {
        free_cdev_cache(elem);
        return rc;
    }

    rc = dispath_msg(data.type,elem->data,data.len,CURRENT_PID);
    free_cdev_cache(elem);
    //成功时,返回实际设置的数据长度: data.len + sizeof(vsec_data_t)
    if(rc == 0) { 
        rc = data.len + sizeof(data);
    }

    if (down_interruptible(&dev->sem) == 0)
    {
        if(rc == 0) { dev->st_in.packets++; }
        else { dev->st_in.drops++; }
        up (&dev->sem);
    }

    return rc;
}

static ssize_t cdev_read(struct file * filp, char __user * buf, size_t count, 
			            loff_t *ppos)
{
    ssize_t rc = -EAGAIN;
    struct list_head* pos = NULL;
    struct list_head* head = NULL;
    cdev_cache_elem_t* elem = NULL;
    vsec_cdev_t* dev = filp->private_data;
    
	if (down_interruptible(&dev->sem))
		return rc;

    head = &dev->rbuff;
	while (list_empty(head)) { /* nothing to read */
		up(&dev->sem); /* release the lock */
		if (filp->f_flags & O_NONBLOCK)
			return rc;
		LOG_DEBUG("\"%s\" reading: going to sleep\n", current->comm);
		if (wait_event_interruptible(dev->waits, (!list_empty(head))))
			return rc; /* signal: tell the fs layer to handle it */
		/* otherwise loop, but first reacquire the lock */
		if (down_interruptible(&dev->sem))
			return rc;
	}

	/* ok, data is there, return something */
    rc = -EFAULT;
    pos = head->next;
    elem = list_entry(pos,cdev_cache_elem_t,lh);
    list_del(&elem->lh);

    count = min(count,(size_t)elem->len);
	if (0 == copy_to_user(buf,elem->data, count)) {
        rc = count;
	}
    dev->buff_size--;
    if(rc > 0) {
        dev->st_out.packets++;
    } else {
        dev->st_out.drops++;
    }
	up (&dev->sem);
    free_cdev_cache(elem);

    return rc;
}

static unsigned int cdev_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
    vsec_cdev_t *dev = filp->private_data;

	down(&dev->sem);
	poll_wait(filp, &dev->waits,wait);
    if(!list_empty(&dev->rbuff)) {
	    mask |= POLLIN | POLLRDNORM;	/* readable */
    }
	up(&dev->sem);
	return mask;
}


struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = cdev_open,
    .read = cdev_read,
    .poll = cdev_poll,
    .release = cdev_release,
    .unlocked_ioctl = cdev_ioctl,
};
static vsec_cdev_t vsec_cdev;

static int setup_chr_dev(vsec_cdev_t* vddev)
{
    int rc = 0;
    dev_t devno;
    struct cdev* pcdev = &vddev->cdev;

    vddev->filp = NULL;
    vddev->buff_size = 0;
    cdev_init(pcdev, &fops);
    sema_init(&vddev->sem,1);
    pcdev->owner = THIS_MODULE;
    INIT_LIST_HEAD(&vddev->rbuff);
    init_waivdueue_head(&vddev->waits);

    devno = MKDEV(MAJOR(vddev->devid),
                    MINOR(vddev->devid));
    rc = cdev_add(pcdev, devno, COUNT);
    if(rc) {
        LOG_ERROR("cdev_add failed,rc: %d\n",rc);
    }

    return rc;
}

static int try_notify_client(cdev_cache_elem_t* elem)
{
    int rc = -EAGAIN;
    vsec_cdev_t* dev = &vsec_cdev;

    if (down_interruptible(&dev->sem)) {
		return rc;
    }

    if(!dev->filp || (dev->buff_size >= BUFF_SIZE_MAX)) {
        up(&dev->sem);
        return rc;
    }

    dev->buff_size++;
    list_add_tail(&elem->lh,&dev->rbuff);
    up(&dev->sem);

    rc = 0;
	wake_up_interruptible(&dev->waits);

    return rc;
}

static int cdev_notify_client(u16 cmd,void* data,u32 nsize)
{
    u16 len = 0;
    int rc = -EMSGSIZE;
    
    cdev_cache_elem_t* elem = NULL;
    struct vsec_msg_data* msg = NULL;

    if(nsize > KOSEC_NEW_DATA_MAX) {
        return rc;
    }
    
    rc = -ENOMEM;
    len = sizeof(*msg) + nsize;
    elem = calloc_cdev_cache(len);
    if(IS_ERR(elem)) { return rc; }

    msg = (struct vsec_msg_data*)(elem->data);
    msg->data_type = cmd;
    msg->data_len = nsize;
    memcpy(msg->data,data,nsize);
    elem->len = len;

    rc = try_notify_client(elem);
    if(rc) { free_cdev_cache(elem); }

    return rc;
}

static client_notifier_t client_notifier = {
    .name = "cdev_notifier",
    .notify = cdev_notify_client,
};

static const char* vd_cdev_name = NULL;

const char* vsec_cdev_name(void)
{
    return vd_cdev_name;
}

int vsec_cdev_init(const char* cdev_name)
{
    int rc = 0;
    rc = init_cdev_cache();
    if(rc) { return rc; }

    rc = alloc_chrdev_region(&vsec_cdev.devid,
                    0,COUNT,cdev_name);
    if (rc) {
        destroy_cdev_cache();
        return rc;
    }
    
    rc = setup_chr_dev(&vsec_cdev);
    if (rc) {
        destroy_cdev_cache();
        unregister_chrdev_region(vsec_cdev.devid,COUNT);
        return rc;
    }

    rc = vsec_register_client_notifier(&client_notifier);
    if(rc) {
        cdev_del(&vsec_cdev.cdev);
        destroy_cdev_cache(); 
        unregister_chrdev_region(vsec_cdev.devid,COUNT);
    }
    vd_cdev_name = cdev_name;
    LOG_INFO("init cdev %s,rc: %d\n",cdev_name,rc);

    return rc;
}

void vsec_cdev_uninit(void)
{
    vsec_unregister_client_notifier(&client_notifier);
    cdev_del(&vsec_cdev.cdev);
    destroy_cdev_cache();
    unregister_chrdev_region(vsec_cdev.devid,COUNT);
    LOG_INFO("uninit cdev\n");
}

int vsec_cdev_get_stats(struct vsec_pack_stats* st_in,
					struct vsec_pack_stats* st_out)
{
	vsec_cdev_t* dev = &vsec_cdev;

    if (down_interruptible(&dev->sem)) {
		return rc;
    }

	*st_in = mmc->st_in;
	*st_out = mmc->st_out;
	up(&dev->sem);

	st_in->packets += st_in->drops;
	st_out->packets += st_out->drops;

	return 0;
}

#else

int vsec_cdev_init(const char* cdev_name)
{ (void)cdev_name; return 0; }

void vsec_cdev_uninit(void)
{}


const char* vsec_cdev_name(void)
{ return NULL; }

int vsec_cdev_get_stats(struct vsec_pack_stats* st_in,
					struct vsec_pack_stats* st_out)
{ return -EINVAL; }

#endif


