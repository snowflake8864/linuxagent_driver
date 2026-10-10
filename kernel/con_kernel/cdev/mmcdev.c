#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <asm/shmparam.h>
#include <asm/cacheflush.h>
#include "core/kvd_core.h"
#include "utils/utils.h"
#include "notify/client_notify.h"
#include "gnHead.h"
#include "mmcdev.h"

static spinlock_t _mmc_lock;
static vsec_mmc_t* _vsec_mmc = NULL;

static int vsec_mmc_set_ring(vsec_mmc_t* mmc,
      		struct vsec_mmc_req *req,int closing);

static int vsec_mmc_set(vsec_mmc_t* new_mmc)
{
	u_long flags;
	int rc = -EAGAIN;

	spin_lock_irqsave(&_mmc_lock,flags);
	if(_vsec_mmc == NULL) {
		rc = 0;
		atomic_inc(&new_mmc->ref);
		_vsec_mmc = new_mmc;
	}
	spin_unlock_irqrestore(&_mmc_lock,flags);

	return rc;
}

static vsec_mmc_t* vsec_mmc_get(void)
{
	u_long flags;
	vsec_mmc_t* mmc = NULL;

	spin_lock_irqsave(&_mmc_lock,flags);
	if(_vsec_mmc && atomic_inc_not_zero(&_vsec_mmc->ref)) {
		mmc = _vsec_mmc;
	}
	spin_unlock_irqrestore(&_mmc_lock,flags);

	return mmc;
}

static void vsec_mmc_put(vsec_mmc_t* mmc)
{
	u_long flags;
	vsec_mmc_t* tmp_free = NULL;
	
	spin_lock_irqsave(&_mmc_lock,flags);
	if (atomic_dec_and_test(&mmc->ref)) {
		(void)cmpxchg(&_vsec_mmc,mmc,NULL);
		tmp_free = mmc;
	}
	spin_unlock_irqrestore(&_mmc_lock,flags);

	if(tmp_free) {
		struct vsec_mmc_req req;
		memset(&req, 0,sizeof(req));
		vsec_mmc_set_ring(tmp_free,&req,1);
		kfree(tmp_free);

		LOG_INFO("free mmc: %p\n",tmp_free);
	}
}

static ssize_t vd_mm_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	return -EOPNOTSUPP;
}

static void mmc_stats_in(vsec_mmc_t* mmc,bool ok)
{
	spin_lock_bh(&mmc->lock);
	if(ok) {
		mmc->st_in.packets++;
	} else {
		mmc->st_in.drops++;
	}
	spin_unlock_bh(&mmc->lock);
}

extern int dispath_msg(u16 msg_type, void* data,int data_len,u32 portid);
static ssize_t vd_mm_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	if(count > 0) {
		int rc = 0;
		vsec_data_t data;
		void* pack = NULL;
		vsec_mmc_t* mmc = NULL;

		if(count != sizeof(data)) {
			return -EINVAL;
		}

		mmc = file->private_data;
		if(!mmc) { return -EFAULT; }

		memset(&data,0,sizeof(data));
		if(copy_from_user(&data,buf,count)) {
			return -EFAULT;
		}

		if((data.addr == NULL) || (data.len == 0)) { 
			return -EFAULT; 
		}

		pack = vmalloc(data.len);
		if(!pack) {return -ENOMEM; }
		if(copy_from_user(pack,data.addr,data.len)) {
			vfree(pack);
			return -EFAULT;
		}

		rc = dispath_msg(data.type,pack,data.len,CURRENT_PID);
		vfree(pack);
	  	//成功时,返回实际设置的数据长度: data.len + sizeof(vsec_data_t)
    	if(rc == 0) { count = data.len + sizeof(data); }
		mmc_stats_in(mmc,(rc == 0));
	}

	return count;
}

/* ************************************* */
static inline struct page *pg_vec_endpage(char *one_pg_vec, unsigned int order)
{
	return virt_to_page(one_pg_vec + (PAGE_SIZE << order) - 1);
}

static void free_pg_vec(char **pg_vec, unsigned int order, unsigned int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (likely(pg_vec[i]))
			free_pages((unsigned long) pg_vec[i], order);
	}
	kfree(pg_vec);
}

static inline char *alloc_one_pg_vec_page(unsigned long order)
{
	return (char *) __get_free_pages(GFP_KERNEL | __GFP_COMP | __GFP_ZERO,
					 order);
}

static char **alloc_pg_vec(struct vsec_mmc_req *req, int order)
{
	int i = 0;
	char **pg_vec = NULL;
	unsigned int block_nr = req->block_nr;

	pg_vec = kzalloc(block_nr * sizeof(char*), GFP_KERNEL);
	if (unlikely(!pg_vec))
		goto out;

	for (i = 0; i < block_nr; i++) {
		pg_vec[i] = alloc_one_pg_vec_page(order);
		if (unlikely(!pg_vec[i]))
			goto out_free_pgvec;
	}

out:
	return pg_vec;

out_free_pgvec:
	free_pg_vec(pg_vec, order, block_nr);
	pg_vec = NULL;
	goto out;
}

int vsec_mmc_set_ring(vsec_mmc_t* mmc,
      	struct vsec_mmc_req *req,int closing)
{
	int err = 0;
	int order = 0;
	int bmapped = 0;
	char** pg_vec = NULL;
	
	if(!mmc) { return -EINVAL; }

	if (req->block_nr) {
		int i, l;

		/* Sanity tests and some calculations */

		if (unlikely(mmc->pg_vec))
			return -EBUSY;

		if (unlikely((int)req->block_size <= 0))
			return -EINVAL;
		if (unlikely(req->block_size & (PAGE_SIZE - 1)))
			return -EINVAL;
		if (unlikely(req->frame_size < KOSEC_MMC_HDRLEN))
			return -EINVAL;
		if (unlikely(req->frame_size & (KOSEC_MMC_ALIGNMENT - 1)))
			return -EINVAL;

		mmc->frames_per_block = req->block_size/req->frame_size;
		if (unlikely(mmc->frames_per_block <= 0))
			return -EINVAL;
		if (unlikely((mmc->frames_per_block * req->block_nr) !=
			     req->frame_nr))
			return -EINVAL;

		err = -ENOMEM;
		order = get_order(req->block_size);
		pg_vec = alloc_pg_vec(req, order);
		if (unlikely(!pg_vec))
			goto out;

		l = 0;
		for (i = 0; i < req->block_nr; i++) {
			char *ptr = pg_vec[i];
			struct vsec_mmc_hdr *header;
			int k;

			for (k = 0; k < mmc->frames_per_block; k++) {
				header = (struct vsec_mmc_hdr *) ptr;
				header->status = KOSEC_MMC_ST_KERN;
				ptr += req->frame_size;
			}
		}
		/* Done */
	} else {
		if (unlikely(req->frame_nr))
			return -EINVAL;
	}

	err = -EBUSY;
	mutex_lock(&mmc->pg_vec_lock);
	if (closing || atomic_read(&mmc->ref) == 0) {
		err = 0;

		spin_lock_bh(&mmc->lock);
		pg_vec = xchg(&mmc->pg_vec, pg_vec);
		mmc->frame_max = (req->frame_nr - 1);
		mmc->head = 0;
		mmc->frame_size = req->frame_size;
		spin_unlock_bh(&mmc->lock);

		order = xchg(&mmc->pg_vec_order, order);
		req->block_nr = xchg(&mmc->pg_vec_len, req->block_nr);

		mmc->pg_vec_pages = req->block_size/PAGE_SIZE;
		
		bmapped = atomic_read(&mmc->ref);
	}
	mutex_unlock(&mmc->pg_vec_lock);

	if (pg_vec)
		free_pg_vec(pg_vec, order, req->block_nr);

	//just for case
	WARN_ON(bmapped > 0);

out:
	return err;
}


static long vd_mm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rc = -EINVAL;
	vsec_mmc_t* mmc = NULL;
	void __user* argp = (void __user*)arg;
    
    //如果ioctl命令的类型不是KOSEC_IOC_MAGIC则退出
	if (KOSEC_IOC_MAGIC != _IOC_TYPE(cmd))
        return rc;

	if(!file) { return rc; }

	mmc = file->private_data;
	if(!mmc) { return rc; }

	switch(cmd) {
	case KOSEC_IOC_SETRING:
	{
		struct vsec_mmc_req req;
    	rc = -EFAULT;
		if(copy_from_user(&req,argp,sizeof(req))) {
			return rc;
		}

		rc = vsec_mmc_set_ring(mmc,&req,0);
	}
	break;
	default:
	break;
	}

	return rc;
}

/* Dirty? Well, I still did not learn better way to account
 * for user mmaps.
 */
static int vd_mm_mmap(struct file* file,struct vm_area_struct* vma)
{
	int i = 0;
	int err = -EINVAL;
	unsigned long size;
	unsigned long start;
	u_long total_pg_size = 0;
	vsec_mmc_t* mmc = file->private_data;

	if (vma->vm_pgoff)
		return -EINVAL;

	size = vma->vm_end - vma->vm_start;

	mutex_lock(&mmc->pg_vec_lock);
	if (mmc->pg_vec == NULL)
		goto out;
	
	total_pg_size = mmc->pg_vec_len * 
					mmc->pg_vec_pages * 
					PAGE_SIZE;
	if (size != total_pg_size)
		goto out;

	start = vma->vm_start;
	for (i = 0; i < mmc->pg_vec_len; i++) {
		struct page *page = virt_to_page(mmc->pg_vec[i]);
		int pg_num;

		for (pg_num = 0; pg_num < mmc->pg_vec_pages; pg_num++, page++) {
			err = vm_insert_page(vma, start, page);
			if (unlikely(err))
				goto out;
			start += PAGE_SIZE;
		}
	}
	err = vsec_mmc_set(mmc);
	if(err) {
		LOG_INFO(KERN_ERR "someone has open it");
		goto out;
	}

	err = 0;

out:
	mutex_unlock(&mmc->pg_vec_lock);

	return err;
}

static int vd_mm_open(struct inode *inode, struct file *file)
{
	vsec_mmc_t* mmc = NULL;
	
	mmc = kzalloc(sizeof(*mmc),GFP_KERNEL);
	if(!mmc) { return -ENOMEM; }

	mutex_init(&mmc->pg_vec_lock);
	spin_lock_init(&mmc->lock);
	init_waitqueue_head(&mmc->waits);
	atomic_set(&mmc->ref,0);
	
	//保存原始的private_data;
	mmc->priv = file->private_data;
	//替换private_data
	file->private_data = mmc;

	return 0;
}

static int vd_mm_release(struct inode *inode, struct file *file)
{
	vsec_mmc_t* mmc = file->private_data;

	if(mmc) {
		file->private_data = mmc->priv;
		vsec_mmc_put(mmc);
	}

	return 0;
}

static inline char* mmc_lookup_frame(vsec_mmc_t* mmc,
                              unsigned int position)
{
	char *frame;
	unsigned int pg_vec_pos, frame_offset;

	pg_vec_pos = position / mmc->frames_per_block;
	frame_offset = position % mmc->frames_per_block;

	frame = mmc->pg_vec[pg_vec_pos] + 
				(frame_offset * mmc->frame_size);
	
	return frame;
}

static int mmc_data_ready(vsec_mmc_t* mmc)
{
	wake_up_interruptible(&mmc->waits);
	return 0;
}

static unsigned int vd_mm_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
    vsec_mmc_t* mmc = filp->private_data;

	if(!mmc) { return mask; }

	//这里mmc不会被释放，不用担心
	poll_wait(filp,&mmc->waits,wait);

	spin_lock_bh(&mmc->lock);
	if (mmc->pg_vec) {
		unsigned last;
		struct vsec_mmc_hdr* h = NULL;

		last = mmc->head ? mmc->head - 1 : mmc->frame_max;
		h = (struct vsec_mmc_hdr*)mmc_lookup_frame(mmc, last);
		if (h->status) {
			mask |= POLLIN | POLLRDNORM;
		}
	}
	spin_unlock_bh(&mmc->lock);

	return mask;
}

static const struct file_operations vd_mm_fops = {
	.owner		= THIS_MODULE,
	.read		= vd_mm_read,
	.write		= vd_mm_write,
	.unlocked_ioctl	= vd_mm_ioctl,
	.mmap		= vd_mm_mmap,
	.open		= vd_mm_open,
	.release	= vd_mm_release,
	.poll 		= vd_mm_poll,
	.llseek		= no_llseek,
};

//当没有定义flush dcache对应的宏时，我们将其定义成1
//因为在低版本内核上一定没有这个宏，但很多flush dcache的功能是开启的
//所以我们才将其定义为1,以防止在低版本内核上出现未刷新dcache的情况
#ifndef ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE
#define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 1
#endif

//先获取frame,后续再填充实际数据
static struct vsec_mmc_hdr* get_valid_frame(u_int len,
										vsec_mmc_t* mmc)
{
	struct vsec_mmc_hdr* h = NULL;

	do {
		spin_lock(&mmc->lock);
		if(mmc->frame_size < (len + KOSEC_MMC_HDRLEN)) {
			spin_unlock(&mmc->lock);
			h = ERR_PTR(-EMSGSIZE);
			break;
		}

		h = (struct vsec_mmc_hdr *)mmc_lookup_frame(mmc,mmc->head);
		if (h->status) {
			spin_unlock(&mmc->lock);
			//缓冲区满了，用户态接收太慢???
			h = ERR_PTR(-ENOBUFS);
			break;
		}

		if(mmc->head != mmc->frame_max) {
			mmc->head += 1;
		} else {
			mmc->head = 0;
		}
		mmc->st_out.packets++;
		spin_unlock(&mmc->lock);
	} while(0);

	return h;
}

static void fill_flush_frame(u16 cmd,void* data,u32 nsize,
						struct vsec_mmc_hdr* h)
{
	struct vsec_msg_data* msg = NULL;
	unsigned hlen = KOSEC_MMC_HDRLEN;
	unsigned long status = KOSEC_MMC_ST_USER;

	//这里其实还有一次copy操作
	msg = (struct vsec_msg_data*)((u8*)h + hlen);
	msg->data_type = cmd;
    msg->data_len = nsize;
    memcpy(msg->data,data,nsize);

	h->snaplen = sizeof(*msg) + nsize;

	/*Note:
	*先将具体的数据给刷新到用户态，然后再修改状态标识(status)
	*
	*下面这样判断是为了效率,因为在flush_dcache_page功能不支持的情况下:
	*下面的代码逻辑其是是没有执行任何有意义的操作，只是做了一个无用的循环
	*/
	smp_mb();
#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE == 1
	{
		struct page *p_start, *p_end;
		u8 *h_end = (u8 *)PAGE_ALIGN((u_long)h + 
							hlen + h->snaplen - 1);

		p_start = virt_to_page(h);
		p_end = virt_to_page(h_end);
		while (p_start <= p_end) {
			flush_dcache_page(p_start);
			p_start++;
		}
	}

	smp_wmb();
#endif

	//此处再修改状态标识
	h->status = status;
	//将状态标识刷新到用户态
	flush_dcache_page(virt_to_page(&h->status));
}

static int mmc_notify_client(u16 cmd,void* data,u32 nsize)
{
	u_int msglen = 0;
	int ring_err = 0;
	vsec_mmc_t* mmc = NULL;
	struct vsec_mmc_hdr* frame = NULL;

	mmc = vsec_mmc_get();
	if(mmc == NULL) {
		return -EINVAL;
	}

	msglen = sizeof(struct vsec_msg_data) + nsize;
	frame = get_valid_frame(msglen,mmc);
	if(IS_ERR(frame)) {
		ring_err = PTR_ERR(frame);
		goto pack_drop;
	}

	//填充数据
	fill_flush_frame(cmd,data,nsize,frame);
	//通知用户态获取数据
	mmc_data_ready(mmc);

	vsec_mmc_put(mmc);
	return 0;

pack_drop:
	spin_unlock(&mmc->lock);
	mmc->st_out.drops++;
	spin_unlock(&mmc->lock);

	mmc_data_ready(mmc);
	vsec_mmc_put(mmc);

	return ring_err;
}

static client_notifier_t mmc_cn = {
    .name = "vdmmc",
    .notify = mmc_notify_client,
};

/*
 * No locking needed - only used (and modified) by below initcall and exitcall.
 */
static struct miscdevice vd_mm_cdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "vdmm",
	.fops		= &vd_mm_fops
};

static int _vd_mmc_inited = 0;
void vsec_mmc_init(void)
{
	int err = 0;
	LOG_INFO("vdmmap init\n");

	spin_lock_init(&_mmc_lock);
	err = misc_register(&vd_mm_cdev);
	if (err) {
		LOG_ERROR("misc_register failed,"
			"err: %d\n",err);
		return;
	}

	err = vsec_register_client_notifier(&mmc_cn);
	if(err) {
		misc_deregister(&vd_mm_cdev);
		return;
	}
	_vd_mmc_inited = 1;
}

void vsec_mmc_exit(void)
{
	if(_vd_mmc_inited) {
		vsec_unregister_client_notifier(&mmc_cn);
		misc_deregister(&vd_mm_cdev);
	}
}

const char* vsec_mmc_name(void)
{
	return vd_mm_cdev.name;
}

int vsec_mmc_get_stats(struct vsec_pack_stats* st_in,
					struct vsec_pack_stats* st_out)
{
	vsec_mmc_t* mmc = NULL;

	mmc = vsec_mmc_get();
	if(mmc == NULL) {
		return -EINVAL;
	}

	spin_lock_bh(&mmc->lock);
	*st_in = mmc->st_in;
	*st_out = mmc->st_out;
	spin_unlock_bh(&mmc->lock);

	vsec_mmc_put(mmc);

	st_in->packets += st_in->drops;
	st_out->packets += st_out->drops;

	return 0;
}
