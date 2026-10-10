#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/binfmts.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/mm.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h> //fo get_task_struct,put_task_struct
#include <linux/sched/mm.h> //fo get_task_mm,mmput
#endif
#include "core/kvd_core.h"



#if defined(CONFIG_MMU) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)

    #if defined(CONFIG_MACH_LOONGSON3) || defined(CONFIG_CPU_LOONGSON3)
        //龙芯上这个函数没有定义，我们自己定义一下
        void copy_from_user_page(struct vm_area_struct *vma,
            struct page *page, unsigned long vaddr, void *dst, const void *src,
            unsigned long len)
        {
            if (cpu_has_dc_aliases &&
                page_mapped(page) && !Page_dcache_dirty(page)) {
                void *vfrom = kmap_coherent(page, vaddr) + (vaddr & ~PAGE_MASK);
                memcpy(dst, vfrom, len);
                kunmap_coherent();
            } else {
                memcpy(dst, src, len);
                if (cpu_has_dc_aliases)
                    SetPageDcacheDirty(page);
            }
        }
    #endif

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
        static int do_ioremap_port(struct mm_struct *mm,unsigned long addr,
                void* buf,int len,int write,struct vm_area_struct** pvma)
        {
            int ret = -1;

            #ifdef CONFIG_HAVE_IOREMAP_PROT
                struct vm_area_struct* vma = NULL;
                /*
                * Check if this is a VM_IO | VM_PFNMAP VMA, which
                * we can access using slightly different code.
                */
                vma = find_vma(mm, addr);
                if (!vma) { return ret; }

                *pvma = vma;
                if (vma->vm_ops && vma->vm_ops->access)
                    ret = vma->vm_ops->access(vma, addr, buf,
                                  len, write);
            #endif
            return ret;
        }
    #else
        static int do_ioremap_port(struct mm_struct *mm,unsigned long addr,
            void* buf,int len,int write,struct vm_area_struct** pvma)
        {
            return -1;
        }
    #endif
    /*
    * Access another process' address space.
    * Source/target buffer must be kernel space,
    * Do not walk the page table directly, use get_user_pages
    */
    static int get_access_process_vm(struct task_struct *tsk,
                unsigned long addr, void *buf, int len, int write)
    {
        struct mm_struct *mm;
        struct vm_area_struct *vma;
        void *old_buf = buf;

        mm = get_task_mm(tsk);
        if (!mm)
            return 0;
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
        down_read(&mm->mmap_lock);
	#else
        down_read(&mm->mmap_sem);
	#endif
        /* ignore errors, just check how much was successfully transferred */
        while (len) {
            int bytes, ret, offset;
            void *maddr;
            struct page *page = NULL;

            ret = kvd_get_user_pages(tsk, mm, addr,&page, &vma);
            if (ret <= 0) {
                ret = do_ioremap_port(mm,addr,buf,len,write,&vma);
                if(ret <= 0)
                    break;
                bytes = ret;
            } else {
                bytes = len;
                offset = addr & (PAGE_SIZE-1);
                if (bytes > PAGE_SIZE-offset)
                    bytes = PAGE_SIZE-offset;

                maddr = kmap(page);
                if (write) {
                    copy_to_user_page(vma, page, addr,
                              maddr + offset, buf, bytes);
                    set_page_dirty_lock(page);
                } else {
                    copy_from_user_page(vma, page, addr,
                                buf, maddr + offset, bytes);
                }
                kunmap(page);
                put_page(page);
            }
            len -= bytes;
            buf += bytes;
            addr += bytes;
        }
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
        up_read(&mm->mmap_lock);
	#else
        up_read(&mm->mmap_sem);
	#endif
        mmput(mm);

        return buf - old_buf;
    }
#else
    /*
    * Access another process' address space.
    * - source/target buffer must be kernel space
    */
    static int get_access_process_vm(struct task_struct *tsk,
            unsigned long addr, void *buf, int len, int write)
    {
        struct vm_area_struct *vma;
        struct mm_struct *mm;

        if (addr + len < addr)
            return 0;

        mm = get_task_mm(tsk);
        if (!mm)
            return 0;

        down_read(&mm->mmap_sem);

        /* the access must start within one of the target process's mappings */
        vma = find_vma(mm, addr);
        if (vma) {
            /* don't overrun this mapping */
            if (addr + len >= vma->vm_end)
                len = vma->vm_end - addr;

            /* only read or write mappings where it is permitted */
            if (write && vma->vm_flags & VM_MAYWRITE)
                len -= copy_to_user((void *) addr, buf, len);
            else if (!write && vma->vm_flags & VM_MAYREAD)
                len -= copy_from_user(buf, (void *) addr, len);
            else
                len = 0;
        } else {
            len = 0;
        }

        up_read(&mm->mmap_sem);
        mmput(mm);
        return len;
    }
#endif

/**
 * do_get_cmdline() - copy the cmdline value to a buffer.
 * @task:     the task whose cmdline value to copy.
 * @buffer:   the buffer to copy to.
 * @buflen:   the length of the buffer. Larger cmdline values are truncated
 *            to this length.
 * Returns the size of the cmdline field copied. Note that the copy does
 * not guarantee an ending NULL byte.
 */
static int do_get_cmdline(struct task_struct *task, char *buffer, int buflen)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);

	if (!mm)
		goto out;
	if (!mm->arg_end) {
		goto out_mm;	/* Shh! No looking before we're done */
    }

	len = mm->arg_end - mm->arg_start;
	if (len > buflen)
		len = buflen;

	res = get_access_process_vm(task, mm->arg_start, buffer, len, 0);
	/*
	 * If the nul at the end of args has been overwritten, then
	 * assume application is using setproctitle(3).
	 */
	if (res > 0 && buffer[res-1] != '\0' && len < buflen) {
		len = strnlen(buffer, res);
		if (len < res) {
			res = len;
		} else {
			len = mm->env_end - mm->env_start;
			if (len > buflen - res)
				len = buflen - res;
			res += get_access_process_vm(task,mm->env_start,
						 buffer + res, len, 0);
			res = strnlen(buffer, res);
		}
	}

out_mm:
	mmput(mm);
out:
	return res;
}

/*获取进程的命令行参数: 
 *这个函数只适用于已经运行的进程，该函数不适用于在register_binfmt注册的回调用中获取进程的命令行参数
 *因为register_binfmt注册的回调用中，进程用于存放命令行参数的内存结构(task->mm)根本就没有构造好
 *
 *plen-->是一个输入输出参数，作为输入参数用于指定buf的长度;作为输出参数用于指定返回的命令行参数字长串长度
 */
char* vsec_get_task_cmdline(struct task_struct* tsk,char* buf,unsigned* plen)
{
    int i = 0;
    int len = 0;
    int rc = -EINVAL;
    char* cmdline = NULL;

    if(!buf || !tsk || !plen || !*plen) {
        goto out;
    }

    rc = -EFAULT;
    //one more space for '\0'
    cmdline = buf;
    len = *plen - 1;
    len = do_get_cmdline(tsk,cmdline,len);
    if(len <= 0) { goto out; }

   
    //内核返回的命令行参数长度是包含最后一个参数的结束标识\0的
    //我们在此处要将\0的长度去掉
    while(cmdline[len - 1] == '\0') {
        len--;
    }

    //因为内核就是以\0来区分每个命令行参数的
    //我们在此处将每个参数的\0替换为空格
    for(;i < len;i++) {
        if(cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }

    rc = 0;
    *plen = len;
    cmdline[len] = '\0';

out:
    if(rc) {
        cmdline = ERR_PTR(rc);
    }
    return cmdline;
}

char* vsec_get_task_cmdline2(struct task_struct* tsk,char* buf,unsigned* plen,
                            unsigned* pargc,char* argv[])
{
    int i = 0;
    int len = 0;
    char* p = NULL;
    int rc = -EINVAL;
    unsigned nargc = 0;
    char* cmdline = NULL;

    if(!buf || !tsk || !plen || !*plen) {
        goto out;
    }

    rc = -EFAULT;
    //one more space for '\0'
    cmdline = buf;
    len = *plen - 1;
    len = do_get_cmdline(tsk,cmdline,len);
    if(len <= 0) { goto out; }

    //内核返回的命令行参数长度是包含最后一个参数的结束标识\0的
    //我们在此处要将\0的长度去掉
    while(cmdline[len - 1] == '\0') {
        len--;
    }

    p = cmdline;
    for(;(i <= len) && (nargc < *pargc);i++) {
        if(cmdline[i] == '\0') {
            argv[nargc++] = p;
            p = cmdline + i + 1;
        }
    }

    rc = 0;
    *plen = len;
    *pargc = nargc;

out:
    if(rc) {
        cmdline = ERR_PTR(rc);
    }
    return cmdline;
}


/**
 * do_get_env() - copy the cmdline value to a buffer.
 * @task:     the task whose cmdline value to copy.
 * @buffer:   the buffer to copy to.
 * @buflen:   the length of the buffer. Larger cmdline values are truncated
 *            to this length.
 * Returns the size of the cmdline field copied. Note that the copy does
 * not guarantee an ending NULL byte.
 */
static int do_get_env(struct task_struct *task, char *buffer, int buflen)
{
	int res = 0;
	int envlen = 0;
    int count = buflen;
	struct mm_struct *mm = get_task_mm(task);

	if (!mm)
		goto out;
	if (!mm->env_start) {
		goto out_mm;	/* Shh! No looking before we're done */
    }

	envlen = mm->env_end - mm->env_start;

    while(count > 0) {
        int retlen = 0;
        if(envlen <= res) { break; }
        
        retlen = get_access_process_vm(task, mm->env_start + res,
                                    buffer + res,count, 0);
        if(retlen <= 0) { break; }
        
        res += retlen;
        count -= retlen;
    }

out_mm:
	mmput(mm);
out:
	return res;
}

/*获取进程的环境变量: 
 *这个函数只适用于已经运行的进程，该函数不适用于在register_binfmt注册的回调用中获取进程的环境参数
 *因为register_binfmt注册的回调用中，进程用于存放环境参数的内存结构(task->mm)根本就没有构造好
 *
 *plen-->是一个输入输出参数，作为输入参数用于指定buf的长度;作为输出参数用于指定返回的环境参数字长串长度
 */
char* vsec_get_task_env(struct task_struct* tsk,char* buf,unsigned* plen)
{
    int i = 0;
    int len = 0;
    int rc = -EINVAL;
    char* penv = NULL;

    if(!buf || !tsk || !plen || !*plen) {
        goto out;
    }

    rc = -EFAULT;
    //one more space for '\0'
    penv = buf;
    len = *plen - 1;
    len = do_get_env(tsk,penv,len);
    if(len <= 0) { goto out; }

   
    //内核返回的命令行参数长度是包含最后一个参数的结束标识\0的
    //我们在此处要将\0的长度去掉
    while(penv[len - 1] == '\0') {
        len--;
    }

    //因为内核就是以\0来区分每个命令行参数的
    //我们在此处将每个参数的\0替换为空格
    for(;i < len;i++) {
        if(penv[i] == '\0') {
            penv[i] = ' ';
        }
    }

    rc = 0;
    *plen = len;
    penv[len] = '\0';

out:
    if(rc) {
        penv = ERR_PTR(rc);
    }
    return penv;
}

char* vsec_get_task_env2(struct task_struct* tsk,char* buf,unsigned* plen,
                            unsigned* penvc,char* envs[])
{
    int i = 0;
    int len = 0;
    char* p = NULL;
    int rc = -EINVAL;
    unsigned nenvc = 0;
    char* penv = NULL;

    if(!buf || !tsk || !plen || !*plen) {
        goto out;
    }

    rc = -EFAULT;
    //one more space for '\0'
    penv = buf;
    len = *plen - 1;
    len = do_get_env(tsk,penv,len);
    if(len <= 0) { goto out; }

    //内核返回的命令行参数长度是包含最后一个参数的结束标识\0的
    //我们在此处要将\0的长度去掉
    while(penv[len - 1] == '\0') {
        len--;
    }

    p = penv;
    for(;(i <= len) && (nenvc < *penvc);i++) {
        if(penv[i] == '\0') {
            envs[nenvc++] = p;
            p = penv + i + 1;
        }
    }

    rc = 0;
    *plen = len;
    *penvc = nenvc;

out:
    if(rc) {
        penv = ERR_PTR(rc);
    }
    return penv;
}
