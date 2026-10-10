#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h> //fo get_task_struct,put_task_struct
#include <linux/sched/mm.h> //fo get_task_mm,mmput
#endif

#include "core/kvd_core.h"
#include "utils.h"
#include "exe_cmdline.h"



/*
 *注意:
 *RedHat5.3/5.5/5.11版本的内核虽然是2.6.18
 *但RedHat却对内核做了修改，合并了一些新版本内核中的patch,
 *所以此处获取进程执行的命令行参数时采用的机制与标准的2.6.18内核不同
 *如果采用标准的2.6.18版本的内核获取命令行参数的方法会导致在RedHat5.3/5.5/5.11
 *系统上出现崩溃，此处一定要注意
 */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22) || defined(RHEL_RELEASE_CODE)
    #ifdef CONFIG_MMU
        static struct page *vsec_get_arg_page(struct linux_binprm *bprm, unsigned long pos)
        {
        	struct page *page;
        	int ret;

        	ret = kvd_get_user_pages(current,bprm->mm,pos,&page,NULL);
        	if (ret <= 0)
        		return NULL;

        	return page;
        }

        static void vsec_put_arg_page(struct page *page)
        {
            vsec_kunmap_atomic(page);
        	put_page(page);
        }

    #else
        static struct page *vsec_get_arg_page(struct linux_binprm *bprm, unsigned long pos)
        {
        	struct page *page;

        	page = bprm->page[pos / PAGE_SIZE];

        	return page;
        }

        static void vsec_put_arg_page(struct page *page)
        {
            vsec_kunmap_atomic(page);
        }

    #endif /* CONFIG_MMU */
#elif defined(CONFIG_X86_32) && (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18))
    //发现在redhat5.0, 2.6.18-8 32位系统上获取命令行参数
    //使用kmap_atomic映射页面时发生崩溃,改为使用kmap映射后未再发现崩溃
    //此处修改为缩小影响范围,直接判断32位系统的2.6.18内核不再检查命令行参数
    static struct page *vsec_get_arg_page(struct linux_binprm *bprm, unsigned long pos)
    {
        return NULL;
    }

    static void vsec_put_arg_page(struct page *page)
    {
    }
#else
    static struct page *vsec_get_arg_page(struct linux_binprm *bprm, unsigned long pos)
    {
        struct page *page;

        page = bprm->page[pos / PAGE_SIZE];

        return page;
    }

    static void vsec_put_arg_page(struct page *page)
    {
        vsec_kunmap_atomic(page);
    }
#endif


static int get_one_arg(struct linux_binprm* bprm,int argc,
            unsigned long pos,char* buffer,int buflen,bool bfind)
{
    int len = 0;
    int cross_page = 0;
    char *kaddr = NULL;
    unsigned long kpos = 0;
    struct page *kmapped_page = NULL;

    do {
        int n = 0;
        struct page *page = NULL;
        int offset, bytes_to_copy;

        offset = pos % PAGE_SIZE;
        bytes_to_copy = PAGE_SIZE - offset;

        if (bytes_to_copy > (buflen - len)) {
            bytes_to_copy = buflen - len;
        }

        if (!kmapped_page || kpos != (pos & PAGE_MASK)) {
            page = vsec_get_arg_page(bprm, pos);
            if (!page) { goto out; }

            if (kmapped_page) {
                vsec_put_arg_page(kmapped_page);
            }
            kmapped_page = page;
            kpos = pos & PAGE_MASK;
            kaddr = vsec_kmap_atomic(kmapped_page);
        }

        /*Note:
         *内核在处理用户态的命令行参数时将结尾的NUL字符也计算进去了
         *在处理时此处采用strnlen计算最大字符串长度,
         *因为第一次我们根本无法计算出bytes_to_copy准确的大小
         *另外，由于命令行参数可能跨页，所以存放参数的每一项的结尾并不一定是\0结尾
         *只能假定copy整个字符串，然后第二次及以后就能计算正确了
         */
        n = strnlen(kaddr + offset,bytes_to_copy);
        memcpy(buffer + len,kaddr + offset,n);
        len += n;
        //如果n == bytes_to_copy说明对应的命令行参数页没有以\0结尾
        //此处一定是出现了命令行参数跨页的问题
        cross_page = (n == bytes_to_copy);
        if(!cross_page) {
            //未跨页时将长度+1,用于包含NUL字符，
            //因为内核在从用户态计算命令行参数时将NUL字符也算进去了
            n++;
            //命令行参数未跨页且还有其他命令行参数时
            //在下一个命令行参数前加一个空格
            //bfind: 如果在进行参数查找则设置一个NIL
            if((argc > 0 || bfind) && (len + 1 < buflen)) {
                buffer[len++] = (bfind ? '\0' : ' ');
            }
        } 
        // else {
        //     printk("cross_page\n");
        // }
        pos += n;
    } while(cross_page && (buflen > len)); //如果跨页继续循环处理同一个参数

out:
    if (kmapped_page) {
        vsec_put_arg_page(kmapped_page);
    }
    return len;
}
//此处获取进程命令行参数时只需要以只读的方式对内存页进行映射即可，不考虑写的情况
static int do_get_cmdline(struct linux_binprm* bprm,char* buffer,int buflen)
{
    int n = 0;
    int len = 0;
    int argc = bprm->argc;
    unsigned long pos = bprm->p;

	while (argc-- > 0) {
		if(len >= buflen) {
            break;
        }

        n = get_one_arg(bprm,argc,pos,
            buffer + len,buflen - len,false);
        if(n <= 0) { break; }

        pos += n;
        len += n;
	}

	return len;
}

//plen-->是一个输入输出参数，作为输入参数用于指定buf的长度;作为输出参数用于指定返回的命令行参数字长串长度
char* vsec_get_exe_cmdline(struct linux_binprm *bprm,char* buff,unsigned* plen)
{
    int len = 0;
    int rc = -EFAULT;
    char* cmdline = buff;

    //one more space for '\0'
    len = *plen - 1;
    len = do_get_cmdline(bprm,cmdline,len);
    if(len <= 0) { goto out; }

    rc = 0;
    *plen = len;
    cmdline[len] = '\0';

out:
    if(rc) {
        cmdline = ERR_PTR(rc);
    }
    return cmdline;
}

#ifndef MAX_ARG_STRLEN
    #define MAX_ARG_STRLEN (PAGE_SIZE*MAX_ARG_PAGES)
#endif


static int get_one_arg_len(struct linux_binprm* bprm,int* pargc,
                unsigned long pos)
{
    int len = 0;
    int argc = *pargc;
    int cross_page = 0;
    char *kaddr = NULL;
    unsigned long kpos = 0;
    struct page *kmapped_page = NULL;

    do {
        int n = 0;
        struct page *page = NULL;
        int offset, bytes_to_copy;

        offset = pos % PAGE_SIZE;
        bytes_to_copy = PAGE_SIZE - offset;

        if (!kmapped_page || kpos != (pos & PAGE_MASK)) {
            page = vsec_get_arg_page(bprm, pos);
            if (!page) { goto out; }

            if (kmapped_page) {
                vsec_put_arg_page(kmapped_page);
            }
            kmapped_page = page;
            kpos = pos & PAGE_MASK;
            kaddr = vsec_kmap_atomic(kmapped_page);
        }

        /*Note:
         *内核在处理用户态的命令行参数时将结尾的NUL字符也计算进去了
         *在处理时此处采用strnlen计算最大字符串长度,
         *因为第一次我们根本无法计算出bytes_to_copy准确的大小
         *另外，由于命令行参数可能跨页，所以存放参数的每一项的结尾并不一定是\0结尾
         *只能假定copy整个字符串，然后第二次及以后就能计算正确了
         */
        n = strnlen(kaddr + offset,bytes_to_copy);
        //如果n == bytes_to_copy说明对应的命令行参数页没有以\0结尾
        //此处一定是出现了命令行参数跨页的问题
        cross_page = (n == bytes_to_copy);
        if(!cross_page) {
            argc--;
            //未跨页时将长度+1,用于包含NUL字符，
            //因为内核在从用户态计算命令行参数时将NUL字符也算进去了
            n++;
        }
        len += n;
        pos += n;
    } while((argc > 0) && cross_page); //如果跨页继续循环处理同一个参数

    *pargc = argc;
out:
    if (kmapped_page) {
        vsec_put_arg_page(kmapped_page);
    }
    return len;
}

static u_long find_env_start(struct linux_binprm* bprm)
{
    int argc = bprm->argc;
    unsigned long pos = bprm->p;

	while (argc > 0) {
        int n = get_one_arg_len(bprm,&argc,pos);
        if(n <= 0) { break; }

        pos += n;
	}

	return pos;
}

//此处获取进程命令行参数时只需要以只读的方式对内存页进行映射即可，不考虑写的情况
static int do_get_env(struct linux_binprm* bprm,
                char* buffer,int buflen,
                void* ctx,bool (*find_cb)(char*env,unsigned,void*))
{
    int n = 0;
    int len = 0;
    int envc = bprm->envc;
    unsigned long pos = find_env_start(bprm);

    if(pos == 0) { return -EFAULT; }

	while (envc-- > 0) {
		if(len >= buflen) {
            break;
        }

        n = get_one_arg(bprm,envc,pos,
            buffer + len,buflen - len,
            (find_cb != NULL));
        if(n <= 0) { break; }

        pos += n;
        if(find_cb) {
            /*查找到了，直接退出即可
             *Note: 这里再做一次计算
             *因为get_one_arg为了方便处理在针对参数查找情况下
             *在尾部会自动添加一个NIL字符,此处我们过滤掉
             */
            while(buffer[len + n - 1] == '\0') {
                n--;
            }
        
            if(find_cb(buffer + len,n,ctx)) {
                len = n;
                break;
            }
            memset(buffer + len,0,n);
        } else {
            len += n;
        }
	}

	return len;
}

//plen-->是一个输入输出参数，作为输入参数用于指定buf的长度;作为输出参数用于指定返回的环境变量的字符串长度
char* vsec_get_exe_env(struct linux_binprm *bprm,char* buff,unsigned* plen)
{
    int len = 0;
    int rc = -EFAULT;
    char* env = buff;

    //one more space for '\0'
    len = *plen - 1;
    len = do_get_env(bprm,env,len,NULL,NULL);
    if(len <= 0) { goto out; }

    rc = 0;
    *plen = len;
    env[len] = '\0';

out:
    if(rc) {
        env = ERR_PTR(rc);
    }
    return env;
}

int vsec_get_exe_env2(struct linux_binprm *bprm,void* ctx,
                bool (*find_cb)(char*env,unsigned,void* ctx))
{
    int len = PAGE_SIZE;
    char* env = kzalloc(len,GFP_KERNEL);
    if(!env) { return -ENOMEM; }

    //one more space for '\0'
    len = do_get_env(bprm,env,
                len - 1,ctx,find_cb);
    kfree(env);
    return len;
}

static int get_one_arg2(struct linux_binprm* bprm,
            vsec_cmd_argv_t args[],int* pargs_count,
            int* pargc,unsigned long pos,char* buffer,int buflen)
{
    int len = 0;
    int args_count = 0;
    int argc = *pargc;
    int cross_page = 0;
    char *kaddr = NULL;
    unsigned long kpos = 0;
    char* parg_start = buffer;
    struct page *kmapped_page = NULL;

    do {
        int n = 0;
        struct page *page = NULL;
        int offset, bytes_to_copy;

        offset = pos % PAGE_SIZE;
        bytes_to_copy = PAGE_SIZE - offset;

        if (bytes_to_copy > (buflen - len)) {
            bytes_to_copy = buflen - len;
        }

        if (!kmapped_page || kpos != (pos & PAGE_MASK)) {
            page = vsec_get_arg_page(bprm, pos);
            if (!page) { goto out; }

            if (kmapped_page) {
                vsec_put_arg_page(kmapped_page);
            }
            kmapped_page = page;
            kpos = pos & PAGE_MASK;
            kaddr = vsec_kmap_atomic(kmapped_page);
        }

        /*Note:
         *内核在处理用户态的命令行参数时将结尾的NUL字符也计算进去了
         *在处理时此处采用strnlen计算最大字符串长度,
         *因为第一次我们根本无法计算出bytes_to_copy准确的大小
         *另外，由于命令行参数可能跨页，所以存放参数的每一项的结尾并不一定是\0结尾
         *只能假定copy整个字符串，然后第二次及以后就能计算正确了
         */
        n = strnlen(kaddr + offset,bytes_to_copy);
        memcpy(buffer + len,kaddr + offset,n);
        len += n;
        //如果n == bytes_to_copy说明对应的命令行参数页没有以\0结尾
        //此处一定是出现了命令行参数跨页的问题
        cross_page = (n == bytes_to_copy);
        if(!cross_page) {
            argc--;
            //未跨页时将长度+1,用于包含NUL字符，
            //因为内核在从用户态计算命令行参数时将NUL字符也算进去了
            n++;
            args[args_count].argv = parg_start;
            args[args_count].len = buffer + len - parg_start;
            args_count++;

            //每个参数使用一个NUL字符分隔
            if(len + 1 < buflen) {
                buffer[len++] = '\0';
            }

            parg_start = buffer + len;
        } else {
            // printk("cross_page\n");
        }
        pos += n;
    } while((argc > 0) && cross_page && (buflen > len)); //如果跨页继续循环处理同一个参数

    *pargc = argc;
    *pargs_count = args_count;
out:
    if (kmapped_page) {
        vsec_put_arg_page(kmapped_page);
    }
    return len;
}

int vsec_get_exe_args(struct linux_binprm* bprm,
        char* buffer,size_t buflen,
        vsec_cmd_argv_t args[16],int args_count)
{
    int n = 0;
    int len = 0;
    int argc = bprm->argc;
    unsigned long pos = bprm->p;

    if(!bprm || !buffer || !buflen || 
        (args_count <= 0)) 
    {
        return -EINVAL;
    }

    argc = min(argc,args_count);
    args_count = 0;
	while (argc > 0) {
        int got_args_count = 0;

		if(len >= buflen) {
            break;
        }

        n = get_one_arg2(bprm,
            args + args_count,&got_args_count,
            &argc,pos,buffer + len,buflen - len);
        if(n <= 0) { break; }

        pos += n;
        len += n;
        args_count += got_args_count;
	}

	return args_count;
}

