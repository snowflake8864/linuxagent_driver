#include <linux/types.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/utsname.h>
#include "core/kvd_core.h"
#include "khookframe.h"


typedef int (*line_cb_t)(const char* data,size_t len); 
#define SYSMAP_LINE_SIZE 512

static int process_lines(char* buf,size_t len,
                char** premain,line_cb_t cb)
{
    int cbret = 0;
    char* p = NULL;
    char* pstart = buf;
    char* pend = buf + len;

    *premain = buf;

    do {
        p = memchr(pstart,'\n',len);
        if(p == NULL) {
            //单行预计长度绝对不会超过512个字节
            if(SYSMAP_LINE_SIZE <= len) {
                cbret = -EFBIG;
            }

            break; 
        }

        *p = '\0';
        cbret = cb(pstart,(p - pstart));
        *p = '\n';
        //skip '\n'
        len -= (p - pstart + 1);

        pstart = p + 1;
        //尾部刚好是一个\n
        if(pstart >= pend) {
            break; 
        }
        
        //返回非0直接结束
        if(cbret) { break; }
    }while(p != NULL);

    if(pstart < pend) {
        *premain = pstart;
    } else {
        *premain = NULL;
    }
    
    return cbret;
}

#define SYSMAP_BUF_SIZE (256 * 1024)
static int do_load_sysmap(struct file* fp,line_cb_t cb)
{
    int ret = 0;
    loff_t pos = 0;
    ssize_t len = 0;
    loff_t i_size = 0;
    char* buf = NULL;
    char* pstart = NULL;
    char* pend = NULL;

    buf = vmalloc(SYSMAP_BUF_SIZE);
    if(!buf) { ret = -ENOMEM; goto out; }

    pstart = buf;
    pend = buf + SYSMAP_BUF_SIZE;

    i_size = i_size_read(file_inode(fp));
	while (pos < i_size) {
        int cbret = 0;
		ssize_t bytes = 0;
        char* premain = NULL;
        size_t buflen = pend - pstart;
        
        bytes = kvd_kernel_read(fp,pstart,buflen,&pos);
		if (bytes < 0) {
			ret = bytes;
			goto out;
		}

		if (bytes == 0)
			break;

        len += bytes;
        cbret = process_lines(buf,len,
                        &premain,cb);
        if(cbret) { goto out; }

        if(premain) {
            //还有未处理的数据
            len = ((buf + len) - premain);
            memcpy(buf,premain,len);
            pstart = buf + len;
        } else {
            //缓冲区数据全部处理完成
            len = 0;
            pstart = buf;
        }
	}

out:
    if(buf) { vfree(buf); }
    return ret;
}

int load_sysmap(const char* sysmaps[],size_t size,
		int (*cb)(const char* data,size_t len))
{
    int rc = 0;
	size_t i = 0;
    struct file* fp = ERR_PTR(-EBADF);

	//依次打开相关文件，如果有一个成功则不再继续
	for(;i < size;i++) {
		const char* fname = sysmaps[i];
		BUG_ON(fname == NULL);

    	fp = filp_open(fname, O_RDONLY,0400);
		if(!IS_ERR(fp)) { break; }

        rc = PTR_ERR(fp);
		LOG_ERROR("load_sysmap: open %s fail,rc: %d \n",
                fname,rc);
	}

	if(IS_ERR(fp)) { 
		rc = PTR_ERR(fp);
		return rc; 
	}
    
    rc = do_load_sysmap(fp,cb);
    filp_close(fp, NULL);

    return rc;
}
