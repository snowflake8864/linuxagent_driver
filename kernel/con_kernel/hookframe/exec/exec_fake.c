#include <linux/types.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include "utils/task_cmdline.h"
#include "core/kvd_core.h"
#include "khookframe.h"
#include "defense/defense_inner.h"



static unsigned long has_fake = 0;
static struct list_head fake_list;
static DEFINE_RWLOCK(fake_list_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0) || SPEC_VERSION_BUILD == 1
static int prepare_binprm(struct linux_binprm* bprm)
{
	loff_t pos = 0;
	
	memset(bprm->buf,0,BINPRM_BUF_SIZE);
	return kernel_read(bprm->file,bprm->buf,BINPRM_BUF_SIZE,&pos);
}
#endif

static int do_fake_exec(const char* fake,
                    struct linux_binprm* bprm)
{
    int rc = 0;
    struct file* file_kern = open_exec(fake);
    if(IS_ERR(file_kern)) {
        rc = PTR_ERR(file_kern);
        return rc;
    }

    {
        const char* old_fname = NULL;
        const char* old_interp = NULL;
        struct file* tmp_file = bprm->file;

        bprm->file = file_kern;
        old_interp = bprm->interp;
        old_fname = bprm->filename;
        bprm->filename = bprm->interp = fake;

        rc = prepare_binprm(bprm);
        if (rc < 0) {
            LOG_ERROR("prepare_binprm failed:%s, bprm->file:%p", 
                        current->comm,
                        bprm->file);
            allow_write_access(file_kern);
            fput(file_kern);
            bprm->file = tmp_file;
            bprm->filename = old_fname;
            bprm->interp = old_interp;
        } else {
            allow_write_access(tmp_file);
            fput(tmp_file);
        }
    }

    return rc;
}

static void need_fake_exe(const char* realpath,unsigned len,
                        struct linux_binprm *bprm)
{
    unsigned long flags;
    const char* fake = NULL;
    const char* p = realpath;
    const char* name = realpath;
    kvd_exec_fake_t* elem = NULL;

    p = strrchr(realpath, '/');
    if (p) { name = p + 1; }

//    LOG_DEBUG("check need fake: realpath: %s,name: %s\n",\
                    realpath,name);
    
    LOG_INFO("check need fake: realpath: %s,name: %s\n",\
                    realpath,name);
    read_lock_irqsave(&fake_list_lock,flags);
    list_for_each_entry(elem,&fake_list,lh) {
		int bfake = 0;
        const char *vfake = NULL;
        int (*fake_check)(const char *, const char *) = NULL;
        int (*fake_check2)(struct linux_binprm *, const char *, const char *) = NULL;
        if(elem->fake_check) {
            vfake = elem->fake;
            fake_check = elem->fake_check;
        } else if(elem->fake_check2) {
            vfake = elem->fake;
            fake_check2 = elem->fake_check2;
        }
        read_unlock_irqrestore(&fake_list_lock,flags);

        if (fake_check) {
            bfake = fake_check(realpath, name);
        } else if (fake_check2) {
            bfake = fake_check2(bprm, realpath, name);
        }
        if(bfake) { fake = vfake; goto out; }

        read_lock_irqsave(&fake_list_lock,flags);
	}
    read_unlock_irqrestore(&fake_list_lock,flags);

out:
    if(fake) { do_fake_exec(fake,bprm); }
}


#if 0
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0)
static int _load_bin_check(struct linux_binprm *bprm)
#else
static int _load_bin_check(struct linux_binprm *bprm,
                            struct  pt_regs * regs)
#endif
{
    int ret = -ENOEXEC;
    unsigned int pathlen = 0;
    char* realname = ERR_PTR(-EBADF);
    
    //这里先判断是否有fake注册
    //如果没有就不用再进行下面的逻辑了
    //尤其是kvd_file_pathname操作其实是比较慢的
    //我们在此处执行能快一点就快一点
    //这里不加锁了，可能会有点不准确，但我们是能够接受的
    if(!test_bit(0,&has_fake)) {
        return ret;
    }

    realname = kvd_filp_pathname(bprm->file,&pathlen);
    if (IS_ERR(realname)) {
        return ret;
    }

    need_fake_exe(realname,pathlen,bprm);
    kvd_put_pathname(realname);

    return ret;
}
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0)
static int _load_bin_check(struct linux_binprm *bprm)
#else
static int _load_bin_check(struct linux_binprm *bprm,
                            struct  pt_regs * regs)
#endif
{
    int ret = -ENOEXEC;
    unsigned int pathlen = 0;
    char* realname = ERR_PTR(-EBADF);

    //这里先判断是否有fake注册
    //如果没有就不用再进行下面的逻辑了
    //尤其是kvd_file_pathname操作其实是比较慢的
    //我们在此处执行能快一点就快一点
    //这里不加锁了，可能会有点不准确，但我们是能够接受的
    if(!test_bit(0,&has_fake)) {
        return ret;
    }
    int nDeny = 0;

    if (is_proc_start_enable() || is_syslog_enable())
    {
        realname = kvd_filp_pathname(bprm->file,&pathlen);
        if(IS_ERR(realname)) { return ret; }
        //if (is_process_enable() || is_syslog_enable())
        //get_user_command(current);
#if 0
        if (pathlen == 7 && strncmp(realname, "/bin/cp", 7) == 0) {
            char* p = NULL;
            unsigned argc = 8;
            char* argv[8] = {NULL};
            unsigned len = PAGE_SIZE;

            char* buf = kzalloc(len,GFP_KERNEL);
            if(!buf) { return -ENOEXEC; }
            p = vsec_get_task_cmdline2(current,buf,&len,
                    &argc,argv);
            if(KVD_IS_ERR_OR_NULL(p) != 0 && argc >= 2) { 
                LOG_INFO("========[%s]\n", p);
            }
            int i;
            for (i = 0; i < argc; i++) {
                LOG_INFO("========%d,[%s]\n", i, argv[i]);
            }
            kfree(buf);

        }
#endif
        nDeny = exe_audit_filepath(realname, pathlen);
        kvd_put_pathname(realname);
        if (nDeny) {
            return -EACCES;
        }
    }
    return -ENOEXEC;
}
#endif





static struct linux_binfmt fake_fmt = {
    .module         = THIS_MODULE,
    .load_binary    = _load_bin_check,
};

int kvd_init_exec_fake(void)
{
    INIT_LIST_HEAD(&fake_list);
    //process_audit_zero_copy_init();
    return kvd_register_binfmt(&fake_fmt);
}

void kvd_uninit_exec_fake(void)
{
    kvd_unregister_binfmt(&fake_fmt);
    //process_audit_zero_copy_exit();
}

int kvd_register_exec_fake(kvd_exec_fake_t* exec_fake)
{
    int bexist = 0;
    int rc = -EAGAIN;
    unsigned long flags;
    kvd_exec_fake_t* elem = NULL;

    BUG_ON((exec_fake == NULL) ||
          (exec_fake->fake == NULL) ||
          ((exec_fake->fake_check == NULL) &&
          (exec_fake->fake_check2 == NULL)));

    write_lock_irqsave(&fake_list_lock,flags);
	list_for_each_entry(elem,&fake_list,lh) {
		bexist = (!strcmp(elem->fake,
                    exec_fake->fake));
        if(bexist) { break; }
	}
    if(!bexist) {
        rc = 0;
        set_bit(0,&has_fake);
	    list_add_tail(&exec_fake->lh,&fake_list);
    }
    write_unlock_irqrestore(&fake_list_lock,flags);

    return rc;
}

void kvd_unregister_exec_fake(kvd_exec_fake_t* exec_fake)
{
    unsigned long flags;

    BUG_ON(exec_fake == NULL);
    //不支持在模块运行时进行unregister
    BUG_ON(THIS_MODULE->state == MODULE_STATE_LIVE);
    
    write_lock_irqsave(&fake_list_lock,flags);
    list_del(&exec_fake->lh);
    if(list_empty(&fake_list)) {
        clear_bit(0,&has_fake);
    }
    write_unlock_irqrestore(&fake_list_lock,flags);
}

