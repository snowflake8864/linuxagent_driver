#include <linux/version.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/delay.h>
#include "hook_ksyms.h"


 #if defined(__aarch64__) && (LINUX_VERSION_CODE == KERNEL_VERSION(4,19,232) )
    //KF麒麟适配已导出kallsyms_lookup_name
    //#define KYLIN_ARM_232X 1
 #endif

extern int hook_search_ksym(const char *sym_name, unsigned long *sym_addr);
static void** find_sys_call_table3(void)
{
    void** pcall_table = NULL;
    //如果启用了地址随机化,从System.map文件中获取的就是错误的
    //一定不要使用,否则就会导致崩溃的
    //注释掉了，hook_search_ksym里针对地址随机化是有通过sys_close修正的 lichangkun 2021-3-17
//#if !defined(CONFIG_RANDOMIZE_MEMORY)
    int rc = 0;
    unsigned long addr = 0;
    rc = hook_search_ksym("sys_call_table",&addr);
    if(rc == 0) { pcall_table = (void**)addr; }
//#endif
    return pcall_table;
}

#if defined(__x86_64__) && defined(RHEL_RELEASE_CODE)
    #if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
        //find system call table by register
        #if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,4))
            static void **find_sys_call_table(void)
            {
                void** ptable = NULL;
                unsigned long ptr = 0;
                unsigned long pend = 0;
                unsigned long *p  = NULL;
                unsigned long psys_close = 0;

                pend = (unsigned long)&loops_per_jiffy;
                psys_close = (unsigned long)sys_close;
                for (ptr = psys_close;ptr < pend;ptr += sizeof(void*)) {
                    p = (unsigned long*)ptr;
                    if (p[__NR_close] == psys_close) {
                        ptable = (void**) p;
                        break;
                    }
                }

                return ptable;
            }
        #else
            //6.4及更高版本的系统不要采用下面的形式查找系统调用表
            //不然极可能会崩溃，这个在xen虚拟机6.4的系统上是已知的
            static void** find_sys_call_table(void)
            {
                int i = 0;
                int nsign = 0;
                u64 system_call;
                char* byte = NULL;
                void** pcall_table = NULL;
                char sign[] = "\x4C\x89\xD1\xFF\x14\xC5";

                nsign = sizeof(sign) - 1;
                rdmsrl(MSR_LSTAR, system_call);
                byte = (char*)system_call;

                //下面这个偏移量1024，是因为在CentOS6.9 2.6.32-696.20.1.el6.x86_64使用150无法查找到系统调用表
                //关于150,我也不知道很多相同的hook机制为什么会选择150作为偏移量
                for (i = 0;i < 1024; i++, byte++) {
                    if (memcmp(byte, sign,nsign)) { continue; }

                    pcall_table = (void**)(long)*(int*)(byte + nsign);
                    break;
                }

                return pcall_table;
            }
        #endif

        //just for link-define,we don't really use it
        unsigned long kallsyms_lookup_name(const char *name)
        {
        	return 0;
        }
    #else
        //urgly,but we must do it
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
            unsigned long kallsyms_lookup_name(const char *name)
            {   
                return 0;
            }
        #else
        extern unsigned long kallsyms_lookup_name(const char *name);
        #endif
        static void** find_sys_call_table(void)
        {
            void** pcall_table = NULL;
            pcall_table = (void**)kallsyms_lookup_name("sys_call_table");
            if (pcall_table) { goto out; }

            pcall_table = find_sys_call_table3();
        out:
            return pcall_table;

        }
    #endif //enddefine (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
#else
    #ifdef __i386__
        struct _idtr{
            unsigned short  limit;
            unsigned int    base;
        } __attribute__ ( ( packed ) );

        // 中断描述符表结构
        struct _idt_descriptor
        {
            unsigned short offset_low;
            unsigned short sel;
            unsigned char  none, flags;
            unsigned short offset_high;
        } __attribute__((packed));

        /*
         * 32位CentOS 5.11系统，kallsyms_lookup_name符号没被导出
	 	 * #if defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(5,11)
	 	 * 此处如果使用上面的预处理，在CentOS 5.11上可以编译通过，但在某些系统如Debian 10，
	 	 * 将无法编译通过，只能使用丑陋的代码。
         */
        #if defined(RHEL_RELEASE_CODE)
            #if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6,4)
            	unsigned long kallsyms_lookup_name(const char *name)
	        	{
		    		return 0;
	        	}
            #else
            	extern unsigned long kallsyms_lookup_name(const char *name);
	    	#endif
        #else
            #if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
                unsigned long kallsyms_lookup_name(const char *name)
	        	{
		    		return 0;
	        	}
            #else
                extern unsigned long kallsyms_lookup_name(const char *name);
            #endif
        #endif

        static long* get_sys_call_table(void)
        {
            struct _idt_descriptor * idt;
            struct _idtr idtr;
            unsigned int sys_call_off;
            int sys_call_table=0;
            unsigned char* p;
            int i;

            asm("sidt %0":"=m"(idtr));
            printk("addr of idtr: 0x%x\n", (unsigned int)&idtr);
            idt=(struct _idt_descriptor *)(idtr.base+8*0x80);
            sys_call_off=((unsigned int )(idt->offset_high<<16)|(unsigned int )idt->offset_low);
            printk("addr of idt 0x80: 0x%x\n", sys_call_off);
            p=(unsigned char *)sys_call_off;
            for (i=0; i<100; i++)
            {
                if (p[i]==0xff && p[i+1]==0x14 && p[i+2]==0x85)
                {
                    sys_call_table=*(int*)((int)p+i+3);
                    printk("addr of sys_call_table: 0x%x\n", sys_call_table);
                    return (long*)sys_call_table;
                }
            }
            return 0;
        }


        static void** find_sys_call_table(void)
        {
            void** pcall_table = NULL;

            pcall_table = (void**)get_sys_call_table();
            if(!pcall_table) {
                //查不到，再用kallsyms_lookup_name找一次
                pcall_table = (void**)kallsyms_lookup_name("sys_call_table");
            }

            return pcall_table;
        }
    #else

    #if defined(__x86_64__) && (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,38) )
        static int kallsyms_cb_fn(void * data, const char *syms, 
                                struct module * mod,
                                unsigned long addr)
        {
            int bmatch = 0;
            const char *name = (char*)(*(unsigned long*)data);
            unsigned long *sym_addr = ((unsigned long*)data + 1);

            bmatch = (0 == strcmp(name, syms));
            if(bmatch) { *sym_addr = addr; }

            return bmatch;
        }

        unsigned long kallsyms_lookup_name(const char *name)
        {
            int rc = 0;
            unsigned long data[2] = {(unsigned long)name, 0};

            rc = kallsyms_on_each_symbol(kallsyms_cb_fn, data);
            if (1 ==  rc)
                return data[1];

            return 0ul;
        }
    #else
        #if defined(__mips__) && (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32) )
            unsigned long kallsyms_lookup_name(const char *name)
	        	{
		    		return 0;
	        	}
        #else 
		    #if defined(KYLIN_ARM_232X) || (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0) )
                unsigned long kallsyms_lookup_name(const char *name)
		            {   
				        return 0;
		            }
			#else
            	extern unsigned long kallsyms_lookup_name(const char *name);
		    #endif
        #endif
    #endif

		static const char* get_sys_close_name(void)
		{
			const char* name = "sys_close";
			
            //目前只有arm64需要这样做，x64,mips64上不会走到这里
            //并且高版本内核的x64系统，此处要返回NULL，让其查找失败
            //不然调用find_sys_call_table2时会崩溃
            #ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
				#ifdef __aarch64__
					name = "__arm64_sys_close";
                #else
                    name = NULL;
				#endif
			#endif	
			
			return name;
		}

        //高版本的x64不应该走到这个函数调用处
        static void** find_sys_call_table2(void)
        {
            unsigned long ptr = 0;
            unsigned long pend = 0;
            unsigned long *p  = NULL;
        	void** pcall_table = NULL;
            unsigned long psys_close = 0;
			const char* sys_close_name = "sys_close";

			sys_close_name = get_sys_close_name();
            if(!sys_close_name) {
                LOG_ERROR("can't get valid sys_close name\n");
                return pcall_table;
            }

            psys_close = (unsigned long)kallsyms_lookup_name(sys_close_name);
            if(!psys_close) {
                LOG_ERROR("failed to find address of %s\n",sys_close_name);
                return pcall_table;
            }

			LOG_INFO("find syscall table2,sys_close_name: %s,addr: %lu\n",
                sys_close_name,psys_close);
            pend = (unsigned long)&loops_per_jiffy;
            for (ptr = psys_close;ptr < pend;ptr += sizeof(void*)) {
                p = (unsigned long*)ptr;
                if (p[__NR_close] == psys_close) {
                    pcall_table = (void**) p;
                    break;
                }
            }

            return pcall_table;
        }

        static void** find_sys_call_table(void)
        {
        	void** pcall_table = NULL;
           
        	pcall_table = (void**)kallsyms_lookup_name("sys_call_table");
            if (pcall_table) { goto out; }

            pcall_table = find_sys_call_table2();
            if(pcall_table) { goto out; }

            //这个主要针对凝思4.2.40 2.6.32-41 x86_64的系统
            pcall_table = find_sys_call_table3();
            
        out:
        	return pcall_table;
        }
    #endif
#endif
