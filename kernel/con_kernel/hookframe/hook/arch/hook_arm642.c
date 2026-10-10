/*
 *hook_arm64.c: 2019-07-24 created by qudreams
 *for arm64 hook syscalls
 *针对内核符号未导出的情况
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include "khookframe.h"

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
	static char* pstart_rodata = NULL;
	static char* pinit_begin = NULL;
	static bool* prodata_enabled = NULL;
    //内核偏移地址，在开启地址随机化后
    //计算内核地址需要加上这个偏移量
    static u_long __kaddr_offset = 0;
    //update_mapping_prot函数在System.map文件中的地址
    //ump is a shortname for update_mapping_prot
	static void* __sysmap_addr_ump = NULL; 

	typedef struct {
		const char* name;
		void** pvalue;
	}ksym_value_t;

	static ksym_value_t ksyms[] = {
		{"__init_begin", (void**)&pinit_begin},
		{"__start_rodata", (void**)&pstart_rodata},
		{"rodata_enabled", (void**)&prodata_enabled},
        {"update_mapping_prot",(void**)&__sysmap_addr_ump},
	};

	void (*pupdate_mapping_prot)(phys_addr_t phys, unsigned long virt,
					phys_addr_t size, pgprot_t prot);
	//disable write protect
	static int disable_arm64_wp(unsigned long* pflags)
	{
		int rc = -EAGAIN;
		char* pend = NULL;
		char* pstart = NULL;
		unsigned long section_size;
		(void)pflags;

		if(!prodata_enabled) {
			return rc;
		}

		rc = 0;
		if(!*prodata_enabled) {
			return rc;
		}

		(void)xchg(&pend,pinit_begin);
		(void)xchg(&pstart,pstart_rodata);
	
		if(!pend || !pstart) {
			rc = -EINVAL;
			return rc;
		}
		/*
		* mark .rodata as read only. Use __init_begin rather than __end_rodata
		* to cover NOTES and EXCEPTION_TABLE.
		*/
		section_size = (unsigned long)pend - (unsigned long)pstart;
		pupdate_mapping_prot(__pa_symbol(pstart), (unsigned long)pstart,
					section_size, PAGE_KERNEL_EXEC);
		return rc;
	}

	//enable write protect
	void restore_arm64_wp(unsigned long val)
	{
		char* pend = NULL;
		char* pstart = NULL;
		unsigned long section_size;
		(void)val;

		if(!prodata_enabled) { return; }
		if(!*prodata_enabled) { return; }

		(void)xchg(&pend,pinit_begin);
		(void)xchg(&pstart,pstart_rodata);

		if(!pend || !pstart) {
			return;
		}

		/*
		* mark .rodata as read only. Use __init_begin rather than __end_rodata
		* to cover NOTES and EXCEPTION_TABLE.
		*/
		section_size = (unsigned long)pend - (unsigned long)pstart;
		pupdate_mapping_prot(__pa_symbol(pstart), (unsigned long)pstart,
					section_size, PAGE_KERNEL_RO);
	}

	//初始化时设置需要的符号地址，有些符号地址在内核中拿不到
	//需要应用层在初始化时设置进来
	static int set_arm64_ksym_addr(const char* symname,
					unsigned long addr)
	{
		size_t i = 0;
		int rc = -EAGAIN;
		void** pvalue = NULL;
		size_t size = ARRAY_SIZE(ksyms);

		LOG_INFO("symname:%s addr:%lx\n",symname, addr);

		for(i = 0;i < size;i++) {
			if(!strcmp(symname,ksyms[i].name)) {
				pvalue = ksyms[i].pvalue;
				break;
			}
		}

		if(pvalue) {
			xchg(pvalue,(void*)addr);
			if (pupdate_mapping_prot) rc = 0;
			LOG_INFO("set symname:%s *pvalue:%p successfully\n",
					symname, *pvalue);
		}

		return rc;
	}

    extern int hook_search_ksym(const char *sym_name, unsigned long *sym_addr);
    static void refix_arm64_ksym_addr(void)
    {
        long val = 0;
        size_t i = 0;
        size_t size = ARRAY_SIZE(ksyms);

        //linux5.7.0及之后版本此值为空,需从 kallsyms 中查找
        if (!pupdate_mapping_prot) {
            int rc = hook_search_ksym("update_mapping_prot", (unsigned long *)&pupdate_mapping_prot);
            if (rc || !pupdate_mapping_prot) return;
        }
        val = (long)pupdate_mapping_prot - (long)__sysmap_addr_ump;
        __kaddr_offset =  abs(val);

		LOG_INFO("kaddr offset: %lx\n",val);

		for(i = 0;i < size;i++) {
            void** pvalue = NULL;
			pvalue = ksyms[i].pvalue;
            *pvalue += __kaddr_offset;

            LOG_INFO("fixed ksym-addr of %s to: %lx\n",
               ksyms[i].name,(long)*pvalue);
		}
    }

	//do hook init by cpu architecture
	static int init_arm64_hook(void)
	{
		int rc = 0;

		LOG_INFO("init hook arm64 no-kallsyms\n");

		//内核版本5.7.0及之后未导出 kallsyms_lookup_name
		//需使用 fn_set_ksym_addr 和 fn_refix_ksym_addr 设置地址
		pupdate_mapping_prot = (void*)kallsyms_lookup_name("update_mapping_prot");
		if(!pupdate_mapping_prot) {
			LOG_ERROR("hook_arm64 can't find update_mapping_prot\n");
			return rc;
		}

		LOG_INFO("hook_arm64 update_mapping_prot fun: %p\n", 
				pupdate_mapping_prot);

		rc = 0;
		LOG_INFO("hook_arm64 no-kallsyms init success\n");
		return rc;
	}

	static void uninit_arm64_hook(void) {}

	static struct hook_arch_operations arm64_hao = {
		.name = "arm64_nokallsyms_hook",
		.fn_init = init_arm64_hook,
		.fn_uninit = uninit_arm64_hook,
		.fn_disable_wp = disable_arm64_wp,
		.fn_restore_wp = restore_arm64_wp,
		.fn_set_ksym_addr = set_arm64_ksym_addr,
        .fn_refix_ksym_addr = refix_arm64_ksym_addr,
	};
	static struct hook_arch_operations* pha_operation = &arm64_hao;
#else
	static struct hook_arch_operations* pha_operation = &def_hao;
#endif
