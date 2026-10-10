/*
 *hook_arm64.c: 2019-07-24 created by qudreams
 *for arm64 hook syscalls
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include "khookframe.h"

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
	static pte_t* pbm_pte = NULL;
	static char* pstart_rodata = NULL;
	static char* pinit_begin = NULL;
	static bool* prodata_enabled = NULL;
	static struct mm_struct *pinit_mm = NULL;

	static inline bool use_1G_block(unsigned long addr, unsigned long next,
				unsigned long phys)
	{
		if (PAGE_SHIFT != 12)
			return false;

		if (((addr | next | phys) & ~PUD_MASK) != 0)
			return false;

		return true;
	}


	#define NO_BLOCK_MAPPINGS	BIT(0)
	#define NO_CONT_MAPPINGS	BIT(1)

	static bool pgattr_change_is_safe(u64 old, u64 new)
	{
		/*
		* The following mapping attributes may be updated in live
		* kernel mappings without the need for break-before-make.
		*/
		static const pteval_t mask = PTE_PXN | PTE_RDONLY | PTE_WRITE;

		/* creating or taking down mappings is always safe */
		if (old == 0 || new == 0)
			return true;

		/* live contiguous mappings may not be manipulated at all */
		if ((old | new) & PTE_CONT)
			return false;

		return ((old ^ new) & ~mask) == 0;
	}

	static void init_pte(pmd_t *pmd, unsigned long addr, unsigned long end,
				phys_addr_t phys, pgprot_t prot)
	{
		pte_t *pte = NULL;

		pte = pte_set_fixmap_offset(pmd, addr);
		do {
			pte_t old_pte = *pte;

			set_pte(pte, pfn_pte(__phys_to_pfn(phys), prot));

			/*
			* After the PTE entry has been populated once, we
			* only allow updates to the permission attributes.
			*/
			BUG_ON(!pgattr_change_is_safe(pte_val(old_pte), pte_val(*pte)));

			phys += PAGE_SIZE;
		} while (pte++, addr += PAGE_SIZE, addr != end);

		pte_clear_fixmap();
	}

	static void alloc_init_cont_pte(pmd_t *pmd, unsigned long addr,
					unsigned long end, phys_addr_t phys,
					pgprot_t prot,
					phys_addr_t (*pgtable_alloc)(void),
					int flags)
	{
		unsigned long next;

		BUG_ON(pmd_sect(*pmd));
		if (pmd_none(*pmd)) {
			phys_addr_t pte_phys;
			BUG_ON(!pgtable_alloc);
			pte_phys = pgtable_alloc();
			__pmd_populate(pmd, pte_phys, PMD_TYPE_TABLE);
		}
		BUG_ON(pmd_bad(*pmd));

		do {
			pgprot_t __prot = prot;

			next = pte_cont_addr_end(addr, end);

			/* use a contiguous mapping if the range is suitably aligned */
			if ((((addr | next | phys) & ~CONT_PTE_MASK) == 0) &&
				(flags & NO_CONT_MAPPINGS) == 0)
				__prot = __pgprot(pgprot_val(prot) | PTE_CONT);

			init_pte(pmd, addr, next, phys, __prot);

			phys += next - addr;
		} while (addr = next, addr != end);
	}

	static void init_pmd(pud_t *pud, unsigned long addr, unsigned long end,
				phys_addr_t phys, pgprot_t prot,
				phys_addr_t (*pgtable_alloc)(void), int flags)
	{
		unsigned long next;
		pmd_t *pmd;

		pmd = pmd_set_fixmap_offset(pud, addr);
		do {
			pmd_t old_pmd = *pmd;

			next = pmd_addr_end(addr, end);

			/* try section mapping first */
			if (((addr | next | phys) & ~SECTION_MASK) == 0 &&
				(flags & NO_BLOCK_MAPPINGS) == 0) {
				pmd_set_huge(pmd, phys, prot);

				/*
				* After the PMD entry has been populated once, we
				* only allow updates to the permission attributes.
				*/
				BUG_ON(!pgattr_change_is_safe(pmd_val(old_pmd),
								pmd_val(*pmd)));
			} else {
				alloc_init_cont_pte(pmd, addr, next, phys, prot,
							pgtable_alloc, flags);

				BUG_ON(pmd_val(old_pmd) != 0 &&
					pmd_val(old_pmd) != pmd_val(*pmd));
			}
			phys += next - addr;
		} while (pmd++, addr = next, addr != end);

		pmd_clear_fixmap();
	}

	static void alloc_init_cont_pmd(pud_t *pud, unsigned long addr,
					unsigned long end, phys_addr_t phys,
					pgprot_t prot,
					phys_addr_t (*pgtable_alloc)(void), int flags)
	{
		unsigned long next;

		/*
		* Check for initial section mappings in the pgd/pud.
		*/
		BUG_ON(pud_sect(*pud));
		if (pud_none(*pud)) {
			phys_addr_t pmd_phys;
			BUG_ON(!pgtable_alloc);
			pmd_phys = pgtable_alloc();
			__pud_populate(pud, pmd_phys, PUD_TYPE_TABLE);
		}
		BUG_ON(pud_bad(*pud));

		do {
			pgprot_t __prot = prot;

			next = pmd_cont_addr_end(addr, end);

			/* use a contiguous mapping if the range is suitably aligned */
			if ((((addr | next | phys) & ~CONT_PMD_MASK) == 0) &&
				(flags & NO_CONT_MAPPINGS) == 0)
				__prot = __pgprot(pgprot_val(prot) | PTE_CONT);

			init_pmd(pud, addr, next, phys, __prot, pgtable_alloc, flags);

			phys += next - addr;
		} while (addr = next, addr != end);
	}

	int pud_set_huge(pud_t *pud, phys_addr_t phys, pgprot_t prot)
	{
		BUG_ON(phys & ~PUD_MASK);
		set_pud(pud, __pud(phys | PUD_TYPE_SECT | pgprot_val(mk_sect_prot(prot))));
		return 1;
	}

	int pmd_set_huge(pmd_t *pmd, phys_addr_t phys, pgprot_t prot)
	{
		BUG_ON(phys & ~PMD_MASK);
		set_pmd(pmd, __pmd(phys | PMD_TYPE_SECT | pgprot_val(mk_sect_prot(prot))));
		return 1;
	}


	static void alloc_init_pud(pgd_t *pgd, unsigned long addr, unsigned long end,
					phys_addr_t phys, pgprot_t prot,
					phys_addr_t (*pgtable_alloc)(void),
					int flags)
	{
		pud_t *pud;
		unsigned long next;

		if (pgd_none(*pgd)) {
			phys_addr_t pud_phys;
			BUG_ON(!pgtable_alloc);
			pud_phys = pgtable_alloc();
			__pgd_populate(pgd, pud_phys, PUD_TYPE_TABLE);
		}
		BUG_ON(pgd_bad(*pgd));

		pud = pud_set_fixmap_offset(pgd, addr);
		do {
			pud_t old_pud = *pud;

			next = pud_addr_end(addr, end);

			/*
			* For 4K granule only, attempt to put down a 1GB block
			*/
			if (use_1G_block(addr, next, phys) &&
				(flags & NO_BLOCK_MAPPINGS) == 0) {
				pud_set_huge(pud, phys, prot);

				/*
				* After the PUD entry has been populated once, we
				* only allow updates to the permission attributes.
				*/
				BUG_ON(!pgattr_change_is_safe(pud_val(old_pud),
								pud_val(*pud)));
			} else {
				alloc_init_cont_pmd(pud, addr, next, phys, prot,
							pgtable_alloc, flags);

				BUG_ON(pud_val(old_pud) != 0 &&
					pud_val(old_pud) != pud_val(*pud));
			}
			phys += next - addr;
		} while (pud++, addr = next, addr != end);

		pud_clear_fixmap();
	}

	static inline pte_t * fixmap_pte(unsigned long addr)
	{
		return &pbm_pte[pte_index(addr)];
	}


	void __set_fixmap(enum fixed_addresses idx,
					phys_addr_t phys, pgprot_t flags)
	{
		unsigned long addr = __fix_to_virt(idx);
		pte_t *pte;

		BUG_ON(idx <= FIX_HOLE || idx >= __end_of_fixed_addresses);

		pte = fixmap_pte(addr);

		if (pgprot_val(flags)) {
			set_pte(pte, pfn_pte(phys >> PAGE_SHIFT, flags));
		} else {
			pte_clear(&init_mm, addr, pte);
			flush_tlb_kernel_range(addr, addr+PAGE_SIZE);
		}
	}


	static void __create_pgd_mapping(pgd_t *pgdir, phys_addr_t phys,
					unsigned long virt, phys_addr_t size,
					pgprot_t prot,
					phys_addr_t (*pgtable_alloc)(void),
					int flags)
	{
		unsigned long addr, length, end, next;
		pgd_t *pgd = pgd_offset_raw(pgdir, virt);

		/*
		* If the virtual and physical address don't have the same offset
		* within a page, we cannot map the region as the caller expects.
		*/
		if (WARN_ON((phys ^ virt) & ~PAGE_MASK))
			return;

		phys &= PAGE_MASK;
		addr = virt & PAGE_MASK;
		length = PAGE_ALIGN(size + (virt & ~PAGE_MASK));

		end = addr + length;
		do {
			next = pgd_addr_end(addr, end);
			alloc_init_pud(pgd, addr, next, phys, prot, pgtable_alloc,
					flags);
			phys += next - addr;
		} while (pgd++, addr = next, addr != end);
	}

	static void update_mapping_prot(phys_addr_t phys, unsigned long virt,
					phys_addr_t size, pgprot_t prot)
	{
		if (virt < VMALLOC_START) {
			pr_warn("BUG: not updating mapping for %pa at 0x%016lx - outside kernel range\n",
				&phys, virt);
			return;
		}

		__create_pgd_mapping(pinit_mm->pgd, phys, virt, size, prot, NULL,
					NO_CONT_MAPPINGS);

		/* flush the TLBs after updating live kernel mappings */
		flush_tlb_kernel_range(virt, virt + size);
	}

	//disable write protect
	//don't care return value
	static int disable_arm64_wp(unsigned long* pflags)
	{
		int rc = 0;
		unsigned long section_size;
		if(*prodata_enabled == 0) { return rc; }

		/*
		* mark .rodata as read only. Use __init_begin rather than __end_rodata
		* to cover NOTES and EXCEPTION_TABLE.
		*/
		section_size = (unsigned long)pinit_begin - (unsigned long)pstart_rodata;
		update_mapping_prot(__pa_symbol(pstart_rodata), (unsigned long)pstart_rodata,
					section_size, PAGE_KERNEL_EXEC);
		return rc;
	}

	//enable write protect
	static void restore_arm64_wp(unsigned long val)
	{
		unsigned long section_size;

		(void)val;
		if(*prodata_enabled == 0) { return; }
		/*
		* mark .rodata as read only. Use __init_begin rather than __end_rodata
		* to cover NOTES and EXCEPTION_TABLE.
		*/
		section_size = (unsigned long)pinit_begin - (unsigned long)pstart_rodata;
		update_mapping_prot(__pa_symbol(pstart_rodata), (unsigned long)pstart_rodata,
					section_size, PAGE_KERNEL_ROX);
	}

	static int set_arm64_ksym_addr(const char* symname,
							unsigned long addr)
	{ 
		(void)symname; (void)addr; 
		return -EAGAIN;
	}
	//do hook init by cpu architecture
	static int init_arm64_hook(void)
	{
		int rc = -EFAULT;

		LOG_INFO("init hook arm64 kallsyms\n");
		/* can be directly found in kernel memory */
		pinit_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
		if(pinit_mm == NULL) {
			LOG_ERROR("hook_arm64 can't find init_mm\n");
			return rc;
		}
		LOG_INFO("hook_arm64 init_mm: %p\n",pinit_mm);

		pinit_begin = (char*)kallsyms_lookup_name("__init_begin");
		if(pinit_begin == NULL) {
			LOG_ERROR("hook_arm64 can't find __init_begin\n");
			return rc;
		}
		LOG_INFO("hook_arm64 init begin: %p\n",pinit_begin);

		pstart_rodata = (char*)kallsyms_lookup_name("__start_rodata");
		if(pstart_rodata == NULL) {
			LOG_ERROR("hook_arm64 can't find __start_rodata\n");
			return rc;
		}
		LOG_INFO("hook_arm64 start_ro_data: %p\n",pstart_rodata);

		pbm_pte = (pte_t*)kallsyms_lookup_name("bm_pte");
		if(pbm_pte == NULL) {
			LOG_ERROR("hook_arm64 can't find bm_pte\n");
			return rc;
		}
		LOG_INFO("hook_arm64 bm_pte: %p\n",pbm_pte);

		prodata_enabled = (bool*)kallsyms_lookup_name("rodata_enabled");
		if(prodata_enabled == NULL) {
			LOG_ERROR("hook_arm64 can't find rodata_enabled\n");
			return rc;
		}
		LOG_INFO("hook_arm64 rodata_enabled,address: %p,value: %d\n",
				prodata_enabled,*prodata_enabled);

		rc = 0;
		LOG_INFO("hook_arm64 kallsyms init success\n");
		return rc;
	}

	static void uninit_arm64_hook(void) {}

	static struct hook_arch_operations arm64_hao = {
		.name = "arm64_kallsyms_hook",
		.fn_init = init_arm64_hook,
		.fn_uninit = uninit_arm64_hook,
		.fn_disable_wp = disable_arm64_wp,
		.fn_restore_wp = restore_arm64_wp,
		.fn_set_ksym_addr = set_arm64_ksym_addr,
	};

	static struct hook_arch_operations* pha_operation = &arm64_hao;
#else
	static struct hook_arch_operations* pha_operation = &def_hao;
#endif
