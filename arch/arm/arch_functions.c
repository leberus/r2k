#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/printk.h>

#ifdef CONFIG_ARM64
#include "arm64_definitions.h"
#elif defined CONFIG_ARM_LPAE
#include "arm_lpae_definitions.h"
#else
#include "arm_definitions.h"
#endif

#ifndef pmd_sect
# define pmd_sect(x)		((pmd_val(x) & PMD_TYPE_MASK) == PMD_TYPE_SECT)
#endif

#ifndef pmd_table
# define pmd_table(x)		((pmd_val(x) & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
#endif

#if !defined (pmd_write) && !defined (CONFIG_DEBUG_RODATA)
#  define pmd_write(x)		(1)
#endif

#define PAGE_IS_RW(x)           pte_write(x)
#define PAGE_IS_PRESENT(x)      pte_present(x)

#define WRITE_TYPE	 	0x1
#define PRESENT_TYPE		0x2

static char *r2_devname = "r2k";	

static pud_t *lookup_address (unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	
	pgd = get_global_pgd() + pgd_index (addr);
	if (pgd_bad (*pgd)) 
		return NULL;
	
	pud = pud_offset (pgd, addr);
	return pud;
}

static pud_t *virt_to_pud (unsigned long addr)
{
	return lookup_address (addr);
}

static int check_addr (unsigned long addr, int type)
{
	pud_t *pud;
	pmd_t *pmd;

	pud = virt_to_pud (addr);
	if (pud == NULL || pud_none (*pud)) {
		pr_info ("%s: pud null\n", r2_devname);
		return 0;
	}

#if defined (CONFIG_ARM64) && !defined (CONFIG_ANDROID)
	if (pud_sect (*pud)) {
		pr_info ("%s: pud_section\n", r2_devname);
		return type == WRITE_TYPE
				? pud_write (*pud) 
				: pud_present (*pud);
	}
#endif
	pmd = pmd_offset (pud, addr);
	if (!pmd_none (*pmd)) {
		if (pmd_sect (*pmd)) {
			pr_info ("%s: pmd_sect\n", r2_devname);
			return type == WRITE_TYPE
				? pmd_write (*pmd)
				: pmd_present (*pmd);  
		}

		if (pmd_table (*pmd)) {
			pr_info ("%s: pmd_table\n", r2_devname);
			pte_t *pte = pte_offset_kernel (pmd, addr);
			return type == WRITE_TYPE
				? PAGE_IS_RW (*pte)
				: PAGE_IS_PRESENT (*pte);
		}
	}

	return 0;
}
	
int addr_is_writeable (unsigned long addr)
{
	return check_addr (addr, WRITE_TYPE);
}

int addr_is_mapped (unsigned long addr)
{
	return check_addr (addr, PRESENT_TYPE);
}

