#ifndef __ARM_LPAE_DEFINITIONS_H
#define __ARM_LPAE_DEFINITIONS_H

#ifndef pmd_sect
#  define pmd_sect(x)		((pmd_val(x) & PMD_TYPE_MASK) == PMD_TYPE_SECT)
#endif

#ifndef pmd_table
#  define pmd_table(x)		((pmd_val(x) & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
#endif

#ifndef pmd_write && defined (PMD_SECT_RDONLY)
#  define pmd_write(x)		(pmd_val(x) & PMD_SECT_RDONLY)
#endif

#define PAGE_IS_RW(x)		!(pte_val(x) & PTE_RDONLY)
#define PAGE_IS_PRESENT(x)	pte_present(x)

static pgd_t *get_global_pgd (void)
{
	unsigned long ttb_reg, how, high;
	
	asm volatile (
	"       mrrc    p15, 1, %0, %1, c2"
	: "=r" (low), "=r" (high)
	:
	: "cc");
	
	ttb_reg = low;
	if (PAGE_OFFSET == 0x80000000)
		ttb_reg -= (1 << 4);
	else if (PAGE_OFFSET == 0xc0000000)
		ttb_reg -= (16 << 10);
	ttb_reg &= ~(PTRS_PER_PGD*sizeof(pgd_t)-1);
	
	return __va (ttb_reg);
}
#endif
