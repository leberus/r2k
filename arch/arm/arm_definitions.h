#ifndef __ARM_DEFINITIONS_H
#define __ARM_DEFINITIONS_H

#ifndef pmd_sect
#  define pmd_sect(x)		((pmd_val(x) & PMD_TYPE_MASK) == PMD_TYPE_SECT)
#endif

#ifndef pmd_table
#  define pmd_table(x)		((pmd_val(x) & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
#endif

#ifndef pmd_write
#   define pmd_write(x)		(pmd_val(x) & PMD_SECT_AP_WRITE)
#endif

#define PAGE_IS_RW(x)		pte_write(x)
#define PAGE_IS_PRESENT(x)	pte_present(x)

static pgd_t *get_global_pgd (void)
{
	unsigned long ttb_reg;

	asm volatile (
	"       mrc     p15, 0, %0, c2, c0, 1"
	: "=r" (ttb_reg));
	ttb_reg &= ~0x3fff;

	return __va (ttb_reg);
}
#endif	

