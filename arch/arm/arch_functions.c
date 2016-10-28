#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/printk.h>

#if defined (CONFIG_ARM) || defined (CONFIG_ANDROID)

# ifndef pmd_sect
#  define pmd_sect(x)           ((pmd_val(x) & PMD_TYPE_MASK) == PMD_TYPE_SECT)
# endif

# ifndef pmd_table
#  define pmd_table(x)          ((pmd_val(x) & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
# endif

# ifndef pmd_write
#  if defined (CONFIG_ARM_LPAE) && defined (PMD_SECT_RDONLY)
#   define pmd_write(x)         (pmd_val(x) & PMD_SECT_RDONLY)
#  else
#   define pmd_write(x)         (pmd_val(x) & PMD_SECT_AP_WRITE)
#  endif
# endif

# ifdef CONFIG_ARM
#  define PAGE_IS_RW(x)         pte_write(x)
# else
#  define PAGE_IS_RW(x)         !(pte_val(x) & PTE_RDONLY)
# endif

# define PAGE_IS_PRESENT(x)     pte_present(x)

#elif defined CONFIG_ARM64
# define PAGE_IS_PRESENT(x)     pte_present(x)
# define PAGE_IS_RW(x)          pte_write(x)
#endif 

#define WRITE_TYPE	 	0x1
#define PRESENT_TYPE		0x2

static char *r2_devname = "r2k";	

static pgd_t *get_global_pgd (void)
{
	pgd_t *pgd;
	unsigned long ttb_reg;

#ifdef CONFIG_ARM
# ifdef CONFIG_ARM_LPAE                         /* arm with LPAE */
	unsigned long low, high;

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
# else                                          /* arm */
        asm volatile (
        "       mrc     p15, 0, %0, c2, c0, 1"
        : "=r" (ttb_reg));
        ttb_reg &= ~0x3fff;
# endif
#else                                           /* arm64 */
        asm volatile (
        "       mrs     %0, TTBR1_EL1"
        : "=r" (ttb_reg));
        ttb_reg &= (0xffffffffffffffff << 0x9);
#endif
        pgd = __va (ttb_reg);
        pr_info ("%s: get_global_pgd: 0x%0llx - %p\n", r2_devname, pgd_val (*pgd), pgd);
        return pgd;
}

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

