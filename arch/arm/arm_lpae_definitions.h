#ifndef __ARM_LPAE_DEFINITIONS_H
#define __ARM_LPAE_DEFINITIONS_H

static pgd_t *get_global_pgd (void)
{
	unsigned long ttb_reg, low, high;
	
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
