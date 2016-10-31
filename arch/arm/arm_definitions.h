#ifndef __ARM_DEFINITIONS_H
#define __ARM_DEFINITIONS_H

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

