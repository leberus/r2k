#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <linux/proc_fs.h>
#include "arm_definitions.h"
#include "dump_pagetables.h"


/*	
	Most of the code it has been taken from arch/-/mm/dump.c
	Here has just been added additional code to supply physical addresses 
*/
	
static void dump_prot(struct pg_state *st, const struct prot_bits *bits, size_t num)
{
        unsigned i;

        for (i = 0; i < num; i++, bits++) {
                const char *s;

                if ((st->current_prot & bits->mask) == bits->val)
                        s = bits->set;
                else
                        s = bits->clear;

                if (s) 
                        seq_printf(st->seq, " %s", s);
        }
}

static void note_page(struct pg_state *st, unsigned long addr, unsigned level, u64 val)
{
        static const char units[] = "KMGTPE";
        u64 prot = val & pg_level[level].mask;
	int nr_pages;

        if (!st->level) {
                st->level = level;
                st->current_prot = prot;
                seq_printf(st->seq, "---[ %s ]---\n", st->marker->name);
        } else if (prot != st->current_prot || level != st->level ||
                   addr >= st->marker[1].start_address) {
                const char *unit = units;
                unsigned long delta;

                if (st->current_prot) {
                        seq_printf(st->seq, "0x%08lx-0x%08lx   ",
                                   st->start_address, addr); 

                        delta = (addr - st->start_address) >> 10;
                        while (!(delta & 1023) && unit[1]) {
                                delta >>= 10;
                                unit++;
                        }
                        seq_printf(st->seq, "%9lu%c ", delta, *unit);
                        if (pg_level[st->level].bits) 
                                dump_prot(st, pg_level[st->level].bits, pg_level[st->level].num);

			nr_pages = (addr - st->start_address) / PAGE_SIZE;
			if (st->marker->start_address == PAGE_OFFSET ||
				st->marker->start_address == VMALLOC_START ||
				st->marker->start_address == MODULES_VADDR) {
				int i;
				unsigned long aux_addr;

				seq_printf (st->seq, "\n\t");
				if (st->marker->start_address == PAGE_OFFSET) {
					seq_printf(st->seq, "  phys: {  0x%08llx-0x%08llx  }",
								__pa (st->start_address),
								__pa (addr));
				} else if ((st->marker->start_address == VMALLOC_START ||
					st->marker->start_address == MODULES_VADDR) &&
			      		level == 4)	{
					seq_printf (st->seq, "  phys: {\n\t\t");
					for (i = 0, aux_addr = st->start_address; 
								i < nr_pages ; 
							i++, aux_addr += PAGE_SIZE) {
						unsigned long pfn = vmalloc_to_pfn ((void *) aux_addr);
						
						if (i > 3 && !(i & ~(~0x3L)))
							seq_printf (st->seq, "\n\t\t");
						if (!pfn_valid (pfn))
							seq_printf (st->seq, " NULL");
						else
							seq_printf (st->seq, " 0x%08lx", (pfn << PAGE_SHIFT));
					}
					seq_printf (st->seq, "\n\t\t}");
				} 
			}
			
                        seq_printf(st->seq, "\n\n"); 
                }

                if (addr >= st->marker[1].start_address) {
                        st->marker++;
                        seq_printf(st->seq, "---[ %s ]---\n", st->marker->name);
                }
                st->start_address = addr;
                st->current_prot = prot;
                st->level = level;
        }

#ifdef CONFIG_ARM64
	if (addr >= st->marker[1].start_address) {
		st->marker++;
		seq_printf (st->seq, "---[%s]---\n", st->marker->name);
	}
#endif
}

static void walk_pte(struct pg_state *st, pmd_t *pmd, unsigned long start)
{
        pte_t *pte = pte_offset_kernel(pmd, 0);
        unsigned long addr;
        unsigned i;

        for (i = 0; i < PTRS_PER_PTE; i++, pte++) {
                addr = start + i * PAGE_SIZE;
                note_page(st, addr, 4, pte_val(*pte));
        }
}

static void walk_pmd(struct pg_state *st, pud_t *pud, unsigned long start)
{
        pmd_t *pmd = pmd_offset(pud, 0);
        unsigned long addr;
        unsigned i;

        for (i = 0; i < PTRS_PER_PMD; i++, pmd++) {
                addr = start + i * PMD_SIZE;
#ifdef CONFIG_ARM64
		if (pmd_none(*pmd) || pmd_sect (*pmd))
#else
		if (pmd_none(*pmd) || pmd_large(*pmd) || !pmd_present(*pmd))
#endif
                        note_page(st, addr, 3, pmd_val(*pmd));
                else
                        walk_pte(st, pmd, addr);

#ifdef CONFIG_ARM
                if (SECTION_SIZE < PMD_SIZE && pmd_large(pmd[1]))
                        note_page(st, addr + SECTION_SIZE, 3, pmd_val(pmd[1]));
#endif
        }
}

static void walk_pud(struct pg_state *st, pgd_t *pgd, unsigned long start)
{
        pud_t *pud = pud_offset(pgd, 0);
        unsigned long addr;
        unsigned i;

        for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
                addr = start + i * PUD_SIZE;
#ifdef CONFIG_ARM64
		if (pud_none (*pud) || pud_sect (*pud)) 
			note_page (st, addr, 2, pud_val (*pud));
		else
		       	walk_pmd (st, pud, addr);	
#else
                if (!pud_none(*pud))
			walk_pmd (st, pud, addr);
		else
			note_page (st, addr, 2, pud_val (*pud));
#endif
        }
}

static void walk_pgd(struct seq_file *m)
{
        pgd_t *pgd;
        struct pg_state st;
        unsigned long addr;
        unsigned i;

        memset(&st, 0, sizeof(st));
        st.seq = m;
        st.marker = address_markers;

	pgd = get_global_pgd ();

        for (i = 0; i < PTRS_PER_PGD; i++, pgd++) {
#ifdef CONFIG_ARM64
                addr = VA_START + i * PGDIR_SIZE;
#else
		addr = i * PGDIR_SIZE;
#endif
                if (!pgd_none(*pgd)) {
                        walk_pud(&st, pgd, addr);
                } else {
                        note_page(&st, addr, 1, pgd_val(*pgd));
                }
        }

        note_page(&st, 0, 0, 0);
}

static int pg_dump_show(struct seq_file *m, void *v)
{
        walk_pgd(m);
        return 0;
}

static int pg_dump_open(struct inode *inode, struct file *file)
{
        return single_open(file, pg_dump_show, NULL);
}

static const struct file_operations pg_dump_fops = {
        .open           = pg_dump_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
};

int pg_dump(void)
{
        unsigned i, j;

        for (i = 0; i < ARRAY_SIZE(pg_level); i++)
                if (pg_level[i].bits)
                        for (j = 0; j < pg_level[i].num; j++)
                                pg_level[i].mask |= pg_level[i].bits[j].mask;

#ifdef CONFIG_ARM
        address_markers[2].start_address = VMALLOC_START;
#endif
	if (proc_create ("r2k_kernel_pagetables", 
				0, NULL, &pg_dump_fops) == NULL) {
		pr_info ("NULL\n");
		return -1;
	}
	return 0;
}

void pg_dump_remove_entry(void)
{
	remove_proc_entry ("r2k_kernel_pagetables", NULL);
}
