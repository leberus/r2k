#ifndef __R2K_H
#define __R2K_H

#include <linux/version.h>

static char *r2_devname = "r2k";

#define  R2_CLASS_NAME  "r2k"
static struct device *r2k_dev_ph;
static struct class *r2k_class;
static struct cdev *r2k_dev;
static dev_t devno;

#define R2_TYPE 0x69

/* Memory Part */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
#define get_user_pages          get_user_pages_remote
#define page_cache_release      put_page
#endif

#define ADDR_OFFSET(x)          (x & (~PAGE_MASK))

#define IOCTL_READ_KERNEL_MEMORY        0x1
#define IOCTL_WRITE_KERNEL_MEMORY       0x2
#define IOCTL_READ_PROCESS_ADDR         0x3
#define IOCTL_WRITE_PROCESS_ADDR        0x4
#define IOCTL_READ_PHYSICAL_ADDR        0x5
#define IOCTL_WRITE_PHYSICAL_ADDR       0x6
#define IOCTL_GET_KERNEL_MAP            0x7

struct r2k_memory_transf {
        int pid;
        unsigned long addr;
        unsigned long len;
        void __user *buff;
};

#define MAX_PHYS_ADDR	128

struct kernel_map_info {
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long phys_addr[MAX_PHYS_ADDR];
	int n_pages;
};

struct kernel_maps {
	int n_entries;
	int size;
};

struct r2k_map {
	struct kernel_maps kernel_maps_info;
	struct kernel_map_info *map_info;
};

extern int addr_is_writeable (unsigned long addr);
extern int addr_is_mapped (unsigned long addr);
extern int dump_pagetables (void);
extern int pg_dump (struct r2k_map *k_map);

/**********************/

/* CPU-Registers Part */

#define IOCTL_READ_REG	0x8
#define IOCTL_PROC_INFO	0x9

#if defined(CONFIG_X86_32)
#define reg_size 4
#elif defined(CONFIG_X86_64)
#define reg_size 8
#endif

struct r2k_control_reg {
#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
        unsigned long cr0;
        unsigned long cr1; //Register Not used. What to do?
        unsigned long cr2;
        unsigned long cr3;
        unsigned long cr4;
#ifdef CONFIG_X86_64
        unsigned long cr8;
#endif
#endif
};

//fails for kernel 3.15 x86
struct r2k_proc_info {
        pid_t pid;
        char comm[16]; //TASK_COMM_LEN = 16 include/linux/sched.h
        unsigned long vmareastruct[4096];
        unsigned long stack;
};

/**********************/
#endif
