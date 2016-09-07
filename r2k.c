#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/page-flags.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <asm/uaccess.h>
#include <asm/highmem.h>

#define PTE_CHECK_BIT(x)	(_AT(pteval_t, 1) << x)

/*
	search how the modules are being loaded
*/


/*

	static inline int pte_write(pte_t pte) { return pte_val(pte) & _PAGE_WRITABLE; }

*/

static char R2_TYPE = 'k';

#define IOCTL_READ_KERNEL_MEMORY	0x1
#define IOCTL_WRITE_KERNEL_MEMORY	0x2
#define IOCTL_READ_LINEAR_ADDR		0x3
#define IOCTL_WRITE_LINEAR_ADDR		0x4
#define IOCTL_READ_PHYSICAL_ADDR	0x5
#define IOCTL_WRITE_PHYSICAL_ADDR	0x6
#define IOCTL_GET_PROC_MAPS		0x7
#define IOCTL_GET_KERNEL_MAP		0x8


static struct cdev *r2_dev;
static dev_t dev;
static char *r2_devname = "r2";

static unsigned char c = 'a';

struct r2k_data {
	int pid;
	unsigned long addr;
	unsigned long len;
	void __user *buff;
};

static int io_open (struct inode *inode, struct file *file)
{
	return 0;
}

static int io_close (struct inode *inode, struct file *file)
{
	return 0;
}

static unsigned int addr_is_mapped (unsigned long addr)
{
	pte_t *pte;
	unsigned int level;

	pte = lookup_address (addr, &level);
	if (pte) {
		return (pte_val (*pte) & _PAGE_PRESENT);
	}

	pr_info ("%s: addr_is_mapped - pte_null\n", r2_devname);
	return 0;
}

static unsigned int addr_is_writeable (unsigned long addr)
{
	pte_t *pte;
	unsigned int level;

	pte = lookup_address (addr, &level);
	if (pte) {
		return (pte_val (*pte) & _PAGE_RW);
	}

	pr_info ("%s: pte == null\n", r2_devname);
	return 0;
}

static int check_kernel_addr (unsigned long addr)
{
	return virt_addr_valid (addr) == 0 ? is_vmalloc_addr ((void *)addr) : 1;
}

static void check_vmalloc_addr (unsigned long addr)
{
	if (is_vmalloc_addr ((void *)addr))
		pr_info ("%s: 0x%lx belongs to vmalloc\n", r2_devname, addr);
	else
		pr_info ("%s: 0x%lx does not belong to vmalloc\n", r2_devname, addr);
}

static long io_ioctl (struct file *file, unsigned int cmd, unsigned long data_addr)
{
	struct r2k_data __user *data = (struct r2k_data __user *)data_addr;
	unsigned long len;
	int ret = 0;

	if (_IOC_TYPE (cmd) != R2_TYPE)
		return -EINVAL;

	len = data->len;

	switch (_IOC_NR (cmd)) {

	case IOCTL_READ_KERNEL_MEMORY:
		
		pr_info ("%s: IOCTL_READ_KERNEL_MEMORY on 0x%lx\n", r2_devname, data->addr);
	
		if (!check_kernel_addr (data->addr)) {
			pr_info ("%s: 0x%lx invalid addr\n", r2_devname, data->addr);
			ret = -EFAULT;
			return ret;
		}

		check_vmalloc_addr (data->addr);

		if (!addr_is_mapped (data->addr)) {
			pr_info ("%s: addr is not mapped\n", r2_devname);
			ret = -EFAULT;
			return ret;
		}

		ret = copy_to_user (data->buff, (void *)data->addr, len);
		if (ret) {
			pr_info ("%s: copy_to_user failed\n", r2_devname);
			ret = -EFAULT;
			return ret;
		}

		break;

	case IOCTL_WRITE_KERNEL_MEMORY:

		pr_info ("%s: IOCTL_WRITE_KERNEL_MEMORY on 0x%lx\n", r2_devname, data->addr);

		if (!check_kernel_addr (data->addr)) {
			pr_info ("%s: 0x%lx invalid addr\n", r2_devname, data->addr);
			ret = -EFAULT;
			return ret;
		}	

		if (!addr_is_writeable (data->addr)) {
			pr_info ("%s: cannot write at addr 0x%lx\n", r2_devname, data->addr);
			ret = -EPERM;
			return ret;
		}
				
		ret = copy_from_user ((void *)data->addr, data->buff, len);
		if (ret) {
			pr_info ("%s: copy_to_user failed\n", r2_devname);
			ret = -EFAULT;
			return ret;
		}
				
		break; 

	case IOCTL_READ_LINEAR_ADDR:
		pr_info ("%s: IOCTL_READ_LINEAR_ADDR on 0x%lx from pid, %d bytes (%ld)\n", r2_devname, data->addr, data->pid, data->len);

		struct page *pg;
		struct task_struct *task;
		struct vm_area_struct *vma;
		void *kaddr;
		
		task = pid_task (find_vpid (data->pid), PIDTYPE_PID);
		if (!task) {
			pr_info ("%s: could not retrieve task_struct from pid (%d)\n", r2_devname, data->pid);
			ret = -ESRCH;
			return ret;
		}

		vma = find_vma (task->mm, data->addr);
		if (vma) {
			pr_info ("%s: vma->addr - 0x%lx\n", r2_devname, vma->vm_start);
		}

		down_read (&task->mm->mmap_sem);
		ret = get_user_pages (task, task->mm, data->addr, 1, 0, 0, &pg, NULL);
		if (!ret) {
			pr_info ("%s: could not retrieve page from pid (%d)\n", r2_devname, data->pid);
			ret = -ESRCH;
			return ret;
		}

		kaddr = kmap (pg);
		if (!kaddr) {
			pr_info ("%s: could not map the page from pid (%d)\n", r2_devname, data->pid);
			up_read (&task->mm->mmap_sem);
			ret = -ESRCH;
			return ret;
		}

		pr_info ("%s: kaddr : 0x%p\n", r2_devname, kaddr);
		ret = copy_to_user (data->buff, kaddr + (data->addr - vma->vm_start), len);
		if (ret) {
			up_read (&task->mm->mmap_sem);
			pr_info ("%s: copy_to_user failed\n", r2_devname);
			ret = -EFAULT;
			return ret;
		}
	
		page_cache_release (pg);
		up_read (&task->mm->mmap_sem);		
		break;

	default:
		pr_info ("%s: operation not implemented\n", r2_devname);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static struct file_operations fops = {
        .owner = THIS_MODULE,
        .open = io_open,
        .release = io_close,
        .unlocked_ioctl = io_ioctl,
};


static int __init r2k_init (void)
{
        int ret;

	pr_info ("%s: loading driver\n", r2_devname);

	ret = alloc_chrdev_region (&dev, 0, 1, r2_devname);
	r2_dev = cdev_alloc();
	cdev_init (r2_dev, &fops);
	cdev_add (r2_dev, dev, 1);
	
	pr_info ("%s: please create the proper device with - mknod /dev/%s c %d %d\n", r2_devname, r2_devname, MAJOR (dev), MINOR (dev));
	pr_info ("%s: VMALLOC_END:\t\t0x%lx\n", r2_devname, VMALLOC_END);
	pr_info ("%s: VMALLOC_OFFSET:\t\t0x%x\n", r2_devname, VMALLOC_OFFSET);
	pr_info ("%s: PKMAP_BASE:\t\t0x%lx\n", r2_devname, PKMAP_BASE);
	pr_info ("%s: FIXADDR_START:\t\t0x%lx\n", r2_devname, FIXADDR_START);
	pr_info ("%s: FIXADDR_TOP:\t\t0x%lx\n", r2_devname, FIXADDR_TOP);
	pr_info ("%s: mem_map:\t\t\t0x%p\n", r2_devname, &mem_map);
	pr_info ("%s: __START_KERNEL_map:\t0x%lx\n", r2_devname, __START_KERNEL_map);
	pr_info ("%s: KERNEL_IMAGE_SIZE:\t\t0x%x\n", r2_devname, KERNEL_IMAGE_SIZE);
	pr_info ("%s: c variable memory:\t\t0x%p\n", r2_devname, &c);

	return 0;
}

static void __exit r2k_exit (void)
{
	unregister_chrdev_region (dev, 1);
	cdev_del (r2_dev);
	pr_info ("%s: unloading driver, please delete /dev/%s\n", r2_devname, r2_devname);
}

module_init (r2k_init);
module_exit (r2k_exit);

MODULE_AUTHOR("Oscar Salvador");
MODULE_DESCRIPTION("r2k");
MODULE_LICENSE("GPL v2");
