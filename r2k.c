#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/page-flags.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
#define get_user_pages		get_user_pages_remote
#define page_cache_release	put_page
#endif

#define ADDR_OFFSET(x)		(x & (~PAGE_MASK))

#define R2_TYPE 0x69

#define IOCTL_READ_KERNEL_MEMORY	0x1
#define IOCTL_WRITE_KERNEL_MEMORY	0x2
#define IOCTL_READ_PROCESS_ADDR		0x3
#define IOCTL_WRITE_PROCESS_ADDR	0x4
#define IOCTL_READ_PHYSICAL_ADDR	0x5
#define IOCTL_WRITE_PHYSICAL_ADDR	0x6
#define IOCTL_GET_PROC_MAPS		0x7
#define IOCTL_GET_KERNEL_MAP		0x8

#define  R2_CLASS_NAME	"r2k"

static struct device *r2k_dev_ph;
static struct class *r2k_class;
static struct cdev *r2k_dev;
static dev_t devno;

static char *r2_devname = "r2k";

struct r2k_data {
	int pid;
	unsigned long addr;
	unsigned long len;
	void __user *buff;
};

extern int addr_is_writeable (unsigned long addr);
extern int addr_is_mapped (unsigned long addr);

static int io_open (struct inode *inode, struct file *file)
{
	return 0;
}

static int io_close (struct inode *inode, struct file *file)
{
	return 0;
}

static int is_from_module_or_vmalloc (unsigned long addr)
{
	if (is_vmalloc_addr ((void *)addr) ||
		__module_address (addr))
		return 1;
	return 0;
}

static int check_kernel_addr (unsigned long addr)
{
	return virt_addr_valid (addr) == 0 
			? is_from_module_or_vmalloc (addr) 
			: 1;
}

static int get_nr_pages (unsigned long addr, unsigned long next_aligned_addr, 
							unsigned long len)
{
	int nr_pages;

	if (addr & (PAGE_SIZE - 1)) {
		if (addr + len > next_aligned_addr) 
			nr_pages = len < PAGE_SIZE 
					? (len / PAGE_SIZE) + 2 
					: (len / PAGE_SIZE) + 1;
		else
			nr_pages = 1;
	} else {
		 nr_pages = (len & (PAGE_SIZE - 1)) 
				? len / PAGE_SIZE + 1 
				: len / PAGE_SIZE;
	}
	return nr_pages;
}

static inline int get_bytes_to_rw (unsigned long addr, unsigned long len,
						unsigned long next_aligned_addr)
{
	return (len > (next_aligned_addr - addr)) 
			? next_aligned_addr - addr 
			: len;
}

static unsigned long get_next_aligned_addr (unsigned long addr)
{
	return (addr & (PAGE_SIZE - 1)) 
			? PAGE_ALIGN (addr) 
			: addr + PAGE_SIZE;
}

static inline void *map_addr (struct page *pg, unsigned long addr)
{
	return kmap_atomic (pg) + ADDR_OFFSET (addr);
}

static inline void unmap_addr (void *kaddr, unsigned long addr)
{
	kunmap_atomic (kaddr - ADDR_OFFSET (addr));
}

static long io_ioctl (struct file *file, unsigned int cmd, 
					unsigned long data_addr)
{
	struct r2k_data *data;
	struct task_struct *task;
	struct vm_area_struct *vma;
	unsigned long next_aligned_addr;
	int nr_pages;
	int page_i;
	void __user *buffer_r;
	unsigned long len;
	int ret = 0;

	if (_IOC_TYPE (cmd) != R2_TYPE)
		return -EINVAL;

	data = kmalloc (sizeof (*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	memset (data, 0, sizeof (*data));
	ret = copy_from_user (data, (void __user*)data_addr, sizeof (*data));
	if (ret) {
		pr_info ("%s: couldn not copy struct r2k_data\n", r2_devname);
		ret = -EFAULT;
		goto out;
	}

	len = data->len;
	if (len == 0) {
		ret = -EINVAL;
		goto out;
	}

	switch (_IOC_NR (cmd)) {

	case IOCTL_READ_KERNEL_MEMORY:
		
		pr_info ("%s: IOCTL_READ_KERNEL_MEMORY at 0x%lx\n", r2_devname, 
								data->addr);

		pr_info ("%s: phys 0x%x\n", r2_devname, __pa(data->addr));
	
		if (!check_kernel_addr (data->addr)) {
			pr_info ("%s: 0x%lx invalid addr\n", r2_devname, 
								data->addr);
			ret = -EFAULT;
			goto out;
		}

		if (!addr_is_mapped (data->addr)) {
			pr_info ("%s: addr is not mapped\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}

		ret = copy_to_user (data->buff, (void *)data->addr, len);
		if (ret) {
			pr_info ("%s: copy_to_user failed\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}

		break;

	case IOCTL_WRITE_KERNEL_MEMORY:

		pr_info ("%s: IOCTL_WRITE_KERNEL_MEMORY at 0x%lx\n", r2_devname, 
								data->addr);

		if (!check_kernel_addr (data->addr)) {
			pr_info ("%s: 0x%lx invalid addr\n", r2_devname, 
								data->addr);
			ret = -EFAULT;
			goto out;
		}	

		if (!addr_is_writeable (data->addr)) {
			pr_info ("%s: cannot write at addr 0x%lx\n", r2_devname, 
								data->addr);
			ret = -EPERM;
			goto out;
		}

		ret = copy_from_user ((void *)data->addr, data->buff, len);
		if (ret) {
			pr_info ("%s: copy_to_user failed\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}
				
		break; 

	case IOCTL_READ_PROCESS_ADDR:
	case IOCTL_WRITE_PROCESS_ADDR:

		pr_info ("%s: IOCTL_READ/WRITE_PROCESS_ADDR at 0x%lx" 
						"from pid (%d) bytes (%ld)\n", 
						r2_devname, data->addr, 
						data->pid, data->len);

		buffer_r = data->buff;

		task = pid_task (find_vpid (data->pid), PIDTYPE_PID);
		if (!task) {
			pr_info ("%s: could not retrieve task_struct" 
							"from pid (%d)\n", 
							r2_devname, data->pid);
			ret = -ESRCH;
			goto out;
		}

		vma = find_vma (task->mm, data->addr);
		if (!vma) {
			pr_info ("%s: could not retrieve vm_area_struct" 
								"at 0x%lx\n", 
						r2_devname, data->addr);
			ret = -EFAULT;
			goto out;
		}
			
		pr_info ("%s: vma->vm_start - vma->vm_end, 0x%lx - 0x%lx\n", 
						r2_devname, vma->vm_start, 
								vma->vm_end);

		if (data->addr + len > vma->vm_end) {
			pr_info ("%s: 0x%lx + %ld bytes goes beyond" 
					"valid addresses. bytes recalculated to"
								"%ld bytes\n", 
								r2_devname, 
								data->addr, 
								data->len, 
						vma->vm_end - data->addr);
			len = vma->vm_end - data->addr;
		}
		
		next_aligned_addr = get_next_aligned_addr (data->addr);
		nr_pages = get_nr_pages (data->addr, next_aligned_addr, len);
		pr_info ("%s: next_aligned_addr 0x%lx\n", r2_devname, 
							next_aligned_addr);
			
		down_read (&task->mm->mmap_sem);
		for (page_i = 0 ; page_i < nr_pages ; page_i++ ) {

			struct page *pg = NULL;;
			void *kaddr;
			int bytes;

			ret = get_user_pages (task, task->mm, data->addr, 1, 
									0, 
									0, 
									&pg, 
									NULL);
			if (!ret) {
				pr_info ("%s: could not retrieve page"
							"from pid (%d)\n", 
							r2_devname, data->pid);
				ret = -ESRCH;
				if (pg)
	        			page_cache_release (pg);
				goto out_loop;
			}

			bytes = get_bytes_to_rw (data->addr, len, 
							next_aligned_addr);
			kaddr = map_addr (pg, data->addr);
			pr_info ("%s: kaddr 0x%p\n", r2_devname, kaddr);
			pr_info ("%s: reading %d bytes\n", r2_devname, bytes);

			if (!addr_is_mapped ( (unsigned long)kaddr)) {
                        	pr_info ("%s: addr is not mapped," 
						"triggering a fault\n", 
								r2_devname);
				unmap_addr (kaddr, data->addr);
				if (pg)
					page_cache_release (pg);
				goto out_loop;
			} 

			if (_IOC_NR (cmd) == IOCTL_READ_PROCESS_ADDR)
				ret = copy_to_user (buffer_r, kaddr, bytes);
			else
				ret = copy_from_user (kaddr, buffer_r,  bytes);

			if (ret) {
				pr_info ("%s: copy_to_user failed\n", 
								r2_devname);
				ret = -EFAULT;
				unmap_addr (kaddr, data->addr);
				if (pg)
	        			page_cache_release (pg);
				goto out_loop;
			}

			buffer_r += bytes;
			data->addr = next_aligned_addr;
			next_aligned_addr += PAGE_SIZE;
			len -= bytes;
			unmap_addr (kaddr, data->addr);
			if (pg)
				page_cache_release (pg);
		}

	out_loop:
		up_read (&task->mm->mmap_sem);
		break;

	case IOCTL_READ_PHYSICAL_ADDR:
	case IOCTL_WRITE_PHYSICAL_ADDR:

		pr_info ("%s: IOCTL_READ/WRITE_PHYSICAL_ADDR on 0x%lx\n", r2_devname, 
								data->addr);
		if (!pfn_valid (data->addr >> PAGE_SHIFT)) {
			pr_info ("%s: 0x%lx out of range\n", r2_devname, data->addr);
			ret = -EFAULT;
			goto out;
		}
		buffer_r = data->buff;

#if defined (CONFIG_X86_32) || defined (CONFIG_ARM)
		next_aligned_addr = get_next_aligned_addr (data->addr);
		nr_pages = get_nr_pages (data->addr, next_aligned_addr, len);
	
		for (page_i = 0 ; page_i < nr_pages ; page_i++) {

			struct page *pg;
			void *kaddr;
			int bytes;

			bytes = get_bytes_to_rw (data->addr, len, 
							next_aligned_addr);

			pg = pfn_to_page (data->addr >> PAGE_SHIFT);
			kaddr = map_addr (pg, data->addr);
			pr_info ("%s: kaddr: 0x%p\n", r2_devname, kaddr);
			pr_info ("%s: kaddr - offset: 0x%p\n", r2_devname, 
					kaddr - (data->addr & (~PAGE_MASK)));
			pr_info ("%s: reading %d bytes\n", r2_devname, bytes);

			if (_IOC_NR (cmd) == IOCTL_READ_PHYSICAL_ADDR)
				ret = copy_to_user (buffer_r, kaddr, bytes);
			else {
				if (!addr_is_writeable ( (unsigned long)kaddr)) {
					pr_info ("%s: cannot write at addr "
								"0x%lx\n", 
								r2_devname, 
							(unsigned long)kaddr);
					unmap_addr (kaddr, data->addr);
					ret = -EPERM;
					goto out;
				}
				ret = copy_from_user (kaddr, buffer_r, bytes);
			}

			if (ret) {
				pr_info ("%s: failed while copying\n",
								r2_devname);
				unmap_addr (kaddr, data->addr);
                	        ret = -EFAULT;
				goto out;
			}

			unmap_addr (kaddr, data->addr);
			buffer_r += bytes;
			data->addr = next_aligned_addr;
			next_aligned_addr += PAGE_SIZE;
			len -= bytes;
		}
#else
		void *kaddr = phys_to_virt (data->addr);

		if (_IOC_NR (cmd) == IOCTL_READ_PHYSICAL_ADDR)
			ret = copy_to_user (buffer_r, kaddr, len);
		else {
			if (!addr_is_writeable ( (unsigned long)kaddr)) {
				pr_info ("%s: cannot write at addr "
							"0x%lx\n",
							r2_devname,
							(unsigned long)kaddr);
				ret = -EPERM;
				goto out;
			}
			ret = copy_from_user (kaddr, buffer_r, len);
		}

		if (ret) {
                                pr_info ("%s: failed while copying\n",
                                                                r2_devname);
                                ret = -EFAULT;
                                goto out;
                        }
#endif

		break;

	case IOCTL_GET_KERNEL_MAP:
	
		pr_info ("%s: IOCTL_GET_KERNEL_MAP\n", r2_devname);

		/*
			Areas
	
			User Space
			Kernel Mapping
			vmalloc()
			vmalloc() End
			Persistent kmap() 
			Fixmap Area
		*/
			
		break;

	default:
		pr_info ("%s: operation not implemented\n", r2_devname);
		ret = -EINVAL;
		break;
	}

out:
	kfree (data);
	return ret;
}

static struct file_operations fops = {
        .owner = THIS_MODULE,
        .open = io_open,
        .release = io_close,
        .unlocked_ioctl = io_ioctl,
};

static char *r2k_devnode (struct device *dev_ph, umode_t *mode)
{
	if (mode) {
		if (dev_ph->devt == devno) 
			*mode = 0644;
	}
	return NULL;
}


static int __init r2k_init (void)
{
	int ret;

	pr_info ("%s: loading driver\n", r2_devname);
	pr_info ("%s: alloc_chrdev_region: %p\n", r2_devname, alloc_chrdev_region);

	ret = alloc_chrdev_region (&devno, 0, 1, r2_devname);
	if (ret < 0) {
		pr_info ("%s: alloc_chrdev_region failed\n", r2_devname);
		goto out;
	}

	r2k_class = class_create (THIS_MODULE, R2_CLASS_NAME);
	if (IS_ERR (r2k_class)) {
		pr_info ("%s: class_create failed creating -r2k- class\n", 
								r2_devname);
		ret = PTR_ERR (r2k_class);
		goto out_unreg_dev;
	}

	r2k_class->devnode = r2k_devnode;		

	r2k_dev = cdev_alloc();
	if (r2k_dev == NULL) {
		pr_info ("%s: cdev_alloc failed\n", r2_devname);
		ret = -ENOMEM;
		goto out_unreg_class;
	}	

	cdev_init (r2k_dev, &fops);
	ret = cdev_add (r2k_dev, devno, 1);
	if (ret < 0) {
		pr_info ("%s: cdev_add failed\n", r2_devname);
		goto out_unreg_class;
	}

	r2k_dev_ph = device_create (r2k_class, NULL, devno, NULL, r2_devname);
	if (IS_ERR (r2k_dev_ph)) {
		pr_info ("%s: device_create failed\n", r2_devname);
		ret = PTR_ERR (r2k_dev_ph);
		goto out_del_cdev;
	}

	pr_info ("%s: /dev/%s created\n", r2_devname, r2_devname);
	pr_info ("%s: kernel_version: %s\n", r2_devname, utsname()->release);

	return 0;

out_del_cdev:
	cdev_del (r2k_dev);	

out_unreg_class:
	device_destroy (r2k_class, devno);
	class_unregister (r2k_class);

out_unreg_dev:
	unregister_chrdev_region (devno, 1);

out:
	return ret;
}

static void __exit r2k_exit (void)
{
	device_destroy (r2k_class, devno);
	class_unregister (r2k_class);

	class_destroy (r2k_class);
	cdev_del (r2k_dev);
	unregister_chrdev_region (devno, 1);
	pr_info ("%s: unloading driver, /dev/%s deleted\n", r2_devname,
								r2_devname);
}

module_init (r2k_init);
module_exit (r2k_exit);

MODULE_AUTHOR("Oscar Salvador");
MODULE_DESCRIPTION("r2k");
MODULE_LICENSE("GPL v2");
