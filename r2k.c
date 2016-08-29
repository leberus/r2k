#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

static char R2_TYPE = 'k';

static struct cdev *r2_dev;
static dev_t dev;
static char *r2_devname = "r2";


struct r2k_data {
	unsigned long *addr;
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

static long io_ioctl (struct file *file, unsigned int cmd, unsigned long data_addr)
{
	struct r2k_data __user *data = (struct r2k_data __user *)data_addr;
	unsigned long len;
	int ret;

	if (_IOC_TYPE (cmd) != R2_TYPE)
		return -EINVAL;

	len = data->len;

	switch (_IOC_DIR (cmd)) {

	case _IOC_READ:

		if (data->addr < PAGE_OFFSET) {
			pr_info ("%s: error - 0x%lx belongs to USERSPACE\n", r2_devname, (unsigned long)data->addr);
			ret = -EINVAL;
			return ret;
		} else {
			pr_info ("%s: 0x%lx above PAGE_OFFSET\n", r2_devname, (unsigned long)data->addr);
		}

		pr_info ("%s: addr: 0x%lx  val: 0x%lx\n", r2_devname, (unsigned long)data->addr, (unsigned long)*(data->addr));

		ret = copy_to_user (data->buff, (void *)data->addr, len);
		if (ret) {
			pr_info ("error: copy_to_user failed\n");
			ret = -EINVAL;
			return ret;
		}

		break;
	default:
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
	
	return 0;
}

static void __exit r2k_exit (void)
{
	unregister_chrdev_region (dev, 1);
	cdev_del (r2_dev);
	pr_info ("%s: unloading driver\n", r2_devname);
}

module_init (r2k_init);
module_exit (r2k_exit);

MODULE_LICENSE("GPL v3");
