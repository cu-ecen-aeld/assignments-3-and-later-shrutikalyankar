/**
 * @file main.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/mutex.h>

#include "aesdchar.h"
#include "aesd-circular-buffer.h"

int aesd_major = 0; /* dynamic major */
int aesd_minor = 0;

MODULE_AUTHOR("Shruti Kalyankar");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

/* ------------------------------------------------------------------ */
/* open / release                                                       */
/* ------------------------------------------------------------------ */

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    PDEBUG("open");
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

/* ------------------------------------------------------------------ */
/* read                                                                 */
/* ------------------------------------------------------------------ */

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_offset = 0;
    size_t bytes_to_read;
    ssize_t retval = 0;

    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(
                &dev->buffer, (size_t)*f_pos, &entry_offset);

    if (!entry) {
        /* No data at this offset — EOF */
        mutex_unlock(&dev->lock);
        return 0;
    }

    bytes_to_read = entry->size - entry_offset;
    if (bytes_to_read > count)
        bytes_to_read = count;

    if (copy_to_user(buf, entry->buffptr + entry_offset, bytes_to_read)) {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }

    *f_pos += bytes_to_read;
    retval  = (ssize_t)bytes_to_read;

    mutex_unlock(&dev->lock);
    return retval;
}

/* ------------------------------------------------------------------ */
/* write                                                                */
/* ------------------------------------------------------------------ */

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    char *temp;
    const char *old_entry;
    ssize_t retval = -ENOMEM;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    /* Grow the partial-write buffer to fit the new data */
    temp = krealloc(dev->write_buffer,
                    dev->write_buffer_size + count, GFP_KERNEL);
    if (!temp) {
        mutex_unlock(&dev->lock);
        return -ENOMEM;
    }
    dev->write_buffer = temp;

    /* Copy from user space into the kernel buffer */
    if (copy_from_user(dev->write_buffer + dev->write_buffer_size, buf, count)) {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }

    dev->write_buffer_size += count;

    /*
     * Only commit to the circular buffer when we see a newline.
     * Search the kernel-side buffer, NOT the __user pointer.
     */
    if (memchr(dev->write_buffer, '\n', dev->write_buffer_size)) {
        struct aesd_buffer_entry entry;
        entry.buffptr = dev->write_buffer;
        entry.size    = dev->write_buffer_size;

        /* add_entry returns the old buffptr if it overwrote an entry */
        old_entry = aesd_circular_buffer_add_entry(&dev->buffer, &entry);
        if (old_entry)
            kfree(old_entry);

        /* Buffer ownership transferred to the circular buffer */
        dev->write_buffer      = NULL;
        dev->write_buffer_size = 0;
    }

    retval = (ssize_t)count;

    mutex_unlock(&dev->lock);
    return retval;
}

/* ------------------------------------------------------------------ */
/* file_operations                                                      */
/* ------------------------------------------------------------------ */

struct file_operations aesd_fops = {
    .owner   = THIS_MODULE,
    .read    = aesd_read,
    .write   = aesd_write,
    .open    = aesd_open,
    .release = aesd_release,
};

/* ------------------------------------------------------------------ */
/* cdev setup                                                           */
/* ------------------------------------------------------------------ */

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err;
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops   = &aesd_fops;

    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
        printk(KERN_ERR "Error %d adding aesd cdev\n", err);

    return err;
}

/* ------------------------------------------------------------------ */
/* module init / exit                                                   */
/* ------------------------------------------------------------------ */

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }

    memset(&aesd_device, 0, sizeof(struct aesd_dev));
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);
    if (result)
        unregister_chrdev_region(dev, 1);

    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    uint8_t index;
    struct aesd_buffer_entry *entry;

    cdev_del(&aesd_device.cdev);

    /* Free all buffered entries */
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
        if (entry->buffptr) {
            kfree(entry->buffptr);
            entry->buffptr = NULL;
        }
    }

    /* Free any partial (unterminated) write */
    if (aesd_device.write_buffer) {
        kfree(aesd_device.write_buffer);
        aesd_device.write_buffer = NULL;
    }

    mutex_destroy(&aesd_device.lock);
    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
