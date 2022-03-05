/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < Your name here >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"


/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	int ret;
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor));

	if (sensor->msr_data[state->type]->last_update > state->buf_timestamp)
    {
		ret = 1; 
        debug("We need o refresh buf_data\n");
    }
    return ret;
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	unsigned long flags;        //flags from spinlock (previous interrupt state)
    uint16_t val;             //for lookup tables
    long int res;               //for lookup tables
    uint32_t current_timestamp; //last update timestamp
    int ret;
    sensor = state->sensor;
    ret = -EAGAIN; //if there are no data try again
	

	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	
	//critical section, we cant use semaphores (sleep) because sensors are being updated in interrupt context
	spin_lock_irqsave(&sensor->lock, flags);
    val = sensor->msr_data[state->type]->values[0];  //get data
    current_timestamp = sensor->msr_data[state->type]->last_update; //get the timestamp of last update
    //return to previous interrupt state
    spin_unlock_irqrestore(&sensor->lock, flags); 
	//end of critical section (however from read funtion, we know that we still hold semaphore lock)
	
	if(lunix_chrdev_state_needs_refresh(state))
    {
        if (state->type == BATT)
        {
            res = lookup_voltage[val];
        }
        else if (state->type == TEMP)
        {
            res = lookup_temperature[val];
        }
        else if (state->type == LIGHT)
        {
            res = lookup_light[val];
        }
        else
        {
            ret = -EMEDIUMTYPE;    //wrong type
            goto out;
        }
        ret = 0;
		//we update state fields
		//last buf_data update timestamp
        state->buf_timestamp = current_timestamp;
		//buf_data contents 
        state->buf_lim = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%ld.%03ld\n", res/1000, res%1000);
    }
out:
	debug("leaving\n");
	return ret;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */
	//
	struct lunix_chrdev_state_struct *new_state;
	unsigned int minor_number, sensor_num;
	//
	int ret;

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]	  
	 */
	//kanoume allocate mnimi gia to struct state
	new_state = kmalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);
	//apo to minor number vriskoume sensor kai type
	minor_number = iminor(inode);
	sensor_num = minor_number / 8;
	new_state->type = minor_number % 8;
	//vazoume sto pedio sensor: to stoixeio tou arxikopoiimenou pinaka lunix_sensors me thesi sensor_num=minor/8
	new_state->sensor = &lunix_sensors[sensor_num];
	//o buffer arxika exei mikos miden	
	new_state->buf_lim = 0 ; 
	new_state->buf_timestamp = 0 ; 
	sema_init(&new_state->lock,1);  //initialize semaphore
	filp->private_data = new_state;
	ret = 0;	
	//
out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/* ? */
	// Deallocate anthing that open allocated in filp->private data (LDD3, p.59)
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */
	// if the driver don't implement ioctl() EINVAL is returned
	// EINVAL = request or argp is not valid (man ioctl)
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret, rem_bytes;
	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	/* Lock? */
	if (down_interruptible(&state->lock))
 		return -ERESTARTSYS;
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {  //we need fresh data
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			up(&state->lock); //we release semaphore if there are no new data
			if (filp->f_flags & O_NONBLOCK) //if non-block then return
 				return -EAGAIN;
			debug("going to sleep");
			//we sleep until there are new data (in file lunix-sensors.c when a sensor is being updated, at line 95 it wakes up any sleepers)
			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state)))
 				return -ERESTARTSYS; 
			//now that we are woken up, we take the lock in order to read the new data
			if (down_interruptible(&state->lock))
 				return -ERESTARTSYS;
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
		}
	}
 	
 	/* ok, data is there, return something */
	
	/* Determine the number of cached bytes to copy to userspace */
	// If the cnt argument requested from user is greater than cached bytes
	// then return only the cached bytes (3rd arg in copy_to_user())
	rem_bytes = state->buf_lim - *f_pos;
	if (cnt > rem_bytes) {
		cnt = rem_bytes;
	}
	// copy_to_user(), 
	// the return value is the number of bytes that can't be copied
	// so, if ret_value non-zero, the function tried to access restricted area->(SEGFAULT)
	if (copy_to_user(usrbuf, state->buf_data + *f_pos, cnt)) {
		ret = -EFAULT;
		goto out;
	}
	// After copy_to_user() we have to update the *f_pos
	// and return the length of data have been readed
	*f_pos += cnt;
	ret = cnt;
	//
	/* Auto-rewind on EOF mode? */
	if (*f_pos == state->buf_lim) *f_pos = 0;
out:
	up(&state->lock); //we release semaphore for other readers
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
    .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	// here don't understand why *8 (sensors*8 measures/sensor)
	// i would set lunix_minor_cnt to lunix_sensor_cnt*3 (like the mknod)
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	// with the next 2 lines i set up my cdev structure
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;

	//LUNIX_CHRDEV_MAJOR is defined to 60 and first MINOR assigned to 0
	// ?? Have i to assign minor numbers to the other devices ??
	// Look at ln 202 for implementation
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0); 
	
	/* register_chrdev_region? */
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix");
	// now i have allocated 128 (16 << 3) device numbers(minor) for device lunix with start MKDEV(60, 0)
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	/* ? */
	/* cdev_add? */
	// i add the following line
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	// 
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
