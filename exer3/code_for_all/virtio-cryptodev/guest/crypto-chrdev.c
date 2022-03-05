/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/semaphore.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) { //iterates until minor number is found
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len, num_out, num_in;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
	// declare a scatterlist for the syscall type and fd from host
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	// declaration of the virtqueue struct
	struct virtqueue *vq;
	

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0) //opens without lseek option
		goto fail;				//that is what we return to user, the fd to the virtual device
							//in crof->fd we put the fd of the real device from the backend
	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev; //kanoume assign deiktes se mnimi kernel
	crof->host_fd = -1;
	filp->private_data = crof; //kanoume assigne deiktes se mnimi kernel

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	vq = crdev->vq;

	num_out = 0;
	num_in = 0;
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	// Caller must ensure we don't call this with other virtqueue
    // operations at the same time

	if (down_interruptible(&crdev->lock))  //we lock, because there are race conditions regarding virtqueue
 		return -ERESTARTSYS;
	
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	if (err == -1){
		debug("perror with virtqueue");
	}
	virtqueue_kick(vq);

	/**
	 * Wait for the host to process our data.
	 **/

	while (virtqueue_get_buf(vq, &len) == NULL);

	up(&crdev->lock); //release semaphore

	if (*host_fd < 0)
	{
		return -ENODEV;
	}
	crof->host_fd = *host_fd;
	debug("Leaving");
	return ret;

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int *host_fd, err, len;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	struct virtqueue *vq;
	unsigned int num_out, num_in;	

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);

	debug("1 koble");
	/**
	 * Send data to the host.
	 **/
	*host_fd = crof->host_fd;
	
	vq = crdev->vq;
	num_out = 0;
       	num_in = 0;

	debug("2 koble");

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	debug("3 koble");
	/**
	 * Wait for the host to process our data.
	 **/
	 
	if (down_interruptible(&crdev->lock))  //we lock, because there are race conditions regarding virtqueue
 		return -ERESTARTSYS;
	
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	if (err == -1){
		debug("virtqueue");
	}
	virtqueue_kick(vq);

	/**
	 * Wait for the host to process our data.
	 **/

	while (virtqueue_get_buf(vq, &len) == NULL);
	
	up(&crdev->lock); //release semaphore
	debug("all good until here");
	kfree(syscall_type);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, host_fd_sg, ioctl_cmd_sg,
					   session_key_sg, session_op_sg, host_return_val_sg, ses_id_sg,
					   src_sg, dst_sg, iv_sg, crypt_op_sg, *sgs[8];
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	unsigned char *output_msg, *input_msg, *session_key, *src, *dst, *iv;
	unsigned int *syscall_type, *ioctl_cmd;
	int *host_fd, *host_return_val;
	struct crypt_op *crypt_op;
	struct session_op *session_op;
	uint32_t *ses_id;


	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	//output_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	//input_msg = kzalloc(MSG_LEN, GFP_KERNEL);

	//allocate common data

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL); 
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	*ioctl_cmd = cmd;

	host_return_val = kzalloc(sizeof(*host_return_val), GFP_KERNEL);
	*host_return_val = -1;

	debug("first allocations finished");

	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	// initialize sgs
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;

	sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
	//we will add it to the sgs[] later

	debug("common sgs done");

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		//memcpy(output_msg, "Hello HOST from ioctl CIOCGSESSION.", 36);
		//input_msg[0] = '\0';
		//sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		//sgs[num_out++] = &output_msg_sg;
		//sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		//sgs[num_out + num_in++] = &input_msg_sg;

		session_op = kzalloc(sizeof(*session_op), GFP_KERNEL); 
		if (copy_from_user(session_op, (struct session_op *)arg, sizeof(*session_op))) //we cast arg to struct session_op pointer (user space)
			return -EFAULT;

		//we use session_op->key pointer to copy from user, because it is userspace address

		session_key = kzalloc(session_op->keylen, GFP_KERNEL);
		if (copy_from_user(session_key, session_op->key, session_op->keylen)) //session_op->key is user space pointer to key
			return -EFAULT;

		sg_init_one(&session_key_sg, session_key, sizeof(session_op->keylen));
		sgs[num_out++] = &session_key_sg;

		sg_init_one(&session_op_sg, session_op, sizeof(*session_op));
		sgs[num_out + num_in++] = &session_op_sg;
		
		sgs[num_out + num_in++] = &host_return_val_sg;  //we left that from before

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		//memcpy(output_msg, "Hello HOST from ioctl CIOCFSESSION.", 36);
		//input_msg[0] = '\0';
		//sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		//sgs[num_out++] = &output_msg_sg;
		//sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		//sgs[num_out + num_in++] = &input_msg_sg;

		ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);
		if (copy_from_user(ses_id, (uint32_t *)arg, sizeof(*ses_id))) 
			return -EFAULT;

		sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
		sgs[num_out++] = &ses_id_sg;
		
		sgs[num_out + num_in++] = &host_return_val_sg;  //we left that from before

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		//memcpy(output_msg, "Hello HOST from ioctl CIOCCRYPT.", 33);
		//input_msg[0] = '\0';
		//sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
		//sgs[num_out++] = &output_msg_sg;
		//sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
		//sgs[num_out + num_in++] = &input_msg_sg;

		crypt_op = kzalloc(sizeof(*crypt_op), GFP_KERNEL);
		if (copy_from_user(crypt_op, (struct crypt_op *)arg, sizeof(*crypt_op))) 
			return -EFAULT;
		
		iv = kzalloc(16, GFP_KERNEL);
		if (copy_from_user(iv, crypt_op->iv, 16)) 
			return -EFAULT;

		src = kzalloc(crypt_op->len, GFP_KERNEL);
		if (copy_from_user(src, crypt_op->src, crypt_op->len))
			return -EFAULT;

		dst = kzalloc(crypt_op->len, GFP_KERNEL);
		if (copy_from_user(dst, crypt_op->dst, crypt_op->len))  //we copy that from user because he fills it with '\0'
			return -EFAULT;

		sg_init_one(&crypt_op_sg, crypt_op, sizeof(*crypt_op));
		sgs[num_out++] = &crypt_op_sg;

		sg_init_one(&src_sg, src, crypt_op->len);
		sgs[num_out++] = &src_sg;

		sg_init_one(&iv_sg, iv, 16);
		sgs[num_out++] = &iv_sg;

		sg_init_one(&dst_sg, dst, crypt_op->len);
		sgs[num_out + num_in++] = &dst_sg;

		sgs[num_out + num_in++] = &host_return_val_sg;
	
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	debug("first switch end");
	/**
	 * Wait for the host to process our data.
	 **/
	if (down_interruptible(&crdev->lock))  //we lock, because there are race conditions regarding virtqueue
 		return -ERESTARTSYS;
	
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
		
	up(&crdev->lock); //release semaphore

	debug("data is here");

	ret = *host_return_val;

	//time to copy_to_user

	switch (cmd) {
	case CIOCGSESSION:
		session_op->key = ((struct session_op *) arg)->key; //key pointer we got from virtqueue refers to host userspace 
										//so we need to assign (reinstate) the right one for the userspace program
		if (copy_to_user((struct session_op *)arg, session_op, sizeof(*session_op)))
			return -EFAULT;
		kfree(session_op);
		kfree(session_key);
		break;

	case CIOCFSESSION:
		kfree(ses_id);
		break; //nothing to copy

	case CIOCCRYPT:
		if (copy_to_user(((struct crypt_op *)arg)->dst, dst, crypt_op->len))
			return -EFAULT;
		kfree(crypt_op);
		kfree(iv);
		kfree(src);
		kfree(dst);
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}
	
	debug("user got data");

	//debug("We said: '%s'", output_msg);
	//debug("Host answered: '%s'", input_msg);

	//kfree(output_msg);
	//kfree(input_msg);
	kfree(syscall_type);
	kfree(host_fd);
	kfree(ioctl_cmd);
	kfree(host_return_val);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
