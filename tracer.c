// SPDX-License-Identifier: GPL-2.0+

/*
 * Linux kernel operations surveillant
 *
 * Author: Cătălin-Alexandru Rîpanu catalin.ripanu@stud.acs.upb.ro
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/seq_file.h>

#include "tracer.h"
#include "utils.h"
#include "kprobes.h"

static int dev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t dev_read(struct file *file, char __user *user_buffer,
						size_t size, loff_t *offset)
{
	return 0;
}

static ssize_t dev_write(struct file *file, const char __user *user_buffer,
						 size_t size, loff_t *offset)
{
	return size;
}

/**
 * ketprobe_ioctl - ioctl interface with two arguments
 * @file: file which helps with the kprobes statistics
 * @cmd: ioctl command from user space
 * @arg: ioctl parameter from user space
 *
 * If the command is TRACER_ADD_PROCESS then it adds a
 * new process structure in process hashtable. This
 * operation is thread-safe.
 *
 * If the command is TRACER_REMOVE_PROCESS then it
 * removes a process structure from process hashtable.
 * This operation is thread-safe.
 */
static long ketprobe_ioctl(struct file *file, unsigned int cmd,
						   unsigned long arg)
{
	int ret = 0;

	ioctl_invk = current->pid;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
	{
		struct table_process_node *new_process;

		new_process = kmalloc(sizeof(*new_process), GFP_KERNEL);
		if (new_process == NULL) {
			ret = -ENOMEM;
			break;
		}

		new_process->kmalloc_calls = 0;
		new_process->kfree_calls = 0;
		new_process->kmalloc_mem = 0;
		new_process->kfree_mem = 0;
		new_process->sched_calls = 0;
		new_process->up_calls = 0;
		new_process->down_calls = 0;
		new_process->lock_calls = 0;
		new_process->unlock_calls = 0;
		new_process->pid = (pid_t)arg;

		hash_init(new_process->memory_metadata_table);

		write_lock(&lock);
		hash_add(kernel_process_data_table, &new_process->proc_table, (pid_t)arg);
		write_unlock(&lock);
	}
	break;
	case TRACER_REMOVE_PROCESS:
	{
		struct table_process_node *elem;
		struct hlist_node *tmp;

		write_lock(&lock);

		hash_for_each_possible_safe(kernel_process_data_table, elem, tmp, proc_table, (pid_t)arg) {
			if (elem->pid == (pid_t)arg) {
				hash_del(&elem->proc_table);
				metadata_delete_table(elem);
				kfree(elem);
				break;
			}
		}

		write_unlock(&lock);
	}
	break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

/**
 * Structure for storing all possible operations
 * for device.
 */
static const struct file_operations ketprobe_fops = {
	.owner = THIS_MODULE,
	.open = dev_open,
	.release = dev_release,
	.read = dev_read,
	.write = dev_write,
	.unlocked_ioctl = ketprobe_ioctl,
};

/**
 * table_proc_show - function for writing kprobes info
 * @m: file structure which governs /proc/tracer file
 *
 * This function prints all of the data from processes in
 * hash table. This logic is thread-safe.
 */
static int table_proc_show(struct seq_file *m, void *v)
{
	struct table_process_node *elem;
	uint32_t val;

	read_lock(&lock);

	seq_printf(m, PROC_HEADER);

	hash_for_each(kernel_process_data_table, val, elem, proc_table) {
		seq_printf(m, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
				   elem->pid, elem->kmalloc_calls, elem->kfree_calls,
				   elem->kmalloc_mem, elem->kfree_mem,
				   elem->sched_calls, elem->up_calls, elem->down_calls,
				   elem->lock_calls, elem->unlock_calls);
	}

	read_unlock(&lock);

	return 0;
}

/**
 * list_read_open - uses table_proc_show for writing
 * in /proc/tracer
 */
static int list_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, table_proc_show, NULL);
}

/**
 * Structure for registering procfs operations.
 */
static const struct proc_ops r_pops = {
	.proc_open = list_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

/**
 * kprobe_tracer_init - initialize all resources
 * used for creating tracing functionality
 *
 * It frees registered variables if failure is
 * present during this init phase.
 */
static int kprobe_tracer_init(void)
{
	int ret;

	kernel_device_data = (struct miscdevice){
		.minor = TRACER_DEV_MINOR,
		.name = TRACER_DEV_NAME,
		.fops = &ketprobe_fops,
	};

	ret = misc_register(&kernel_device_data);
	if (ret < 0) {
		pr_err("device register failed\n");
		goto finish_init;
	}

	ret = register_kretprobe(&kmalloc_kretprobe);
	if (ret < 0) {
		pr_err("kmalloc register failed\n");
		goto reg_kmalloc_failed;
	}

	ret = register_kretprobe(&kfree_kretprobe);
	if (ret < 0) {
		pr_err("kfree register failed\n");
		goto reg_kfree_failed;
	}

	ret = register_kretprobe(&schedule_kretprobe);
	if (ret < 0) {
		pr_err("schedule register failed\n");
		goto reg_sched_failed;
	}

	ret = register_kretprobe(&up_kretprobe);
	if (ret < 0) {
		pr_err("up register failed\n");
		goto reg_up_failed;
	}

	ret = register_kretprobe(&down_interruptible_kretprobe);
	if (ret < 0) {
		pr_err("down_interruptible register failed\n");
		goto reg_down_failed;
	}

	ret = register_kretprobe(&mutex_lock_kretprobe);
	if (ret < 0) {
		pr_err("mutex_lock register failed\n");
		goto reg_lock_failed;
	}

	ret = register_kretprobe(&mutex_unlock_kretprobe);
	if (ret < 0) {
		pr_err("mutex_unlock register failed\n");
		goto reg_unlock_failed;
	}

	proc_read = proc_create(procfs_file_read, 0000, proc_read, &r_pops);
	if (!proc_read) {
		ret = -ENOMEM;
		goto proc_list_cleanup;
	}

	goto finish_init;

proc_list_cleanup:
	proc_remove(proc_read);

reg_unlock_failed:
	unregister_kretprobe(&mutex_unlock_kretprobe);

reg_lock_failed:
	unregister_kretprobe(&mutex_lock_kretprobe);

reg_down_failed:
	unregister_kretprobe(&down_interruptible_kretprobe);

reg_up_failed:
	unregister_kretprobe(&up_kretprobe);

reg_sched_failed:
	unregister_kretprobe(&schedule_kretprobe);

reg_kfree_failed:
	unregister_kretprobe(&kfree_kretprobe);

reg_kmalloc_failed:
	unregister_kretprobe(&kmalloc_kretprobe);

finish_init:
	return ret;
}

/**
 * kprobe_tracer_exit - function which frees registers
 * purges global process hastable, removes misc device
 * and destroys procfs file.
 */
static void kprobe_tracer_exit(void)
{
	proc_remove(proc_read);
	misc_deregister(&kernel_device_data);

	unregister_kretprobe(&kmalloc_kretprobe);
	unregister_kretprobe(&kfree_kretprobe);
	unregister_kretprobe(&schedule_kretprobe);
	unregister_kretprobe(&up_kretprobe);
	unregister_kretprobe(&down_interruptible_kretprobe);
	unregister_kretprobe(&mutex_lock_kretprobe);
	unregister_kretprobe(&mutex_unlock_kretprobe);

	purge_kernel_table();
}

module_init(kprobe_tracer_init);
module_exit(kprobe_tracer_exit);

MODULE_DESCRIPTION("Kernel operations surveillant");

MODULE_AUTHOR("Catalin-Alexandru Ripanu catalin.ripanu@stud.acs.upb.ro");
MODULE_LICENSE("GPL v2");
