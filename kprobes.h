/* SPDX-License-Identifier: GPL-2.0+ */

/*
 * Linux kernel operations surveillant
 *
 * Author: Cătălin-Alexandru Rîpanu catalin.ripanu@stud.acs.upb.ro
 */
#ifndef KPROBES_H__
#define KPROBES_H__

/**
 * kmalloc_kretprobe_return_handler - probes kmalloc function
 *
 * Increments kmalloc_calls field and adds the current
 * memory size to kmalloc_mem value for the executing process
 * Ignores the ioctl invoker's pid.
 */
static int kmalloc_kretprobe_return_handler(struct kretprobe_instance *inst,
											struct pt_regs *regs)
{
	struct table_process_node *elem;

	struct memory_metadata_elem *data;

	if (ioctl_invk == current->pid)
		return -1;

	write_lock(&lock);

	data = (struct memory_metadata_elem *)inst->data;

	hash_for_each_possible(kernel_process_data_table, elem, proc_table, current->pid) {
		if (current->pid == elem->pid) {
			elem->kmalloc_calls++;
			elem->kmalloc_mem += data->size;
			metadata_add_to_table(regs_return_value(regs),
								  data->size, elem);
			break;
		}
	}

	write_unlock(&lock);

	return 0;
}
NOKPROBE_SYMBOL(kmalloc_kretprobe_return_handler)

/**
 * kmalloc_kretprobe_init_handler - probes kmalloc function
 *
 * Saves the size kmalloc was called with.
 */
static int kmalloc_kretprobe_init_handler(struct kretprobe_instance *inst,
										  struct pt_regs *regs)
{
	struct memory_metadata_elem *data;

	if (ioctl_invk == current->pid)
		return -1;

	data = (struct memory_metadata_elem *)inst->data;
	data->size = regs->ax;

	return 0;
}
NOKPROBE_SYMBOL(kmalloc_kretprobe_init_handler)

/**
 * kfree_kretprobe_init_handler - probes kfree function
 *
 * Increments the kfree_calls value for the current process.
 */
static int kfree_kretprobe_init_handler(struct kretprobe_instance *inst,
										struct pt_regs *regs)
{

	struct table_process_node *elem;
	struct hlist_node *tmp;
	struct memory_metadata_elem *iter;

	if (ioctl_invk == current->pid)
		return -1;

	write_lock(&lock);

	hash_for_each_possible(kernel_process_data_table, elem, proc_table, current->pid) {
		if (current->pid == elem->pid) {
			elem->kfree_calls++;

			hash_for_each_possible_safe(elem->memory_metadata_table, iter, tmp, mem_table, regs->ax) {
				if (iter->address == regs->ax) {
					elem->kfree_mem += iter->size;
					hash_del(&iter->mem_table);
					kfree(iter);
					break;
				}
			}
			break;
		}
	}

	write_unlock(&lock);

	return 0;
}
NOKPROBE_SYMBOL(kfree_kretprobe_init_handler)

/**
 * schedule_kretprobe_init_handler - probes schedule function
 *
 * Increments the sched_calls value for the current process.
 */
static int schedule_kretprobe_init_handler(struct kretprobe_instance *inst,
										   struct pt_regs *regs)
{
	struct table_process_node *elem;

	if (ioctl_invk == current->pid)
		return -1;

	write_lock(&lock);

	hash_for_each_possible(kernel_process_data_table, elem, proc_table, current->pid) {
		if (current->pid == elem->pid) {
			elem->sched_calls++;
			break;
		}
	}

	write_unlock(&lock);

	return 0;
}
NOKPROBE_SYMBOL(schedule_kretprobe_init_handler)

/**
 * up_kretprobe_init_handler - probes up function
 *
 * Increments the up_calls value for the current process.
 */
static int up_kretprobe_init_handler(struct kretprobe_instance *inst,
									 struct pt_regs *regs)
{
	struct table_process_node *elem;

	if (ioctl_invk == current->pid)
		return -1;

	write_lock(&lock);

	hash_for_each_possible(kernel_process_data_table, elem, proc_table, current->pid) {
		if (current->pid == elem->pid) {
			elem->up_calls++;
			break;
		}
	}

	write_unlock(&lock);

	return 0;
}
NOKPROBE_SYMBOL(up_kretprobe_init_handler)

/**
 * down_interruptible_kretprobe_init_handler - probes down_interruptible function
 *
 * Increments the down_calls value for the current process.
 */
static int down_interruptible_kretprobe_init_handler(struct kretprobe_instance *inst,
													 struct pt_regs *regs)
{
	struct table_process_node *elem;

	if (ioctl_invk == current->pid)
		return -1;

	write_lock(&lock);

	hash_for_each_possible(kernel_process_data_table, elem, proc_table, current->pid) {
		if (current->pid == elem->pid) {
			elem->down_calls++;
			break;
		}
	}

	write_unlock(&lock);

	return 0;
}
NOKPROBE_SYMBOL(down_interruptible_kretprobe_init_handler)

/**
 * mutex_lock_kretprobe_init_handler - probes mutex_lock function
 *
 * Increments the lock_calls value for the current process.
 */
static int mutex_lock_kretprobe_init_handler(struct kretprobe_instance *inst,
											 struct pt_regs *regs)
{
	struct table_process_node *elem;

	if (ioctl_invk == current->pid)
		return -1;

	write_lock(&lock);

	hash_for_each_possible(kernel_process_data_table, elem, proc_table, current->pid) {
		if (current->pid == elem->pid) {
			elem->lock_calls++;
			break;
		}
	}

	write_unlock(&lock);

	return 0;
}
NOKPROBE_SYMBOL(mutex_lock_kretprobe_init_handler)

/**
 * mutex_unlock_kretprobe_init_handler - probes mutex_unlock function
 *
 * Increments the unlock_calls value for the current process.
 */
static int mutex_unlock_kretprobe_init_handler(struct kretprobe_instance *inst,
											   struct pt_regs *regs)
{
	struct table_process_node *elem;

	if (ioctl_invk == current->pid)
		return -1;

	write_lock(&lock);

	hash_for_each_possible(kernel_process_data_table, elem, proc_table, current->pid) {
		if (current->pid == elem->pid) {
			elem->unlock_calls++;
			break;
		}
	}

	write_unlock(&lock);

	return 0;
}
NOKPROBE_SYMBOL(mutex_unlock_kretprobe_init_handler)

static struct kretprobe kmalloc_kretprobe = {
	.kp = {.symbol_name = "__kmalloc"},
	.handler = kmalloc_kretprobe_return_handler,
	.entry_handler = kmalloc_kretprobe_init_handler,
	.data_size = sizeof(struct memory_metadata_elem),
	.maxactive = 128,
};

static struct kretprobe kfree_kretprobe = {
	.kp = {.symbol_name = "kfree"},
	.entry_handler = kfree_kretprobe_init_handler,
	.maxactive = 128,
};

static struct kretprobe schedule_kretprobe = {
	.kp = {.symbol_name = "schedule"},
	.entry_handler = schedule_kretprobe_init_handler,
	.maxactive = 128,
};

static struct kretprobe up_kretprobe = {
	.kp = {.symbol_name = "up"},
	.entry_handler = up_kretprobe_init_handler,
	.maxactive = 128,
};

static struct kretprobe down_interruptible_kretprobe = {
	.kp = {.symbol_name = "down_interruptible"},
	.entry_handler = down_interruptible_kretprobe_init_handler,
	.maxactive = 128,
};

static struct kretprobe mutex_lock_kretprobe = {
	.kp = {.symbol_name = "mutex_lock_nested"},
	.entry_handler = mutex_lock_kretprobe_init_handler,
	.maxactive = 128,
};

static struct kretprobe mutex_unlock_kretprobe = {
	.kp = {.symbol_name = "mutex_unlock"},
	.entry_handler = mutex_unlock_kretprobe_init_handler,
	.maxactive = 128,
};

#endif /* KPROBES_H_ */
