/* SPDX-License-Identifier: GPL-2.0+ */

/*
 * Linux kernel operations surveillant
 *
 * Author: Cătălin-Alexandru Rîpanu catalin.ripanu@stud.acs.upb.ro
 */
#ifndef UTILS_H__
#define UTILS_H__

#define HASHTABLE_SIZE 10

#define PROC_HEADER                                                            \
	"PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\tlock\tunlock\n"

#define MODULE_NAME "so2_homework1"
#define procfs_file_read "tracer"

pid_t ioctl_invk;

struct memory_metadata_elem {
	uint32_t address;
	uint32_t size;
	struct hlist_node mem_table;
};

struct table_process_node {
	uint32_t kmalloc_calls;
	uint32_t kfree_calls;
	uint32_t kmalloc_mem;
	uint32_t kfree_mem;
	uint32_t sched_calls;
	uint32_t up_calls;
	uint32_t down_calls;
	uint32_t lock_calls;
	uint32_t unlock_calls;
	pid_t pid;
	DECLARE_HASHTABLE(memory_metadata_table, HASHTABLE_SIZE);
	struct hlist_node proc_table;
};

DEFINE_RWLOCK(lock);

DEFINE_HASHTABLE(kernel_process_data_table, HASHTABLE_SIZE);

static struct proc_dir_entry *proc_read;

static struct miscdevice kernel_device_data;

/**
 * memory_metadata_elem - allocates kernel memory for creating
 * <addr - size> pair structure used for kmalloc and kfree probes
 * @address: address returned by a kmalloc invocation
 * @size: size given as a parameter to a kmalloc call
 */
static struct memory_metadata_elem *metadata_info_alloc(uint32_t address,
														uint32_t size)
{
	struct memory_metadata_elem *elem;

	elem = kmalloc(sizeof(*elem), GFP_ATOMIC);
	if (elem == NULL)
		return NULL;

	elem->address = address;
	elem->size = size;

	return elem;
}

/**
 * metadata_add_to_table - creates and adds <address - size> pair
 * to a process hashtable
 * @address: address returned by a kmalloc invocation
 * @size: size given as a parameter to a kmalloc call
 * @process: process to add this <address - size> pair to
 */
static void metadata_add_to_table(uint32_t address, uint32_t size,
								  struct table_process_node *process)
{
	struct memory_metadata_elem *elem;

	elem = metadata_info_alloc(address, size);

	hash_add(process->memory_metadata_table, &elem->mem_table, address);
}

/**
 * metadata_delete_table - deletes <address - size> pairs from a
 * hashtable given by a process
 * @process: process whose hashtable is freed from kernel
 */
static void metadata_delete_table(struct table_process_node *process)
{
	struct hlist_node *tmp;
	struct memory_metadata_elem *elem;
	uint32_t val;

	hash_for_each_safe(process->memory_metadata_table, val, tmp, elem, mem_table) {
		hash_del(&elem->mem_table);
		kfree(elem);
	}
}

/**
 * purge_kernel_table - deletes global processes hashtable
 */
static void purge_kernel_table(void)
{

	struct table_process_node *elem;
	struct hlist_node *tmp;
	uint32_t val;

	write_lock(&lock);

	hash_for_each_safe(kernel_process_data_table, val, tmp, elem, proc_table) {
		hash_del(&elem->proc_table);
		metadata_delete_table(elem);
		kfree(elem);
	}

	write_unlock(&lock);
}

#endif /* UTILS_H_ */
