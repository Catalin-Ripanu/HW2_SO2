# HW2_SO2

A kernel operations surveillant.

With this surveillant, the task is to intercept:

  - kmalloc and kfree calls

  - schedule calls

  - up and down_interruptible calls

  - mutex_lock and mutex_unlock calls

The surveillant will hold, at the process level, the number of calls for each of the above functions. For the kmalloc and kfree calls the total quantity of allocated and deallocated memory will be shown.

The surveillant will be implemented as a kernel module with the name *tracer.ko*.

The interception will be done by recording a sample (kretprobe) for each of the above functions. The surveillant will retain a list/hashtable with the monitored processes and will account for the above information for these processes.

For the control of the list/hashtable with the monitored processes, a char device called /dev/tracer will be used, with major 10 and minor 42. It will expose an ioctl interface with two arguments:

  - the first argument is the request to the monitoring subsystem:

    - TRACER_ADD_PROCESS
    - TRACER_REMOVE_PROCESS

  - the second argument is the PID of the process for which the monitoring request will be executed

Processes that have been added to the list/hashtable and that end their execution will be removed from the list/hashtable. Also, a process will be removed from the dispatch list/hashtable following the TRACER_REMOVE_PROCESS operation.

The information retained by the surveillant will be displayed via the procfs file system, in the /proc/tracer file. For each monitored process an entry is created in the /proc/tracer file having as first field the process PID. The entry will be read-only, and a read operation on it will display the retained results. An example of displaying the contents of the entry is:

```
$ cat /proc/tracer
PID   kmalloc kfree kmalloc_mem kfree_mem  sched   up     down  lock   unlock
42    12      12    2048        2048        124    2      2     9      9
1099  0       0     0           0           1984   0      0     0      0
1244  0       0     0           0           1221   100   1023   1023   1002
1337  123     99    125952      101376      193821 992   81921  7421   6392
```
