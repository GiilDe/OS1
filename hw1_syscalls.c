//
// Created by Miki Mints on 11/7/18.
//
#include<linux/kernel.h>
#include<linux/sched.h>
#include<linux/errno.h>
#include<linux/slab.h>
#include<asm/uaccess.h>

#define PASSWORD 234123
#define PRIVILEGE_DEFAULT 2

/**
 * Enable policy enforcement for a given process (Disabled by default)
 * @param pid The process ID of the given process
 * @param size Maximum number of forbidden activity logs for the process
 * @param password Administrator password
 * @return 0 for success, otherwise returns -errno with a given error code
 */
int sys_enable_policy(pid_t pid, int size, int password){
    if(pid < 0) {
        return -ESRCH;
    }

    struct task_struct* info = find_task_by_pid(pid);

    if(info == NULL) {
        return -ESRCH;
    }

    if(password != PASSWORD) {
        return -EINVAL;
    }

    if(info->policy_enabled == 1){
        return -EINVAL;
    }

    if(size < 0) {
        return -EINVAL;
    }

    info->policy_enabled = 1;
    info->privilege = PRIVILEGE_DEFAULT;
    info->log_array = kmalloc(sizeof(struct forbidden_activity_info)*size, GFP_KERNEL);
    info->num_logs = 0;

    if(info->log_array == NULL) {
        return -ENOMEM;
    }

    printk("Enabling policy for process %d\n", pid);
    info->log_array_size = size;
    return 0;
}

/**
 * Disable policy enforcement for a given process (Disabled by default)
 * @param pid The process ID of the given process
 * @param password Administrator password
 * @return 0 for success, otherwise returns -errno with a given error code
 */
int sys_disable_policy(pid_t pid, int password){
    if(pid < 0)
        return -ESRCH;

    struct task_struct* info = find_task_by_pid(pid);

    if(info == NULL) {
        return -ESRCH;
    }

    if(info->policy_enabled == 0) {
        return -EINVAL;
    }

    if(password != PASSWORD) {
        return -EINVAL;
    }

    printk("Disabling policy for process %d\n", pid);
    kfree(info->log_array);
    info->log_array = NULL;
    info->num_logs = 0;
    info->policy_enabled = 0;
    return 0;
}

/**
 * Set a new privilege level for a process
 * @param pid The process ID
 * @param new_level The new privilege level (between 0 and 2)
 * @param password Administrator password
 * @return 0 for success, otherwise returns -errno with a given error code
 */
int sys_set_process_capabilities(pid_t pid, int new_level, int password){
    if(pid < 0)
        return -ESRCH;

    struct task_struct* info = find_task_by_pid(pid);

    if(info == NULL) {
        return -ESRCH;
    }

    if(new_level < 0 || new_level > 2) {
        return -EINVAL;
    }

    if(password != PASSWORD) {
        return -EINVAL;
    }

    if(!info->policy_enabled){
        return -EINVAL;
    }

    printk("Setting policy privilege %d for process %d\n", new_level, pid);
    info->privilege = new_level;
    return 0;
}

/**
 * Removes the first {@param size} activity logs from a given process, and returns them
 * @param pid The process ID
 * @param size The number of activity logs to return
 * @param user_mem An array of forbidden activity logs where the logs will be returned
 * @return 0 for success, otherwise returns -errno with a given error code
 */
int sys_get_process_log(pid_t pid, int size, struct forbidden_activity_info*
                        user_mem) {
    if (pid < 0) {
        return -ESRCH;
    }

    struct task_struct *info = find_task_by_pid(pid);

    if (info == NULL) {
        return -ESRCH;
    }

    if (!info->policy_enabled || size < 0 || size > info->log_array_size || size > info->num_logs) {
        return -EINVAL;
    }

    copy_to_user(user_mem, info->log_array,
                 sizeof(struct forbidden_activity_info)*size);

    int new_size = info->log_array_size - size;
    log_record *temp = kmalloc(sizeof(struct forbidden_activity_info)*new_size, GFP_KERNEL);

    if(temp == NULL) {
        return -ENOMEM;
    }

    printk("Removing %d activity logs from process %d\n", size, pid);
    int i;
    for (i = size; i < info->num_logs; ++i) {
        temp[i] = info->log_array[i];
    }

    kfree(info->log_array);
    info->log_array = temp;
    info->num_logs -= size;
    info->log_array_size = new_size;
    return 0;
}