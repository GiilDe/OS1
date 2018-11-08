//
// Created by Miki Mints on 11/7/18.
//
#include<linux/kernel.h>
#include<linux/sched.h>

#define PASSWORD 234123
#define PRIVILEGE_DEFAULT 2

#define ESRCH 3
#define EINVAL 22
#define ENOMEM 12

static int validate_syscall_parameters(pid_t pid, int password) {
    if(pid < 0) {
        return -ESRCH;
    }

    if(password != PASSWORD) {
        return -EINVAL;
    }
    return 0;
}

/**
 * Enable policy enforcement for a given process (Disabled by default)
 * @param pid The process ID of the given process
 * @param size Maximum number of forbidden activity logs for the process
 * @param password Administrator password
 * @return 0 for success, otherwise returns -errno with a given error code
 */
int sys_enable_policy(pid_t pid, int size, int password){
    int res = validate_syscall_parameters(pid, password);
    if(res < 0) return res;

    if(size < 0) {
        return -EINVAL;
    }

    struct task_struct* info = find_task_by_pid(pid);

    if(info == NULL) {
        return -ESRCH;
    }

    if(info->policy_enabled == 1){
        return -EINVAL;
    }

    info->policy_enabled = 1;
    info->privilege = PRIVILEGE_DEFAULT;
    info->log_array = kmalloc(sizeof(struct forbidden_activity_info)*size);

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
    int res = validate_syscall_parameters(pid, password);
    if(res < 0) return res;

    struct task_struct* info = find_task_by_pid(pid);

    if(info == NULL) {
        return -ESRCH;
    }

    if(info->policy_enabled == 0) {
        return -EINVAL;
    }

    printk("Disabling policy for process %d\n", pid);
    kfree(info->log_array);
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
    int res = validate_syscall_parameters(pid, password);
    if(res < 0) return res;

    if(new_level < 0 || new_level > 2) {
        return -EINVAL;
    }

    struct task_struct* info = find_task_by_pid(pid);

    if(info == NULL) {
        return -ESRCH;
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

    if (!info->policy_enabled || size < 0 || size > info->log_array_size) {
        return -EINVAL;
    }

    int i;

    for (i = 0; i < size; ++i) {
        user_mem[i] = info->log_array[i];
    }

    int new_size = info->log_array_size - size;
    log_record *temp = kmalloc(sizeof(struct forbidden_activity_info) * new_size);

    if(temp == NULL) {
        return -ENOMEM;
    }

    printk("Removing %d activity logs from process %d\n", size, pid);

    for (i = size; i < info->log_array_size; ++i) {
        temp[i] = info->log_array[i];
    }

    kfree(info->log_array);
    info->log_array = temp;
    return 0;
}