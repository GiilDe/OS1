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

int sys_enable_policy(pid_t pid,int size, int password){
    if(pid < 0){
        return -ESRCH;
    }
    if(password != PASSWORD || size < 0){
        return -EINVAL;
    }
    struct task_struct* info = find_task_by_pid(pid);
    if(info == NULL){
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
    return 0;
}

int sys_disable_policy(pid_t pid, int password){
    if(pid < 0){
        return -ESRCH;
    }
    if(password != PASSWORD){
        return -EINVAL;
    }
    struct task_struct* info = find_task_by_pid(pid);
    if(info == NULL){
        return -ESRCH;
    }
    if(info->policy_enabled == 0){
        return -EINVAL;
    }
    kfree(info->log_array);
    info->policy_enabled = 0;
}

int sys_set_process_capabilities(pid_t pid, int new_level, int password){
    if(pid < 0){
        return -ESRCH;
    }
    if(password != PASSWORD){
        return -EINVAL;
    }
    if(new_level != 0 && new_level != 1 && new_level != 2){
        return -EINVAL;
    }
    struct task_struct* info = find_task_by_pid(pid);
    if(info == NULL){
        return -ESRCH;
    }
    if(!info->policy_enabled){
        return -EINVAL;
    }
    info->privilege = new_level;
}
