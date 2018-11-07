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
    if(info == NULL){ //TODO check if failure returns NULL
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