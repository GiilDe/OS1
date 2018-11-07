//
// Created by Gilad on 07-Nov-18.
//

#ifndef OS1_HW1_SYSCALLS_H
#define OS1_HW1_SYSCALLS_H

#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include "sched.h"

#define PASSWORD 234123
#define PRIVILEGE_DEFAULT 2

typedef struct forbidden_activity_info{
    int syscall_req_level;
    int proc_level;
    int time;
}log_record;

int enable_policy(pid_t pid,int size, int password){
    if(pid < 0){
        errno = ESRCH;
        return -1;
    }
    if(password != PASSWORD || size < 0){
        errno = EINVAL;
        return -1;
    }
    struct task_struct* info = find_task_by_pid(pid);
    if(info == NULL){ //TODO check if failure returns NULL
        errno = ESRCH;
        return -1;
    }
    if(info->policy_enabled == 1){
        errno = EINVAL;
        return -1;
    }
    info->policy_enabled = 1;
    info->privilege = PRIVILEGE_DEFAULT;
    info->log_array = malloc(sizeof(log_record)*size);
    if(info->log_array == NULL){
        errno = ENOMEM;
        return -1;
    }
    return 0;
}




#endif //OS1_HW1_SYSCALLS_H
