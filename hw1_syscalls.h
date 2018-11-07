//
// Created by Gilad on 07-Nov-18.
//

#ifndef OS1_HW1_SYSCALLS_H
#define OS1_HW1_SYSCALLS_H

#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include "sched.h"

#define SYSCALL_ENABLE_POLICY 243

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
    int res;
    __asm__(
        "int $0x80;"
        : "=a" (res)
        : "0" (SYSCALL_ENABLE_POLICY), "b" (pid), "c" (size), "d" (password)
        : "memory"
        );
    if((res) < 0) {
        errno = (-res);
        return -1;
    }

    return res;
}

#endif //OS1_HW1_SYSCALLS_H
