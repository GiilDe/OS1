//
// Created by Miki Mints on 11/7/18.
//
#include "hw1_syscalls.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

int main() {
    int res = enable_policy(getpid(), 10, 234123);
    assert(res == 0);
    res = enable_policy(getpid(), 10, 234123);
    printf("Result: %d", res);
    assert(res == -1);
    assert(errno == EINVAL);
    return 0;
}
