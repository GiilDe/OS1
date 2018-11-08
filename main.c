//
// Created by Miki Mints on 11/7/18.
//
#include "hw1_syscalls.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <sched.h>

#define ADMIN_PASS 234123
#define ADMIN_PASS_INCORRECT 234124
#define PID_INVALID 60000
#define NUM_LOGS 10

#define RUN_TEST(test) assert(test() == 0)

static int enable_self_policy() {
    return enable_policy(getpid(), NUM_LOGS, ADMIN_PASS);
}

int test_fork_policy() {
    int res = enable_self_policy();
    assert(res == 0);
    res = set_process_capabilities(getpid(), 1, ADMIN_PASS);
    assert(res == 0);
    int pid = fork();
    if(pid != 0) {
        assert(pid == -1);
        assert(errno == EINVAL);
    } else {
        exit(0);
    }

    return 0;
}

int test_sched_yield_policy() {
    enable_self_policy();
    int res;

    set_process_capabilities(getpid(), 0, ADMIN_PASS);
    res = sched_yield();
    assert(res == -1 && errno == EINVAL);
    set_process_capabilities(getpid(), 1, ADMIN_PASS);
    res = sched_yield();
    assert(res == 0);

}

int main() {
    int res = enable_policy(getpid(), 10, ADMIN_PASS);
    assert(res == 0);
    res = enable_policy(getpid(), 10, ADMIN_PASS);
    assert(res == -1 && errno == EINVAL); // Already enabled

    res = disable_policy(getpid(), ADMIN_PASS_INCORRECT);
    assert(res == -1 && errno == EINVAL); // Incorrect password

    res = disable_policy(getpid(), ADMIN_PASS);
    assert(res == 0);

    res = disable_policy(getpid(), ADMIN_PASS);
    assert(res == -1 && errno == EINVAL); // Already disabled

    res = enable_policy(getpid(), -1, ADMIN_PASS);
    assert(res == -1 && errno == EINVAL); // Invalid size argument

    res = enable_policy(PID_INVALID, 10, ADMIN_PASS);
    assert(res == -1 && errno == ESRCH); // No such process

    RUN_TEST(test_fork_policy);
    RUN_TEST(test_sched_yield_policy);

    return 0;
}
