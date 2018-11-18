#include <sys/types.h>
#include <unistd.h>
#include <sched.h>

#include "hw1_syscalls.h"

int main() {
  enable_policy(getpid(),-24,234123);// FAIL
  enable_policy(getpid(),1,2); // FAIL
  enable_policy(-1,1,234123); // FAIL
  enable_policy(getpid()*3,1,234123); // FAIL
  enable_policy(getpid(),10,234123);
  enable_policy(getpid(),1,234123); // FAIL
  
  set_process_capabilities(getpid(),1,234123);
  set_process_capabilities(getpid(),5,234123); //FAIL
  set_process_capabilities(getpid(),-6,234123); //FAIL
  
  disable_policy(-1,234123); // FAIL
  disable_policy(getpid(),1); // FAIL
  disable_policy(getpid()*3,234123); // FAIL
  disable_policy(getpid(),234123);
  disable_policy(getpid(),234123); // FAIL
  
  set_process_capabilities(getpid()*2,1,234123); // FAIL
  set_process_capabilities(getpid(),1,234123); // FAIL
  set_process_capabilities(getpid(),3,234123); // FAIL
  
  
  struct forbidden_activity_info* log = malloc(sizeof(struct forbidden_activity_info)*10);
  get_process_log(getpid(),0,log); // FAIL
  enable_policy(getpid(),10,234123);
  get_process_log(getpid(),0,log);
  get_process_log(-1,0,log); // FAIL
  get_process_log(getpid(),-1,log); // FAIL
  get_process_log(getpid(),100,log); // FAIL
  get_process_log(getpid(),2,log); // FAIL
  
  
  sched_yield();
  set_process_capabilities(getpid(),0,234123); 
  sched_yield();// FAIL
  sched_yield();// FAIL
  sched_yield();// FAIL
  get_process_log(getpid(),5,log);// FAIL
  get_process_log(getpid(),2,log);
  printf("Expecting two fail prints (sched_yield 1 and 2) with same pid:\n");
  printf("Tried to run syscall from %d which requires privilege %d while privilege is %d at time %d (sched_yield 1)\n",getpid(),log[0].syscall_req_level,log[0].proc_level,log[0].time);
  printf("Tried to run syscall from %d which requires privilege %d while privilege is %d at time %d (sched_yield 2)\n",getpid(),log[1].syscall_req_level,log[1].proc_level,log[1].time);
  get_process_log(getpid(),2,log);// FAIL
  get_process_log(getpid(),1,log);
  printf("Expecting one fail print (sched_yield 3) with same pid:\n");
  printf("Tried to run syscall from %d which requires privilege %d while privilege is %d at time %d (sched_yield 3)\n",getpid(),log[0].syscall_req_level,log[0].proc_level,log[0].time);
  
  
  disable_policy(getpid(),234123);
  enable_policy(getpid(),5,234123);
  set_process_capabilities(getpid(),0,234123); 
  sched_yield();// FAIL
  sched_yield();// FAIL
  sched_yield();// FAIL
  sched_yield();// FAIL
  get_process_log(getpid(),4,log);
  sched_yield();// FAIL
  sched_yield();// FAIL
  sched_yield();// FAIL
  get_process_log(getpid(),3,log); // shouldn't have problems with memory
  
  disable_policy(getpid(),234123);
  int initial = fork(); // works, we have 2 processes now
  enable_policy(getpid(),20,234123);
  set_process_capabilities(getpid(),0,234123);
  wait(); // FAIL in both
  if (initial) printf("Expecting two fail prints (wait 1) with different pid:\n");
  if (!get_process_log(getpid(),1,log)) {
    printf("Tried to run syscall from %d which requires privilege %d while privilege is %d at time %d (wait 1)\n",getpid(),log[0].syscall_req_level,log[0].proc_level,log[0].time);
  }
  set_process_capabilities(getpid(),2,234123);
  initial = fork() && initial; // success, we have 4 processes now
  get_process_log(getpid(),2,log); // FAIL
  if (initial) printf("Expecting two fail prints (fork 1) with different pid:\n");
  if (!get_process_log(getpid(),1,log)) { // FAIL in new processes, work in two old ones
    printf("Tried to run syscall from %d which requires privilege %d while privilege is %d at time %d (fork 1)\n",getpid(),log[0].syscall_req_level,log[0].proc_level,log[0].time);
  }
  enable_policy(getpid(),20,234123);
  set_process_capabilities(getpid(),2,234123); 
  initial = fork() && initial; // works, we have 8 processes now
  set_process_capabilities(getpid(),1,234123); 
  initial = fork() && initial; // fails in 4 new processes, we have 12 processes now.
  if (initial) printf("Expecting four fail prints (fork 2) with different pid:\n");
  if (!get_process_log(getpid(),1,log)) {
    printf("Tried to run syscall from %d which requires privilege %d while privilege is %d at time %d (fork 2)\n",getpid(),log[0].syscall_req_level,log[0].proc_level,log[0].time);
  }
  
  enable_policy(getpid(),20,234123);
  set_process_capabilities(getpid(),0,234123); 
  initial = fork() && initial; // fails in all 14 processes
  initial = fork() && initial; // fails in all 14 processes
  if (initial) printf("Expecting 24 fail prints (fork 3.1 and fork 3.2) with 12 different pid:\n");
  if (!get_process_log(getpid(),2,log)) {
    printf("Tried to run syscall from %d which requires privilege %d while privilege is %d at time %d (fork 3.1)\n",getpid(),log[0].syscall_req_level,log[0].proc_level,log[0].time);
    printf("Tried to run syscall from %d which requires privilege %d while privilege is %d at time %d (fork 3.2)\n",getpid(),log[1].syscall_req_level,log[1].proc_level,log[1].time);
  }
  disable_policy(getpid(),234123);
  enable_policy(getpid(),20000000,234123); // FAILs for memory (hopefully)
  return 0;
} 
 
