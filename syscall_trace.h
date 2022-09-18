#ifndef SYSCALL_TRACE_HDR
#define SYSCALL_TRACE_HDR

#include "basis.h"
#include <sys/ptrace.h>
#include <sys/reg.h>

int ptrace_wait_syscall(pid_t pid);
long _ptrace(int request, pid_t pid, void* addr, void* data);

int STOPPED;
int TERMINATED;

#endif
