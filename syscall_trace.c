#include "syscall_trace.h"
#include <sys/wait.h>

int STOPPED     = 0;
int TERMINATED  = 1;

long _ptrace(int request, pid_t pid, void* addr, void* data) {
    long r = ptrace((enum __ptrace_request)request, pid, addr, data);
    if (r == -1) {
        fprintf(stderr,  " [TRACE FAILURE] \n errno = %d\n msg   = %s\n", errno, strerror(errno));
	return 1;
    }
    return r;
}

int ptrace_wait_syscall(pid_t pid) {
    int  status;

    for (;;) {
        _ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) { return TERMINATED; }
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) { return STOPPED; }
    }
}
