#include "callstack.h"
#include "log.h"
#include <sys/ptrace.h>
#include <libunwind-ptrace.h>

void callstack_unwind_log(Process *proc){
	pid_t pid = proc->pid;

	log_open();

        if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0){
		syslog(LOG_ERR, LOG_PREFIX"cannot log process(PID=%d) call stack due to ptrace ATTACH failed", pid);
		goto end;
	}


	unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
        void *context = _UPT_create(pid);
        unw_cursor_t cursor;
        if (unw_init_remote(&cursor, as, context) != 0){
		syslog(LOG_ERR, LOG_PREFIX"cannot log process(PID=%d, exe=%s) call stack due to stack cursor initilization failed", pid, proc->exe);
		goto end;
	}

	syslog(LOG_ERR, LOG_PREFIX"process(PID=%d, exe=%s) call stack prologue(bottom up)\n", pid, proc->exe);

	unw_word_t offset, ip;
	char sym[BUF_SIZE];
	while(unw_step(&cursor) > 0){
		memset(sym, 0, BUF_SIZE);

                if (unw_get_reg(&cursor, UNW_REG_IP, &ip)){
			syslog(LOG_ERR, LOG_PREFIX"call stack broken due to read instruction pointer failed");
			goto epi;
		}


                if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0)
			syslog(LOG_ERR, LOG_PREFIX"(%s+0x%lx)\n", sym, offset);
                else
			syslog(LOG_ERR, LOG_PREFIX"?? no symbol found\n");
	}

        _UPT_destroy(context);

        (void) ptrace(PTRACE_DETACH, pid, 0, 0);

epi:
	syslog(LOG_ERR, LOG_PREFIX"process(PID=%d, exe=%s) call stack epilogue\n", pid, proc->exe);

end:
	log_close();

	return;
}
