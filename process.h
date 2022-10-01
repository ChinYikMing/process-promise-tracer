#ifndef PROCESS_HDR
#define PROCESS_HDR

#include "list.h"
#include "config.h"
#include <limits.h>

#define PROC_SIZE (PAGE_SIZE << 1) // PATH_MAX already occupy a PAGE_SIZE so we have to left shift 1 bit

typedef struct process {
	pid_t pid;
	char state; // running, sleeping in an interruptible wait, waiting in uninterruptible disk sleep, zombie, stopped
	uint32_t flags;  // currently used for detecting if is a kernel thread and skip tracing it because normally kernel threads are safe
	char exe[PATH_MAX];
	pid_t tracer;
	List *fdlist;
	List *mmapbuflist;
} Process;

Process *process_create(int pid);
void process_destroy(Process *proc);
void scan_proc_dir(List *list, const char *dir, Process *repeat, double period, Config *cf);

pid_t self_pid;
char self_name[16];

#define PROC_DIR "/proc"

#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

#endif
