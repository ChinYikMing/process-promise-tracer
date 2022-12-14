#ifndef PROCESS_HDR
#define PROCESS_HDR

#include "list.h"
#include <pthread.h>
#include "config.h"
#include <limits.h>

#define PROC_SIZE (PAGE_SIZE << 1) // PATH_MAX already occupy a PAGE_SIZE so we have to left shift 1 bit

typedef struct process {
	pid_t pid;       // -1 is dead
	char state;      // running, sleeping in an interruptible wait, waiting in uninterruptible disk sleep, zombie, stopped
	uint32_t flags;  // currently used for detecting if is a kernel thread and skip tracing it because normally kernel threads are safe
	char exe[PATH_MAX];
	pid_t tracer;
	List *fdlist;
	List *devbuflist;

	List *device_list;
	List *access_file_list;
	List *connection_list;

	// perf related
	List *perf_fdlist;
	List *write_sample_list;
	List *socket_write_sample_list;
	pthread_spinlock_t wsl_lock, swsl_lock;    // wsl = "write sample list", swsl = "socket write sample list"
	int last_run_cpu;

	int tty_nr;
	char tty_path[32];

	// device mmap memory hit count
	int hit;
} Process;

Process *process_create(int pid);
void process_destroy(Process *proc);
void scan_proc_dir(List *process_list, const char *dir, Process *repeat);

pid_t self_pid;
char self_name[16];

#define PROC_DIR "/proc"

#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

#endif
