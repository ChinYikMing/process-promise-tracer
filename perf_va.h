#ifndef PERF_VA_HDR
#define PERF_VA_HDR

#define PAGE_SIZE 4096      // fix me with sysconf()
#define PERF_RB_PAGE 1+16 // according to man 2 perf_event_open, ring buffer size must be 1+2^n pages where the first page is the metadata page(struct perf_event_mmap_page)
#define PERF_RB_SIZE PERF_RB_PAGE * PAGE_SIZE

#include <stdint.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include "process.h"
#include "perf_mem_event.h"

typedef struct va_sample {
	uint32_t pid, tid;
	uint64_t buf_addr;
} va_sample_t;

int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags);

int perf_event_register(Process *proc, mem_event_t event);
int perf_event_unregister(Process *proc);

int perf_event_start(Process *proc);
int perf_event_stop(Process *proc);
int perf_event_reset(Process *proc);

void *perf_event_rb_get(int perf_fd, size_t pages);
void perf_event_rb_put(void *rb);

int perf_event_rb_read(Process *proc, va_sample_t *sample);

#endif
