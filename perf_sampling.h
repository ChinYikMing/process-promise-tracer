#ifndef PERF_SAMPLING_HDR
#define PERF_SAMPLING_HDR

#define PAGE_SIZE 4096      // fix me with sysconf()
#define PERF_RB_PAGE 16 

// according to man 2 perf_event_open, ring buffer size must be 1+2^n pages where the first page is the metadata page(struct perf_event_mmap_page)
#define PERF_RB_SIZE (1 + PERF_RB_PAGE) * PAGE_SIZE

#include <stdint.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include "process.h"
#include "perf_event.h"

typedef struct perf_sample {
        struct perf_event_header header;
        uint64_t sample_id;
        uint64_t ip;
        uint32_t pid, tid;
        uint64_t time;
        uint64_t addr;
        uint32_t cpu, res;
        uint64_t period;
        uint32_t size;
        char data[];
} sample_t;

typedef struct perf_fd {
        int fd;
        uint64_t sample_id;
        void *rb;
} Perf_fd;

int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags);

Perf_fd *perf_event_register(Process *proc, uint32_t type, event_t event, uint64_t sample_type);
int perf_event_unregister(Process *proc);

int perf_event_start(Process *proc);
int perf_event_stop(Process *proc);
int perf_event_reset(Process *proc);

void *perf_event_rb_get(int perf_fd, size_t pages);
void perf_event_rb_put(void *rb);

int perf_event_rb_read(Process *proc, Perf_fd *perf_fd, sample_t *sample);

#endif
