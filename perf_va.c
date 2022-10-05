#include "perf_va.h"
#include "perf_mem_event.h"
#include "basis.h"
#include "process.h"
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/ioctl.h>

#define READ_MEMORY_BARRIER()   __builtin_ia32_lfence()

int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags){
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int perf_event_register(Process *proc, mem_event_t event){
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(struct perf_event_attr));
    attr.type = PERF_TYPE_RAW;
    attr.config = (uint64_t) event;
    attr.size = sizeof(struct perf_event_attr);
    attr.sample_period = 100000;
    // sample sample_id, pid, tid, address
    attr.sample_type = PERF_SAMPLE_IDENTIFIER /* for parsing more easily */ | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR;
    attr.disabled = 1;
    attr.exclude_user = 0;
    attr.exclude_kernel = 0;
    attr.precise_ip = 3;
    //attr.inherit = 1;
    //attr.wakeup_events = WAKEUP_EVENTS;
    
    int fd = perf_event_open(&attr, proc->pid, -1, -1, 0);
    if(fd < 0)
    {
        int ret = -errno;
	handle_error("perf_event_open");
	return ret;
    }

    // create ring buffer
    void *buf = perf_event_rb_get(fd, PERF_RB_SIZE);
    if(MAP_FAILED == buf)
    {
        int ret = -errno;
	handle_error("ring buffer mmap");
	return ret;
    }

    // get id
    uint64_t id;
    int ret = ioctl(fd, PERF_EVENT_IOC_ID, &id);
    if(ret < 0)
    {
        int ret = -errno;
	handle_error("get sample id");
	munmap(buf, PERF_RB_SIZE);
	close(fd);
	return ret;
    }

    proc->perf_fd = fd;
    proc->sample_id = id;
    proc->rb = buf;
    return 0;
}

int perf_event_unregister(Process *proc){
	perf_event_rb_put(proc->rb);
	int ret = close(proc->perf_fd);
	assert(0 == ret);
	return 0;
}

int perf_event_enable(int perf_fd){

}

int perf_event_disable(int perf_fd){

}

int perf_event_start(int perf_fd){
	return ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
}

int perf_event_stop(int perf_fd){
	return ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
}

int perf_event_reset(int perf_fd){
	return ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
}

void *perf_event_rb_get(int perf_fd, size_t pages){
	void *rb = mmap(NULL, PERF_RB_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
	if(MAP_FAILED == rb){
		perror("mmap ring buffer");
		return MAP_FAILED;
	}

	return rb;
}

void perf_event_rb_put(void *rb){
	if(!rb)
		return;
	
	int ret = munmap(rb, PERF_RB_SIZE);
	assert(0 == ret);
	return;
}

struct perf_sample {
	struct perf_event_header header;
	uint64_t sample_id;
	uint32_t pid, tid;
	uint64_t addr;
};

int perf_event_rb_read(Process *proc, va_sample_t *sample){
	void *rb = proc->rb;

	if(!rb){
		//fprintf(stderr, "ring buffer is NULL\n");
		return -EAGAIN;
	}
	
	// the metadata header
	struct perf_event_mmap_page *rb_meta = (struct perf_event_mmap_page *) rb;
	uint64_t head = rb_meta->data_head;
	uint64_t tail = rb_meta->data_tail;

	READ_MEMORY_BARRIER();
	assert(tail <= head);
	if(head == tail){
		//fprintf(stderr, "ring buffer is empty\n");
		return -EAGAIN;
	}

	bool available = false;

	while(tail < head){
		uint64_t pos = tail % (PAGE_SIZE * PERF_RB_SIZE);
		struct perf_sample *ent = (struct perf_sample *)((char*) rb + PAGE_SIZE /* meta page */ + pos);

		tail += ent->header.size; // skip header to read data

		if(ent->header.type == PERF_RECORD_SAMPLE && 
	     	     ent->sample_id == proc->sample_id && 
		       ent->pid == proc->pid){

			sample->pid = ent->pid;
			sample->tid = ent->tid;
			sample->buf_addr = ent->addr;
			available = true;
			break;
		}
	}

	rb_meta->data_tail = tail; // update tail since kernel does not wrap

	return available ? 0 : -EAGAIN;
}
