#include "perf_sampling.h"
#include "list.h"
#include "perf_event.h"
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

Perf_fd *perf_fd_create(int fd, uint64_t sample_id, void *rb){
        Perf_fd *perf_fd = malloc(sizeof(Perf_fd));
        if(!perf_fd)
                return NULL;

	perf_fd->fd = fd;
	perf_fd->sample_id = sample_id;
	perf_fd->rb = rb;

        return perf_fd;
}

Perf_fd *perf_event_register(Process *proc, uint32_t type, event_t event, uint64_t sample_type){
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(struct perf_event_attr));
    attr.type = type;
    attr.config = (uint64_t) event;
    attr.size = sizeof(struct perf_event_attr);
    attr.sample_type = sample_type;
    attr.disabled = 1;
    attr.exclude_user = 0;
    attr.exclude_kernel = 0;
    attr.precise_ip = 3;
    attr.sample_period = 10000;
    attr.wakeup_events = 1;
    //attr.inherit = 1;
    
    int fd = perf_event_open(&attr, proc->pid, -1, -1, 0);
    if(fd < 0)
    {
	handle_error("perf_event_open");
	return NULL;
    }

    // create ring buffer
    void *rb = perf_event_rb_get(fd, PERF_RB_SIZE);
    if(MAP_FAILED == rb)
    {
	handle_error("ring buffer mmap");
	return NULL;
    }

    // get id
    uint64_t id;
    int ret = ioctl(fd, PERF_EVENT_IOC_ID, &id);
    if(ret < 0)
    {
	handle_error("get sample id");
	munmap(rb, PERF_RB_SIZE);
	close(fd);
	return NULL;
    }

    Perf_fd *perf_fd = perf_fd_create(fd, id, rb);
    Node *perf_fd_node = node_create((void *) perf_fd);
    list_push_back(proc->perf_fdlist, perf_fd_node);

    return perf_fd;
}

int perf_event_unregister(Process *proc){
	List *perf_fd_list = proc->perf_fdlist;

	Node *iter;
	Perf_fd *perf_fd;


	LIST_FOR_EACH(perf_fd_list, iter){
		perf_fd = LIST_ENTRY(iter, Perf_fd);
		//printf("fd: %d, %p\n", perf_fd->fd, perf_fd->rb);
		close(perf_fd->fd);
		perf_event_rb_put(perf_fd->rb);
	}

	return 0;
}

int perf_event_start(Process *proc){
	List *perf_fd_list = proc->perf_fdlist;

	int ret;
	Node *iter;
	Perf_fd *perf_fd;

	LIST_FOR_EACH(perf_fd_list, iter){
		perf_fd = LIST_ENTRY(iter, Perf_fd);
		ret = ioctl(perf_fd->fd, PERF_EVENT_IOC_ENABLE, 0);
		if(ret == -1)
			handle_error("perf event start failed");
		
	}

	return 0;
}

int perf_event_stop(Process *proc){
	List *perf_fd_list = proc->perf_fdlist;

	int ret;
	Node *iter;
	Perf_fd *perf_fd;

	LIST_FOR_EACH(perf_fd_list, iter){
		perf_fd = LIST_ENTRY(iter, Perf_fd);
		ret = ioctl(perf_fd->fd, PERF_EVENT_IOC_DISABLE, 0);
		if(ret == -1)
			handle_error("perf event stop failed");
		
	}

	return 0;
}

int perf_event_reset(Process *proc){
	List *perf_fd_list = proc->perf_fdlist;

	int ret;
	Node *iter;
	Perf_fd *perf_fd;

	LIST_FOR_EACH(perf_fd_list, iter){
		perf_fd = LIST_ENTRY(iter, Perf_fd);
		ret = ioctl(perf_fd->fd, PERF_EVENT_IOC_RESET, 0);
		if(ret == -1)
			handle_error("perf event reset failed");
		
	}

	return 0;
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

int perf_event_rb_read(Process *proc, Perf_fd *perf_fd, sample_t *sample){
	if(!perf_fd)
		return -EINVAL;

	uint64_t sample_id = perf_fd->sample_id;
	void *rb = perf_fd->rb;
	if(!rb)
		return -EINVAL;
	
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
		uint64_t pos = tail % (PAGE_SIZE * PERF_RB_PAGE);
		sample_t *ent = (sample_t *)((char*) rb + PAGE_SIZE /* meta page */ + pos);

		tail += ent->header.size; // skip header to read data

		if(ent->header.type == PERF_RECORD_SAMPLE && 
	     	     ent->sample_id == sample_id && 
		       ent->pid == proc->pid){

			sample->ip = ent->ip;
                        sample->pid = ent->pid;
                        sample->tid = ent->tid;
                        sample->cpu = ent->cpu;
                        sample->res = ent->res;
                        sample->time = ent->time;
			sample->addr = ent->addr;
                        sample->size = ent->size;
                        memcpy(sample->data, ent->data, ent->size);

			available = true;
			break;
		}
	}

	rb_meta->data_tail = tail; // update tail since kernel does not wrap

	return available ? 0 : -EAGAIN;
}
