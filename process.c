#include "basis.h"
#include "list.h"
#include "process.h"
#include "signal.h"
#include "perf_va.h"
#include "perf_mem_event.h"
#include "cache_va.h"
#include <libelf.h>
#include <sys/mman.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <json-c/json.h>

bool if_parse_error(struct json_object* obj, Process *proc)
{
    if(obj == NULL)
    {
        send_signal(proc, SIGSTOP, "JSON file error\n");
		return false;
    }
	return true;
}

struct data {
 	char* val1;
	char* val2;
};

struct data *data_new(char* val1, char* val2){
	struct data *d = malloc(sizeof(struct data));
	if(!d)
		return NULL;

	d->val1 = val1;
	d->val2 = val2;
	return d;
}

bool process_promise_pass(Process *proc){

    	Elf64_Ehdr  *elf;
	Elf64_Shdr  *shdr;

	int fd = open(proc->exe, O_RDONLY);
	int filesize = lseek(fd,0,SEEK_END);
	uint8_t* data = mmap(NULL, filesize, PROT_READ, MAP_SHARED, fd, 0);

	elf = (Elf64_Ehdr *) data;
	shdr = (Elf64_Shdr *) (data + elf->e_shoff);
	char* strtab = (char *)(data + shdr[elf->e_shstrndx].sh_offset);
	int shNum = elf->e_shnum;
	for(int i=0;i<shNum;i++)
	{   
		if(0 != strcmp(&strtab[shdr[i].sh_name], ".test"))
		    continue;
		size_t k;
		FILE* fp;
		fp = fopen ("file.json", "w+");
		for (k = shdr[i].sh_offset; k < shdr[i].sh_offset + shdr[i].sh_size; k++) 
		{
		    fprintf(fp,"%c", data[k]);
		}   
		fclose(fp);
	}

	close(fd);
	munmap(data, filesize);


	char* json;
	struct json_object* obj;
	int fd1 = open("file.json", O_RDONLY); //file.json
	int fs = lseek(fd1,0,SEEK_END);
	json = mmap(NULL, fs, PROT_READ, MAP_PRIVATE, fd1, 0);
	close(fd1);

	device_list_init(&proc->device_list);
	access_file_list_init(&proc->access_file_list);

	obj = json_tokener_parse(json);

	if(!if_parse_error(obj, proc))
		return false;

	struct json_object* device = json_object_object_get(obj, "device");
	if(!if_parse_error(device, proc))
		return false;
	int len = json_object_array_length(device);
	Node *node;
	struct data *d;
	for(int i=0;i<len;i++)
	{
		struct json_object* jvalue = json_object_array_get_idx(device, i);
		struct json_object* device_i = json_object_object_get(jvalue, "device");
		struct json_object* mask = json_object_object_get(jvalue, "action_mask");
		if(!if_parse_error(device_i, proc) || !if_parse_error(mask, proc))
			return false;
		char* device_ = json_object_get_string(device_i);
		char* mask_ = json_object_get_string(mask);
		d = data_new(device_, mask_);
		node = node_create(d);
		list_push_back(proc->device_list, node);
	}

	struct json_object* files = json_object_object_get(obj, "files");
	if(!if_parse_error(files, proc))
		return false;
	len = json_object_array_length(files);
	for(int i=0; i<len; i++)
	{
		struct json_object* jvalue = json_object_array_get_idx(files, i);
		struct json_object* file_name = json_object_object_get(jvalue, "file_name");
		struct json_object* type = json_object_object_get(jvalue, "type");
		if(!if_parse_error(file_name, proc) || !if_parse_error(type, proc))
			return false;
		char* file_name_ = json_object_get_string(file_name);
		char* type_ = json_object_get_string(type);
		d = data_new(file_name_, type_);
		node = node_create(d);
		list_push_back(proc->access_file_list, node);
	}
	munmap(json, fs);
	return true;
}
int device_list_init(List** device_list)
{
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*device_list = tmp;
	return 0;
}

int access_file_list_init(List** access_file_list)
{
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*access_file_list = tmp;
	return 0;
}


typedef struct fd {
        unsigned int nr;
        char path[PATH_MAX];
} Fd;

Fd *fd_create(int fd, const char *path){
	Fd *_fd = malloc(sizeof(Fd));
	if(!_fd)
		return NULL;

	_fd->nr = fd;
	memset(_fd->path, 0, PATH_MAX);
	strcpy(_fd->path, path);

	return _fd;
}

void fd_destroy(Fd *fd){
	free(fd);
}

int fdlist_init(List **fdlist){
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*fdlist = tmp;
	return 0;
}

void fdlist_destroy(List *fdlist){
	Node *iter;
	Fd *fd;

	LIST_FOR_EACH(fdlist, iter){
		fd = LIST_ENTRY(iter, Fd);
		fd_destroy(fd);
	}
}

int cache_init(cacheline ***cache, int set, int assoc){
	void *tmp = cache_create(set, assoc);
	if(!tmp)
		return 1;

	*cache = tmp;
	return 0;
}

Node *list_get_node_by_pid(List *list, pid_t pid, bool *pre_exist){
	Node *node = NULL;
	Process *proc = NULL;

	LIST_FOR_EACH(list, node){
		proc = LIST_ENTRY(node, Process);
		if(proc->pid == pid){
			*pre_exist = true;
			return node;
		}
	}

	*pre_exist = false;
	return NULL;
}

Node *list_get_node_by_fd(List *list, int _fd){
	Node *node = NULL;
	Fd *fd = NULL;

	LIST_FOR_EACH(list, node){
		fd = LIST_ENTRY(node, Fd);
		if(fd->nr == _fd)
			return node;
	}
	return NULL;
}

typedef struct devbuf {
        char start[16];
        size_t len;
} Devbuf;

Devbuf *devbuf_create(const char *buf_start, size_t buf_len){
	Devbuf *devbuf = malloc(sizeof(Devbuf));
	if(!devbuf)
		return NULL;

	strcpy(devbuf->start, buf_start);
	devbuf->len = buf_len;
	return devbuf;
}

void devbuf_destroy(Devbuf *devbuf){
	free(devbuf);
}

int devbuflist_init(List **devbuflist){
	List *tmp = malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*devbuflist = tmp;
	return 0;
}

void devbuflist_destroy(List *devbuflist){
	Node *iter;
	Devbuf *devbuf;

	LIST_FOR_EACH(devbuflist, iter){
		devbuf = LIST_ENTRY(iter, Devbuf);
		devbuf_destroy(devbuf);
	}
}

bool process_exist(Process *proc){
	char pid[32] = {0};
	sprintf(pid, "%d", proc->pid);

	char proc_dir_path[PATH_MAX] = {0};
	strcpy(proc_dir_path, PROC_DIR);
	strcat(proc_dir_path, "/");
	strcat(proc_dir_path, pid);

	DIR *proc_dir = opendir(proc_dir_path);
	if(proc_dir){
		closedir(proc_dir);
		return true;
	} else if(ENOENT == errno){
		return false;
	} else { 
		// opendir other reasons failed
	}

	return false;
}

bool process_is_dead(Process *proc){
	return !process_exist(proc);
}

bool process_is_stop(Process *proc){
	return proc->state == 'T';
}

bool process_is_zombie(Process *proc){
	return proc->state == 'Z';
}

bool process_has_exe(Process *proc){
	return proc->exe[0] != 0;
}

bool process_is_kernel_thread(Process *proc){
	return proc->flags & PF_KTHREAD;
}

bool process_is_user_thread(Process *proc){
	return !process_is_kernel_thread(proc);
}

bool process_match_exe(Process *proc, const char *untrusted_proc){
	if(!process_has_exe(proc))
		return false;
	return (0 == strcmp(proc->exe, untrusted_proc)) ? true : false;
}

bool process_is_trusted(Process *proc, Config *cf){
	Conf *c = NULL;
	Node *n = cf->list->head;
	size_t cf_list_size = list_size(cf->list);

	for(size_t i = 0; i < cf_list_size; i++){
		c = n->data;
		if(0 == strcmp(c->key, "prog")){
			if(process_match_exe(proc, c->val)){
				return false;
			}
		}
		n = n->next;
	}

	return true;
}

Process *process_create(int pid){
	Process *proc = mmap(NULL, PROC_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(proc == MAP_FAILED)
		return NULL;

	proc->pid = pid;
	proc->state = 0;
	proc->flags = 0;
	memset(proc->exe, 0, sizeof(PATH_MAX));
	proc->tracer = 0;

	// perf related
	proc->perf_fd = -1;
	proc->sample_id = 0;
	proc->rb = NULL;

	return proc;
}

void process_destroy(Process *proc){
	munmap(proc, PROC_SIZE);
	return;
}

void process_clean(Process *proc){
	fdlist_destroy(proc->fdlist);
	devbuflist_destroy(proc->devbuflist);
	proc->pid = -1;
	proc->state = 'X';
	proc->flags = 0;
	memset(proc->exe, 0, sizeof(PATH_MAX));
	proc->tracer = 0;
	proc->perf_fd = -1;
	proc->sample_id = 0;
	proc->rb = NULL;
	proc->cache = NULL;
	proc->hit_cnt = 0;
	proc->miss_cnt = 0;
	proc->eviction_cnt = 0;
}

void process_updateExe(Process *proc){
	char pid[32] = {0};
	sprintf(pid, "%d", proc->pid);

	char exe_sym[32] = {0};
	strcpy(exe_sym, PROC_DIR);
	strcat(exe_sym, "/");
	strcat(exe_sym, pid);
	strcat(exe_sym, "/");
	strcat(exe_sym, "exe");

	if(access(exe_sym, F_OK) == 0){ // check because kernel thread do not has this file
		ssize_t size = readlink(exe_sym, proc->exe, PATH_MAX);
		proc->exe[size] = 0;

		assert(size != -1);
	}
}

/*
 * return 0 if not match device buffer, else match
 */
int parse_maps_line(const char *maps_line, char *devbuf_start, size_t *devbuf_len){
	if(strstr(maps_line, "/dev/video")){
		char *minus = strchr(maps_line, '-');
		char *space = strchr(maps_line, ' ');
		char start[16] = {0};
		char end[16] = {0};

		strncpy(start, maps_line, minus - maps_line);
		strncpy(end, minus + 1, space - (minus + 1));
		
		uint64_t start_num, end_num; 
		start_num = strtoll(start, NULL, 16);
		end_num = strtoll(end, NULL, 16);

		strncpy(devbuf_start, start, minus - maps_line);
		*devbuf_len  = end_num - start_num;
		return 1;
	}
	return 0;
}

void process_updateDevBufList(Process *proc){
	char pid[32] = {0};
	sprintf(pid, "%d", proc->pid);

	char maps_file[32] = {0};
	strcpy(maps_file, PROC_DIR);
	strcat(maps_file, "/");
	strcat(maps_file, pid);
	strcat(maps_file, "/");
	strcat(maps_file, "maps");

        FILE *maps = fopen(maps_file, "r");
        if(!maps){
	   return;
        }

	char maps_line[BUF_SIZE];
	char devbuf_start[BUF_SIZE];
	size_t devbuf_len;
	int ret;
	while(fgets(maps_line, BUF_SIZE, maps)){
		ret = parse_maps_line(maps_line, devbuf_start, &devbuf_len);
		if(ret){
			Devbuf *devbuf = devbuf_create(devbuf_start, devbuf_len);
	                Node *devbuf_node = node_create((void *) devbuf);

		        //fprintf(stderr, "debbuf_start: %s\n", devbuf_start);

                        list_push_back(proc->devbuflist, devbuf_node);
		}
	}
	fclose(maps);
}

void process_updateFdList(Process *proc){
	char pid[32] = {0};
	sprintf(pid, "%d", proc->pid);

	char fd_dir_path[32] = {0};
	strcpy(fd_dir_path, PROC_DIR);
	strcat(fd_dir_path, "/");
	strcat(fd_dir_path, pid);
	strcat(fd_dir_path, "/");
	strcat(fd_dir_path, "fd");

        DIR *fd_dir = opendir(fd_dir_path);
        DIRent *entry;
        if(!fd_dir){
	   return;
        }

	Node *fd_node = NULL;
	Fd *_fd = NULL;
	char fd_path[PATH_MAX];
	char fd_file[32];
        while((entry = readdir(fd_dir))){
	    const char *name = entry->d_name;
	    unsigned int fd = (unsigned int) strtol(name, NULL, 10);

            if(0 == strcmp(name, ".") || 0 == strcmp(name, ".."))
                continue;

	    memset(fd_path, 0, PATH_MAX);
	    memset(fd_file, 0, PATH_MAX);
	    strcpy(fd_file, fd_dir_path);
	    strcat(fd_file, "/");
	    strcat(fd_file, name);

	    ssize_t size = readlink(fd_file, fd_path, PATH_MAX);
	    fd_path[size] = 0;

	    fd_node = list_get_node_by_fd(proc->fdlist, fd);
	    if(fd_node) {
		    _fd = fd_node->data;
		    if(0 != strcmp(_fd->path, fd_path)) // check if the fd path has changed
			strcpy(_fd->path, fd_path); // update fd path

		    continue;
	    } 

	    Fd *_fd = fd_create(fd, fd_path);
	    Node *fd_node = node_create(_fd);
	    list_push_back(proc->fdlist, fd_node);
        }

        closedir(fd_dir);
        return;
}

int process_stat(Process *proc){
	char pid[32];
	sprintf(pid, "%d", proc->pid);

	// read stat file
	{
		char stat_file[32] = {0};
		strcpy(stat_file, PROC_DIR);
		strcat(stat_file, "/");
		strcat(stat_file, pid);
		strcat(stat_file, "/");
		strcat(stat_file, "stat");

		char buf[BUF_SIZE] = {0};
		FILE *stat_file_ptr = fopen(stat_file, "r");
		if(!stat_file_ptr)
			return 1;

		while(!feof(stat_file_ptr))
			fread(buf, sizeof(char), BUF_SIZE, stat_file_ptr);

		char *ptr = buf;

		// skip pid
		ptr = strchr(ptr, ' ');
		
		// skip comm
		ptr = strchr(ptr + 1, ' ');

		/*
		// fetch comm
		ptr = ptr + 2;
		qtr = strchr(ptr, ')');
		memcpy(proc->comm, ptr, qtr - ptr);
		qtr = NULL;
		ptr = strchr(ptr + 1, ' ');
		*/

		// fetch state
		ptr = ptr + 1;
		proc->state = *ptr;
		ptr = strchr(ptr + 1, ' ');

		// skip ppid
		ptr = strchr(ptr + 1, ' ');

		// skip pgrp
		ptr = strchr(ptr + 1, ' ');
		
		// skip session
		ptr = strchr(ptr + 1, ' ');
		
		// skip tty_nr
		ptr = strchr(ptr + 1, ' ');
		
		// skip tpgid
		ptr = strchr(ptr + 1, ' ');
		
		// fetch flags
		ptr = ptr + 1;
		sscanf(ptr, "%u", &proc->flags);

		fclose(stat_file_ptr);
	}

	// readlink executable
	process_updateExe(proc);

	return 0;
}

// skip pid of repeat if 'repeat' in /proc/[pid]/task directory since it is same as [pid]
void scan_proc_dir(List *list, const char *dir, Process *repeat, double period, Config *cf){ 
    DIR *scan_dir = opendir(dir);
    DIRent *entry;

    if(!scan_dir){ // finish scanning of /proc or /proc/[pid]/task
	return;
    }

    while((entry = readdir(scan_dir))){
	const char *name = entry->d_name;

        if(0 == strcmp(name, ".") || 0 == strcmp(name, ".."))
                continue;

	// skip self
	if(0 == strcmp(name, self_name))
		continue;

	// skip non-process entries
	if(entry->d_type != DT_DIR)
		continue;

	// skip non-number directories
	if(name[0] < '0' || name[0] > '9')
		continue;

	//printf("%s\n", name);

	// below are all /proc/[pid] directory
	// extract /proc/[pid] as pid_t to compare with repeat process's pid in task directory(thread) and skip tracing it
	pid_t pid;
	pid = (pid_t) strtol(name, NULL, 10);
	if(repeat && pid == repeat->pid)
		continue;

        char pid_path[PATH_MAX] = "";
        strcat(pid_path, dir);
        strcat(pid_path, "/");
        strcat(pid_path, name);
        strcat(pid_path, "/");
        strcat(pid_path, "task");

	bool pre_exist;

	Node *proc_node = list_get_node_by_pid(list, pid, &pre_exist);
	Process *proc = NULL;
	if(!proc_node){
		proc = process_create(pid);
		proc_node = node_create((void *) proc);
	} else {
		proc = proc_node->data;
	}
	process_stat(proc);

	scan_proc_dir(list, pid_path, proc, period, cf);

	if(process_is_stop(proc))
		continue;

	if(process_is_kernel_thread(proc)){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}

	if(process_is_trusted(proc, cf)){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}

	if(!process_promise_pass(proc)){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}

	if(!pre_exist){
		printf("new process, pid: %s, exe: %s, state: %c\n", name, proc->exe, proc->state);

		pid_t child = fork();
		if(child == 0){ 
			proc->tracer = child;

			fdlist_init(&proc->fdlist);
			devbuflist_init(&proc->devbuflist);

			int ret;
			va_sample_t va_sample;
			char expr[32];

			/*
			// cache L3
			int set_bit = 13;
			int assoc = 12;
			int block_bit = 6;
			int set_bit = 13; // 6
			*/

			/*
			// cache L1
			int assoc = 8;
			int block_bit = 6;
			int set_bit = 6;
			int set_size = 1 << set_bit;
			*/
			int assoc = 8;
			int block_bit = 20;
			int set_bit = 6;
			int set_size = 1 << set_bit;
			cache_init(&proc->cache, set_size, assoc);

			while(1){
				sleep(1);

				// read process open fd list( read here because malloc memory cannot be shared with child )
				process_updateFdList(proc);

				// get device mmap buffer list
				process_updateDevBufList(proc);

				if(process_is_dead(proc)){
					perf_event_stop(proc);
					perf_event_unregister(proc);
					printSummary(proc->hit_cnt, proc->miss_cnt, proc->eviction_cnt);
					process_clean(proc);
					printf("tracee exit\n");
					_exit(EXIT_SUCCESS);
				}
				
				// perf sampling address here
				if(-1 == proc->perf_fd){
					ret = perf_event_register(proc, ALL_LOADS);
					//ret = perf_event_register(proc, ALL_STORES);
					assert(0 == ret);
					perf_event_start(proc);
				}

				while(true){
					if(process_is_dead(proc)){
						perf_event_stop(proc);
						perf_event_unregister(proc);
						printSummary(proc->hit_cnt, proc->miss_cnt, proc->eviction_cnt);
						process_clean(proc);
						printf("tracee exit\n");
						_exit(EXIT_SUCCESS);
					}

					ret = perf_event_rb_read(proc, &va_sample);

					if(-EAGAIN == ret)
					{
					    usleep(10000);
					    continue;
					}
					else if(ret < 0){
						_exit(EXIT_FAILURE);
					} else {
					    if(va_sample.buf_addr >= 0x7fffee0f9000 && va_sample.buf_addr <= 0x7fffee3e7000) {
					    //if(va_sample.buf_addr >= 0x7fffec6b7000 && va_sample.buf_addr <= 0x7fffec9a5000) {
						    memset(expr, 0, 32);
						    sprintf(expr, "L %lx", va_sample.buf_addr);
						    cache_virtaddr(proc, set_bit, assoc, block_bit, expr);
						    //printf("addr: 0x%lx\n", va_sample.buf_addr);
					    }
					    //printf("addr: 0x%lx\n", va_sample.buf_addr);

					    /*
					    printf("pid: %u, tid: %u, buf address: 0x%lx\n",
						  va_sample.pid, va_sample.tid, va_sample.buf_addr);
						  */
					}
				}
			}
		} else {
			list_push_back(list, proc_node);
		}
	} else { // exist before
		if(!process_is_zombie(proc)){
			process_updateExe(proc); // pid might be reused, then the exe could change, such as calling execve series function
			printf("pid: %d, state: %c, new_exe: %s\n", proc->pid, proc->state, proc->exe);
		}
	}
    }

    closedir(scan_dir);
    return;
}

