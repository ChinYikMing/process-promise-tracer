#include "basis.h"
#include "list.h"
#include "process.h"
#include "syscall_trace.h"
#include <libelf.h>
#include <sys/mman.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <json-glib/json-glib.h>

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

	JsonParser *parser = json_parser_new();
	JsonNode *node = json_node_new(JSON_NODE_OBJECT);
	json_parser_load_from_file(parser, "file.json", NULL);
	node = json_parser_get_root(parser);
    
	JsonObject *obj2 = json_object_new();
	obj2 = json_node_get_object(node);


	return true;
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

int fdlist_init(List **fdlist){
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*fdlist = tmp;
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

typedef struct mmap_buf {
        void *start;
        size_t len;
} Mmapbuf;

Mmapbuf *mmapbuf_create(void *buf_start, size_t buf_len){
	Mmapbuf *mmapbuf = malloc(sizeof(Mmapbuf));
	if(!mmapbuf)
		return NULL;

	mmapbuf->start = buf_start;
	mmapbuf->len = buf_len;
	return mmapbuf;
}

int mmapbuflist_init(List **mmapbuflist){
	List *tmp = malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*mmapbuflist = tmp;
	return 0;
}

bool process_exists(Process *proc){
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
}

bool process_is_dead(Process *proc){
	return proc->dead;
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
	proc->dead = false;

	return proc;
}

void process_destroy(Process *proc){
	munmap(proc, PROC_SIZE);
	return;
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

void process_syscall_trace_attach(Process *proc, int fd, int syscall){
    pid_t pid = proc->pid;

    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    fprintf(stderr, " [TRACE] Attached to process. Ok. \n");

    _ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*) PTRACE_O_TRACECLONE);

    _ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*) PTRACE_O_TRACESYSGOOD);

    struct user_regs_struct regs;
    fprintf(stderr, " [TRACE] Start event loop. Ok. \n");
    for(;;) {
        // Intercept system call entry 
        if (ptrace_wait_syscall(pid) == TERMINATED) {
            fprintf(stderr, " [TRACE] (1) Monitored process has terminated. \n");
            break;
        }

        // Intercept system call exit 
        if (ptrace_wait_syscall(pid) == TERMINATED) {
            fprintf(stderr, " [TRACE] (2) Monitored process has terminated. \n");
            break;
        }

        _ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        // Get system call number
        int _syscall = regs.orig_rax;
        if (_syscall == syscall) {
	    int _fd = (int) regs.r8;

	    if(_fd == fd){
		    void *buf_start = (void *) regs.rax;
		    size_t buf_len = (size_t) regs.rsi;

		    Mmapbuf *mmapbuf = mmapbuf_create(buf_start, buf_len);
		    Node *mmapbuf_node = node_create((void *) mmapbuf);
		    fprintf(stderr, "rax: %p\n", (void *)regs.rax);
		    fprintf(stderr, "rsi: %lld\n", regs.rsi);

		    list_push_back(proc->mmapbuflist, mmapbuf_node);
	    }

            /*
            fprintf(stderr, "rax: %p\n", (void *)regs.rax);
            fprintf(stderr, "rdi: %lld\n", regs.rdi);
            fprintf(stderr, "rsi: %lld\n", regs.rsi);
            fprintf(stderr, "rdx: %lld\n", regs.rdx);
            fprintf(stderr, "r10: %lld\n", regs.r10);
            fprintf(stderr, "r8 : %lld\n", regs.r8);
            fprintf(stderr, "r9 : %lld\n", regs.r9);
	    */
            continue;
        }
    }
	
}

// skip pid of repeat if 'repeat' in /proc/[pid]/task directory since it is same as [pid]
void scan_proc_dir(List *list, const char *dir, Process *repeat, double period, Config *cf){ 
    DIR *scan_dir = opendir(dir);
    DIRent *entry;
    Stat statbuf;
    mode_t mode;

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

	/*
	if(!process_promise_pass(proc)){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}
	*/

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

	if(!pre_exist){
		printf("new process, pid: %s, exe: %s, state: %c\n", name, proc->exe, proc->state);

		pid_t child = fork();
		if(child == 0){ 
			proc->tracer = child;

			fdlist_init(&proc->fdlist);
			mmapbuflist_init(&proc->mmapbuflist);

			while(1){
				sleep(1);

				// read process open fd list( read here because malloc memory cannot be shared with child )
				process_updateFdList(proc);

				// get mmap syscall info
				Node *iter;
				Fd *fd;
				LIST_FOR_EACH(proc->fdlist, iter){
					fd = LIST_ENTRY(iter, Fd);
					printf("fd: %d, path: %s\n", fd->nr, fd->path);

					if(0 == strcmp(fd->path, "/dev/video0")){
						process_syscall_trace_attach(proc, fd->nr, SYS_mmap); 

						/*
						Node *iter2;
						Mmapbuf *mmapbuf;
						LIST_FOR_EACH(proc->mmapbuflist, iter2){
							mmapbuf = LIST_ENTRY(iter2, Mmapbuf);
							printf("buf start: %p, buf len: %zu\n", mmapbuf->start, mmapbuf->len);
						}
						*/
					}
				}

				if(process_is_dead(proc)){
					printf("child exit\n");
					_exit(EXIT_SUCCESS);
				}
				
				// perf sampling address here
				
			}
		} else {
			list_push_back(list, proc_node);
		}
	} else { // exist before
		if(!process_is_zombie(proc)){
			if(!process_exists(proc)){ // check process if exists in /proc
				proc->dead = 1; // inform child the tracee is dead
			} else {
				process_updateExe(proc); // pid might be reused, then the exe could change, such as calling execve series function
				printf("pid: %d, state: %c, new_exe: %s\n", proc->pid, proc->state, proc->exe);
			}
		}
	}
    }

    closedir(scan_dir);
    return;
}

