#include "basis.h"
#include <pthread.h>
#include <arpa/inet.h>
#include "list.h"
#include "callstack.h"
#include "process.h"
#include <poll.h>
#include "net.h"
#include <libgen.h>
#include "signal.h"
#include "perf_sampling.h"
#include "perf_va.h"
#include "cpu.h"
#include "perf_trp.h"
#include "perf_event.h"
#include "config.h"
#include "cache_va.h"
#include "log.h"
#include <libelf.h>
#include <sys/mman.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <json-c/json.h>

int assoc = 0;
int block_bit = 0;
int set_bit = 0;
int set_size = 0;

typedef struct fd {
        int nr;
        char path[PATH_MAX];
} Fd;

typedef struct devbuf {
        char start[16];
        size_t len;
} Devbuf;

struct data {
 	char* val1;
	char* val2;
};

typedef struct write_sample {
	unsigned long fd;
	unsigned long buf;
	unsigned long len;
} WriteSample;

typedef struct thread_data {
	Process *proc;    // to get pid
	Perf_fd *perf_fd; // to get sample_id and rb
} pthread_data_t;

static int fdlist_init(List **fdlist){
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*fdlist = tmp;
	return 0;
}

static int perffdlist_init(List **perffdlist){
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*perffdlist = tmp;
	return 0;
}

static int device_list_init(List** device_list)
{
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*device_list = tmp;
	return 0;
}

static int access_file_list_init(List** access_file_list)
{
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*access_file_list = tmp;
	return 0;
}

static int connection_list_init(List** connection_list)
{
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*connection_list = tmp;
	return 0;
}

static bool get_action_bit(const char *action, int index){
	size_t len = strlen(action);

	if(index < 0 || index > len)
		goto end;

	for(size_t i = len; i > 0; i--){
		if((len - index - 1) == i)
			return (action[i] == '1');
	}

end:
	return false;
}

static bool using_camera(Process *proc){
	Node *iter;
	Fd *fd;

	LIST_FOR_EACH(proc->fdlist, iter){
		fd = LIST_ENTRY(iter, Fd);
		if(0 == strcmp(fd->path, "/dev/video0"))
			return true;
	}

	return false;
}

static bool load_evt_high(Process *proc){
	return (proc->hit_cnt > 0);
}

static bool invalid_write(Process *proc, bool save){
	List *access_file_list = proc->access_file_list;
	List *wsl = proc->write_sample_list;

	if((save && 0 == list_size(access_file_list)) || // not specified to write file in promise but tend to write file
	   (!save && list_size(wsl) > 0))               // should not have any write sample if not tend to write file
		return true;

	if(!save && 0 == list_size(wsl))               // no write sample => commitment
		return false;

	Node *iter, *fileiter;
	struct data *filedata;
	size_t i;
	WriteSample *ws;
	char buf[BUF_SIZE] = {0};
	char basepath[BUF_SIZE] = {0};
	char path[BUF_SIZE] = {0};
	int ret;
	char pidstr[32] = {0};
	char fdstr[32] = {0};

	sprintf(pidstr, "%d", proc->pid);

	strcpy(basepath, PROC_DIR);
	strcat(basepath, "/");
	strcat(basepath, pidstr);
	strcat(basepath, "/");
	strcat(basepath, "fd");
	strcat(basepath, "/");

	pthread_spin_lock(&proc->wsl_lock);
	for(i = 0, iter = wsl->head; i < list_size(wsl); i++, iter = iter->next){
		ws = iter->data;

		sprintf(fdstr, "%lu", ws->fd);
		strcpy(path, basepath);
		strcat(path, fdstr);
		ret = readlink(path, buf, BUF_SIZE);
		if(-1 == ret)
			continue;
		buf[ret] = 0;

		LIST_FOR_EACH(access_file_list, fileiter){
			filedata = LIST_ENTRY(fileiter, struct data);
			if(0 == strcmp(filedata->val1, basename(buf))){
				pthread_spin_unlock(&proc->wsl_lock);
				return false;
			}
		}

		//printf("fd: %lu, buf: %lu, len: %lu\n", ws->fd, ws->buf, ws->len);
	}
	pthread_spin_unlock(&proc->wsl_lock);

	return true;
}

static bool invalid_streaming(Process *proc, bool stream){
	List *connection_list = proc->connection_list;
	List *swsl = proc->socket_write_sample_list;

	if((stream && 0 == list_size(connection_list)) || // not specified connections in promise but tend to write data via connections
	   (!stream && list_size(swsl) > 0))               // should not have any write sample if not tend to stream
		return true;

	if(!stream && 0 == list_size(swsl))               // no socket write sample => commitment
		return false;

	Node *iter, *conn_iter;
	struct data *conn;
	size_t i;
	WriteSample *ws;
	char buf[BUF_SIZE] = {0};
	char basepath[BUF_SIZE] = {0};
	char path[BUF_SIZE] = {0};
	int ret;
	char pidstr[32] = {0};
	char sockfdstr[32] = {0};

	sprintf(pidstr, "%d", proc->pid);

	strcpy(basepath, PROC_DIR);
	strcat(basepath, "/");
	strcat(basepath, pidstr);
	strcat(basepath, "/");
	strcat(basepath, "fd");
	strcat(basepath, "/");

	pthread_spin_lock(&proc->swsl_lock);
	for(i = 0, iter = swsl->head; i < list_size(swsl); i++, iter = iter->next){
		ws = iter->data;

		sprintf(sockfdstr, "%lu", ws->fd);
		strcpy(path, basepath);
		strcat(path, sockfdstr);
		ret = readlink(path, buf, BUF_SIZE);
		if(-1 == ret)
			continue;
		buf[ret] = 0;

		if(0 == strncmp(buf, "socket:[", 8)){
			char rem_addr[64] = {0};
			char ip[64] = {0};
			char port[32] = {0};
			char ipport[128];
			int tcp;
			int ipv4;
			get_rem_addr_by_sockfd(proc, ws->fd, rem_addr, &tcp, &ipv4);
			get_ip_port_from_rem_addr(rem_addr, ipv4, ip, port);
			strcpy(ipport, ip);
			strcat(ipport, ":");
			strcat(ipport, port);

			LIST_FOR_EACH(connection_list, conn_iter){
				conn = LIST_ENTRY(conn_iter, struct data);
				if(0 == strcmp(conn->val1, ipport)){
					pthread_spin_unlock(&proc->swsl_lock);
					return false;
				}
			}
		}

		//printf("fd: %lu, buf: %lu, len: %lu\n", ws->fd, ws->buf, ws->len);
	}
	pthread_spin_unlock(&proc->swsl_lock);

	return true;
}


static int get_ttypath(Process *proc){
	// parsing /dev/pts to get tty which match tty_nr
        char tty_path[PATH_MAX];
        strcpy(tty_path, "/dev/pts/");

        DIR *tty_dir = opendir(tty_path);
        if(!tty_dir){
                printf("tty dir open failed\n");
                return -1;
        }

        struct dirent *tty_entry;
        struct stat tty_stat;
        while((tty_entry = readdir(tty_dir))){
                strcpy(tty_path, "/dev/pts/");
                strcat(tty_path, tty_entry->d_name);
                stat(tty_path, &tty_stat);

                if(proc->tty_nr == tty_stat.st_rdev){
			strcpy(proc->tty_path, tty_path);	
                        break;
		}
        }
        closedir(tty_dir);
	return 0;
}

bool if_parse_error(struct json_object* obj, Process *proc)
{
    if(obj == NULL)
    {
        send_signal(proc, SIGSTOP, "JSON promise file error\n");
		return false;
    }
	return true;
}

struct data *data_new(const char* val1, const char* val2){
	struct data *d = malloc(sizeof(struct data));
	if(!d)
		return NULL;

	d->val1 = strdup(val1);
	d->val2 = strdup(val2);
	return d;
}

bool process_promise_pass(Process *proc){

	if(proc->device_list != NULL)
	{
		return true;
	}
    	Elf64_Ehdr  *elf;
	Elf64_Shdr  *shdr;

	int fd = open(proc->exe, O_RDONLY);
	int filesize = lseek(fd,0,SEEK_END);
	uint8_t* data = mmap(NULL, filesize, PROT_READ, MAP_SHARED, fd, 0);

	elf = (Elf64_Ehdr *) data;
	shdr = (Elf64_Shdr *) (data + elf->e_shoff);
	char* strtab = (char *)(data + shdr[elf->e_shstrndx].sh_offset);
	int shNum = elf->e_shnum;
	int i;
	for(i=0;i<shNum;i++)
	{   
		if(0 != strcmp(&strtab[shdr[i].sh_name], ".test"))
		    continue;
		size_t k;
		FILE* fp;
		fp = fopen ("file.json", "w+");
		if(shdr[i].sh_size == 0)
		{
			send_signal(proc, SIGKILL, "JSON promise file is empty\n");
			return false;
		}
		for (k = shdr[i].sh_offset; k < shdr[i].sh_offset + shdr[i].sh_size; k++) 
		{
		    fprintf(fp,"%c", data[k]);
		}   
		fclose(fp);
		break;
	}
	if(i == shNum) // No .test section exist
	{
		send_signal(proc, SIGKILL, "No JSON promise file exist\n");
		return false;
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
	connection_list_init(&proc->connection_list);

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
		const char* device_ = json_object_get_string(device_i);
		const char* mask_ = json_object_get_string(mask);
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
		const char* file_name_ = json_object_get_string(file_name);
		const char* type_ = json_object_get_string(type);
		d = data_new(file_name_, type_);
		node = node_create(d);
		list_push_back(proc->access_file_list, node);
	}

	struct json_object* con = json_object_object_get(obj, "connections");
	if(!if_parse_error(con, proc))
		return false;
	len = json_object_array_length(con);
	for(int i=0; i<len; i++)
	{
		struct json_object* jvalue = json_object_array_get_idx(con, i);
		struct json_object* ipport = json_object_object_get(jvalue, "ipport");
		struct json_object* mask = json_object_object_get(jvalue, "action_mask");
		if(!if_parse_error(ipport, proc) || !if_parse_error(mask, proc))
			return false;
		const char* ipport_ = json_object_get_string(ipport);
		const char* mask_ = json_object_get_string(mask);
		d = data_new(ipport_, mask_);
		node = node_create(d);
		list_push_back(proc->connection_list, node);
	}

	munmap(json, fs);
	return true;
}

Fd *fd_create(int fd, const char *path){
	Fd *_fd = malloc(sizeof(Fd));
	if(!_fd)
		return NULL;

	_fd->nr = fd;
	memset(_fd->path, 0, PATH_MAX);
	strcpy(_fd->path, path);

	return _fd;
}

WriteSample *write_sample_create(unsigned long fd, unsigned long buf, unsigned long len){
	WriteSample *ws = malloc(sizeof(WriteSample));
	if(!ws)
		return NULL;

	ws->fd = fd;
	ws->buf = buf;
	ws->len = len;

	return ws;
}

int wsl_init(List **write_sample_list){
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	// create 8 dummy node
	Node *dummy_node;
	WriteSample *dummy_sample;
	for(int i = 0; i < 8; i++){
		dummy_sample = write_sample_create(0, 0, 0);
		dummy_node = node_create(dummy_sample);
		list_push_back(tmp, dummy_node);
	}
	tmp->size = 0;

	*write_sample_list = tmp;
	return 0;
}

int swsl_init(List **socket_write_sample_list){
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	// create 8 dummy node
	Node *dummy_node;
	WriteSample *dummy_sample;
	for(int i = 0; i < 8; i++){
		dummy_sample = write_sample_create(0, 0, 0);
		dummy_node = node_create(dummy_sample);
		list_push_back(tmp, dummy_node);
	}
	tmp->size = 0;

	*socket_write_sample_list = tmp;
	return 0;
}

void fdlist_destroy(List *fdlist){
	if(!fdlist)
		return;

	Node *iter, *prev;
	Fd *fd;

	iter = fdlist->head;
	while(iter){
		prev = iter;
		iter = iter->next;
		fd = (Fd *) prev->data;
		free(fd);
		free(prev);
	}

	free(fdlist);
}

void devbuflist_destroy(List *devbuflist){
	if(!devbuflist)
		return;

	Node *iter, *prev;
	Devbuf *devbuf;

	iter = devbuflist->head;
	while(iter){
		prev = iter;
		iter = iter->next;
		devbuf = (Devbuf *) prev->data;
		free(devbuf);
		free(prev);
	}

	free(devbuflist);
}

void devlist_destroy(List *device_list){
	if(!device_list)
		return;

	Node *iter, *prev;
	struct data *d;

	iter = device_list->head;
	while(iter){
		prev = iter;
		iter = iter->next;
		d = (struct data *) prev->data;
		free(d->val1);
		free(d->val2);
		free(d);
		free(prev);
	}

	free(device_list);
}

void accessfilelist_destroy(List *access_file_list){
	if(!access_file_list)
		return;

	Node *iter, *prev;
	struct data *d;

	iter = access_file_list->head;
	while(iter){
		prev = iter;
		iter = iter->next;
		d = (struct data *) prev->data;
		free(d->val1);
		free(d->val2);
		free(d);
		free(prev);
	}

	free(access_file_list);
}

void connectionlist_destroy(List *connection_list){
	if(!connection_list)
		return;

	Node *iter, *prev;
	struct data *d;

	iter = connection_list->head;
	while(iter){
		prev = iter;
		iter = iter->next;
		d = (struct data *) prev->data;
		free(d->val1);
		free(d->val2);
		free(d);
		free(prev);
	}

	free(connection_list);
}

void perffdlist_destroy(List *perf_fdlist){
	if(!perf_fdlist)
		return;

	Node *iter, *prev;
	Perf_fd *perf_fd;

	iter = perf_fdlist->head;
	while(iter){
		prev = iter;
		iter = iter->next;
		perf_fd = (Perf_fd *) prev->data;
		free(perf_fd);
		free(prev);
	}

	free(perf_fdlist);
}

void wsl_destroy(List *write_sample_list){
	if(!write_sample_list)
		return;

	Node *iter = write_sample_list->head, *prev;
	WriteSample *write_sample;
	for(int i = 0; i < 8; i++){
		write_sample = (WriteSample *) iter->data;
		free(write_sample);
		prev = iter;
		iter = iter->next;
		free(prev);
	}

	free(write_sample_list);
}

void swsl_destroy(List *socket_write_sample_list){
	if(!socket_write_sample_list)
		return;

	Node *iter = socket_write_sample_list->head, *prev;
	WriteSample *write_sample;
	for(int i = 0; i < 8; i++){
		write_sample = (WriteSample *) iter->data;
		free(write_sample);
		prev = iter;
		iter = iter->next;
		free(prev);
	}

	free(socket_write_sample_list);
}

int cache_init(cacheline ***cache){
	if(0 == assoc && 0 == block_bit && 0 == set_bit && 0 == set_size){
		Node *iter;
		Conf *c;
		LIST_FOR_EACH(cf->list, iter){
			c = LIST_ENTRY(iter, Conf);
			if(0 == strcmp(c->key, "assoc")){
				sscanf(c->val, "%d", &assoc);
			} else if(0 == strcmp(c->key, "block_bit")){
				sscanf(c->val, "%d", &block_bit);
			} else if(0 == strcmp(c->key, "set_bit")){
				sscanf(c->val, "%d", &set_bit);
			}
		}
		set_size = 1 << set_bit;
	}

	//printf("%d %d %d %d\n", assoc, block_bit, set_bit, set_size);

	void *tmp = cache_create(set_size, assoc);
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

Node *list_get_freenode(List *list, bool *free_node_found){
	Node *node = NULL;
	Process *proc = NULL;

	LIST_FOR_EACH(list, node){
		proc = LIST_ENTRY(node, Process);
		if('X' == proc->state){
			*free_node_found = true;
			return node;
		}
	}

	*free_node_found = false;
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

uint64_t str2uint64(const char *str){
	return strtoull(str, NULL, 16);
}

Devbuf *devbuf_create(const char *buf_start, size_t buf_len){
	Devbuf *devbuf = malloc(sizeof(Devbuf));
	if(!devbuf)
		return NULL;

	strcpy(devbuf->start, buf_start);
	devbuf->len = buf_len;
	return devbuf;
}

int devbuflist_init(List **devbuflist){
	List *tmp = malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*devbuflist = tmp;
	return 0;
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

bool process_is_trusted(Process *proc){
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

	memset(proc->tty_path, 0, 32);
	memset(proc->exe, 0, PATH_MAX);
	proc->pid = pid;
	proc->state = 0;
	proc->flags = 0;
	proc->tracer = 0;
	proc->last_run_cpu = -1;
	proc->tty_nr = -1;
	proc->hit_cnt = 0;
	proc->miss_cnt = 0;
	proc->eviction_cnt = 0;

	proc->perf_fdlist = NULL;
	proc->devbuflist = NULL;
	proc->device_list = NULL;
	proc->access_file_list = NULL;
	proc->connection_list = NULL;
	proc->perf_fdlist = NULL;
	proc->write_sample_list = NULL;
	proc->socket_write_sample_list = NULL;
	proc->cache = NULL;

	pthread_spin_init(&proc->wsl_lock, PTHREAD_PROCESS_SHARED);
	pthread_spin_init(&proc->swsl_lock, PTHREAD_PROCESS_SHARED);

	return proc;
}

void process_destroy(Process *proc){
	pthread_spin_destroy(&proc->wsl_lock);
	pthread_spin_destroy(&proc->swsl_lock);
	munmap(proc, PROC_SIZE);
	return;
}

void process_clean(Process *proc){
	fdlist_destroy(proc->fdlist);
	devbuflist_destroy(proc->devbuflist);
	devlist_destroy(proc->device_list);
	accessfilelist_destroy(proc->access_file_list);
	connectionlist_destroy(proc->connection_list);
	perffdlist_destroy(proc->perf_fdlist);
	wsl_destroy(proc->write_sample_list);
	swsl_destroy(proc->socket_write_sample_list);
	cache_destroy(proc->cache, set_size);

	proc->fdlist = NULL;
	proc->devbuflist = NULL;
	proc->device_list = NULL;
	proc->access_file_list = NULL;
	proc->connection_list = NULL;
	proc->perf_fdlist = NULL;
	proc->write_sample_list = NULL;
	proc->socket_write_sample_list = NULL;
	proc->cache = NULL;

	memset(proc->exe, 0, PATH_MAX);
	memset(proc->tty_path, 0, 32);
	proc->tty_nr = 0;
	proc->last_run_cpu = 0;
	proc->pid = -1;
	proc->state = 'X';
	proc->flags = 0;
	proc->tracer = 0;
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
		start_num = strtoull(start, NULL, 16);
		end_num = strtoull(end, NULL, 16);

		strcpy(devbuf_start, "0x");
		strncat(devbuf_start, start, minus - maps_line);
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
	    int fd = (int) strtol(name, NULL, 10);

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
		
		// fetch tty_nr
		ptr = ptr + 1;
		sscanf(ptr, "%d", &proc->tty_nr);
		ptr = strchr(ptr + 1, ' ');
		
		// skip tpgid
		ptr = strchr(ptr + 1, ' ');
		
		// fetch flags
		ptr = ptr + 1;
		sscanf(ptr, "%u", &proc->flags);
		ptr = strchr(ptr + 1, ' ');

		// skip minflt
		ptr = strchr(ptr + 1, ' ');

		// skip cminflt
		ptr = strchr(ptr + 1, ' ');

		// skip majflt
		ptr = strchr(ptr + 1, ' ');

		// skip cmajflt
		ptr = strchr(ptr + 1, ' ');

		// skip utime
		ptr = strchr(ptr + 1, ' ');

		// skip stime
		ptr = strchr(ptr + 1, ' ');

		// skip cutime
		ptr = strchr(ptr + 1, ' ');

		// skip cstime
		ptr = strchr(ptr + 1, ' ');

		// skip priority
		ptr = strchr(ptr + 1, ' ');

		// skip nice
		ptr = strchr(ptr + 1, ' ');

		// skip num_threads
		ptr = strchr(ptr + 1, ' ');

		// skip itrealvalue
		ptr = strchr(ptr + 1, ' ');

		// skip starttime
		ptr = strchr(ptr + 1, ' ');

		// skip vsize
		ptr = strchr(ptr + 1, ' ');

		// skip rss
		ptr = strchr(ptr + 1, ' ');

		// skip rsslim
		ptr = strchr(ptr + 1, ' ');

		// skip startcode
		ptr = strchr(ptr + 1, ' ');

		// skip endcode
		ptr = strchr(ptr + 1, ' ');

		// skip startstack
		ptr = strchr(ptr + 1, ' ');

		// skip kstkesp
		ptr = strchr(ptr + 1, ' ');

		// skip kstkeip
		ptr = strchr(ptr + 1, ' ');

		// skip signal
		ptr = strchr(ptr + 1, ' ');

		// skip blocked
		ptr = strchr(ptr + 1, ' ');

		// skip sigignore
		ptr = strchr(ptr + 1, ' ');

		// skip sigcatch
		ptr = strchr(ptr + 1, ' ');

		// skip wchan
		ptr = strchr(ptr + 1, ' ');

		// skip nswap
		ptr = strchr(ptr + 1, ' ');

		// skip cnswap
		ptr = strchr(ptr + 1, ' ');

		// skip exit_signal
		ptr = strchr(ptr + 1, ' ');

		// fetch processor
		ptr = ptr + 1;
		sscanf(ptr, "%d", &proc->last_run_cpu);
		ptr = strchr(ptr + 1, ' ');

		fclose(stat_file_ptr);
	}

	// readlink executable
	process_updateExe(proc);

	return 0;
}

static void get_va_sample_from_sample(va_sample_t *va_sample, sample_raw_t *sample){
	va_sample->pid = sample->pid;
	va_sample->tid = sample->tid;
	va_sample->buf_addr = sample->addr;
	return;
}

static void get_trp_sample_from_sample(trp_sample_t *trp_sample, sample_trp_t *sample){
	trp_sample->ip = sample->ip;
	trp_sample->pid = sample->pid;
	trp_sample->tid = sample->tid;
	trp_sample->time = sample->time;
	trp_sample->cpu = sample->res;
	trp_sample->period = sample->period;
	trp_sample->size = sample->size;
	memcpy(trp_sample->data, sample->data, sample->size);
	return;
}

/*
 * the sleep time in microsecond is based on the clock speed of CPU which last ran by the process
 */
static unsigned long get_usleep_time(Process *proc){
	int last_run_cpu = proc->last_run_cpu;
	unsigned long clock_speed_MHz = cpu[last_run_cpu].clock_speed;
	unsigned long long clock_speed = clock_speed_MHz * 1024 * 1024;
	unsigned long msec_per_sec = 1000000;
	double ratio = ((double) clock_speed / 10) / clock_speed;

	/*
	for(int i = 0; i < 8; i++){
		printf("%d %lu\n", i+1, cpu[i].clock_speed);
	}
	exit(1);
	*/

	//printf("%llu %lf %llu\n", clock_speed, ratio, (unsigned long)(ratio * msec_per_sec));
	return (unsigned long) (ratio * msec_per_sec);
}

void *load_evt_monitoring(void *arg){
	pthread_data_t *thread_data = (pthread_data_t *) arg;
	Process *proc = (Process *) thread_data->proc;
	Perf_fd *perf_fd = (Perf_fd *) thread_data->perf_fd;

	int ret;
	sample_raw_t sample;
	va_sample_t va_sample;
	char expr[32];
	uint64_t addr_start, addr_end;

	while(true){
		//printf("usleep %lu\n", get_usleep_time(proc));
		usleep(get_usleep_time(proc));
		/*
		proc->hit_cnt = 0;
		proc->miss_cnt = 0;
		proc->eviction_cnt = 0;
		*/

		ret = perf_event_raw_read(proc, perf_fd, &sample);
		if(-EAGAIN == ret){
		    continue;
		} else if(ret < 0){
			pthread_exit(NULL);
		}

		get_va_sample_from_sample(&va_sample, &sample);

		Node *iter;
		Devbuf *devbuf;
		List *devbuf_list = proc->devbuflist;

		LIST_FOR_EACH(devbuf_list, iter){
			devbuf = LIST_ENTRY(iter, Devbuf);
			addr_start = str2uint64(devbuf->start);
			addr_end = addr_start + devbuf->len;

			if(va_sample.buf_addr >= addr_start && va_sample.buf_addr <= addr_end) {
				 memset(expr, 0, 32);
				 sprintf(expr, "L %lx", va_sample.buf_addr);
				 cache_virtaddr(proc, set_bit, assoc, block_bit, expr);
				 //printf("addr: 0x%lx\n", va_sample.buf_addr);
			}
		}
	}
}

static bool is_tty_write_sample(Process *proc, unsigned long fd){
	char buf[BUF_SIZE] = {0};
	char path[BUF_SIZE] = {0};
	char pidstr[32] = {0};
	char fdstr[32] = {0};
	int ret;

	sprintf(pidstr, "%d", proc->pid);
	sprintf(fdstr, "%lu", fd);

	strcpy(path, PROC_DIR);
	strcat(path, "/");
	strcat(path, pidstr);
	strcat(path, "/");
	strcat(path, "fd");
	strcat(path, "/");
	strcat(path, fdstr);

	ret = readlink(path, buf, BUF_SIZE);
	if(-1 == ret)
		return false;
	buf[ret] = 0;

	return (0 == strncmp(buf, "/dev/pts/", 9));
}

static bool is_socket_write_sample(Process *proc, unsigned long fd){
	char buf[BUF_SIZE] = {0};
	char path[BUF_SIZE] = {0};
	char pidstr[32] = {0};
	char fdstr[32] = {0};
	int ret;

	sprintf(pidstr, "%d", proc->pid);
	sprintf(fdstr, "%lu", fd);

	strcpy(path, PROC_DIR);
	strcat(path, "/");
	strcat(path, pidstr);
	strcat(path, "/");
	strcat(path, "fd");
	strcat(path, "/");
	strcat(path, fdstr);

	ret = readlink(path, buf, BUF_SIZE);
	if(-1 == ret)
		return false;
	buf[ret] = 0;

	return (0 == strncmp(buf, "socket:[", 8));
}

void *trp_monitoring(void *arg){
	pthread_data_t *thread_data = (pthread_data_t *) arg;
	Process *proc = (Process *) thread_data->proc;
	Perf_fd *perf_fd = (Perf_fd *) thread_data->perf_fd;

	Node *iter;
	size_t i;
	WriteSample *ws;
	unsigned long fd;
	unsigned long buf;
	unsigned long len;
	sample_trp_t sample;
	trp_sample_t trp_sample;
	char *ptr;
	int ret;
	struct pollfd pfd;
	pfd.fd = perf_fd->fd;
	pfd.events = POLLIN|POLLERR|POLLHUP;

	while(true){
		ret = poll(&pfd, 1, -1);
		if(ret < 0){
			printf("poll failed\n");
			break;
		}

		if(pfd.revents & POLLIN){
			ret = perf_event_trp_read(proc, perf_fd, &sample);

			if(ret == -EAGAIN){
				continue;
			} else if(ret < 0){
				pthread_exit(NULL);
			}

			get_trp_sample_from_sample(&trp_sample, &sample);
			i = 0;
			ptr = ((char *) trp_sample.data) + 16;
			fd = *((unsigned long *) ptr);
			ptr = ((char *) ptr) + sizeof(unsigned long);
			buf = *((unsigned long *) ptr);
			ptr = ((char *) ptr) + sizeof(unsigned long);
			len = *((unsigned long *) ptr);

			if(is_tty_write_sample(proc, fd))
				continue;

			if(is_socket_write_sample(proc, fd)){
				pthread_spin_lock(&proc->swsl_lock);
				// records only latest 8 samples
				if(8 == list_size(proc->socket_write_sample_list))
					proc->socket_write_sample_list->size = 0;

				iter = proc->socket_write_sample_list->head;
				while(i < list_size(proc->socket_write_sample_list)){
					iter = iter->next;
					i++;
				}
				ws = iter->data;
				ws->fd = fd;
				ws->buf = buf;
				ws->len = len;
				proc->socket_write_sample_list->size++;
				pthread_spin_unlock(&proc->swsl_lock);
			} else {
				pthread_spin_lock(&proc->wsl_lock);
				// records only latest 8 samples
				if(8 == list_size(proc->write_sample_list))
					proc->write_sample_list->size = 0;

				iter = proc->write_sample_list->head;
				while(i < list_size(proc->write_sample_list)){
					iter = iter->next;
					i++;
				}
				ws = iter->data;
				ws->fd = fd;
				ws->buf = buf;
				ws->len = len;
				proc->write_sample_list->size++;
				pthread_spin_unlock(&proc->wsl_lock);
			}


			/*
			ptr = ((char *) trp_sample.data) + 16;
			printf("timestamp: %lx, pid: %d, size: %u, (fd: %zu", trp_sample.time, trp_sample.pid, trp_sample.size, *((unsigned long *) ptr));
			ptr = ((char *) ptr) + sizeof(unsigned long);
			printf(", buf: %p", *((unsigned long *) ptr));
			ptr = ((char *) ptr) + sizeof(unsigned long);
			printf(", byte: %ld)\n", *((unsigned long *) ptr));
			*/
		}

		if(pfd.revents & POLLHUP){                  // perf fd is not invalid or disconnected
			//printf("%d poll hup\n", pfd.fd);
			pthread_exit(NULL);
		}

		if(pfd.revents & POLLERR){                    
			//printf("%d poll err\n", pfd.fd);
			pthread_exit(NULL);
		}
	}

	return NULL;
}

// skip pid of repeat if 'repeat' in /proc/[pid]/task directory since it is same as [pid]
void scan_proc_dir(List *process_list, const char *dir, Process *repeat){ 
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
	bool free_node_found;

	Node *proc_node = list_get_node_by_pid(process_list, pid, &pre_exist);
	Process *proc = NULL;
	if(!proc_node){
		proc_node = list_get_freenode(process_list, &free_node_found);    // previous dead process is considered as free node
		if(!proc_node){
			proc = process_create(pid);
			proc_node = node_create((void *) proc);
		} else {
			proc = proc_node->data;
			proc->pid = pid;
		}
	} else {
		proc = proc_node->data;
		free_node_found = false;
	}

	process_stat(proc);

	if(process_is_kernel_thread(proc)){
		if(free_node_found){
			process_clean(proc);
		} else {
			process_destroy(proc);
			node_destroy(proc_node);
		}
		continue;
	}

	if(process_is_trusted(proc)){
		if(free_node_found){
			process_clean(proc);
		} else {
			process_destroy(proc);
			node_destroy(proc_node);
		}
		continue;
	}

	if(process_is_stop(proc)){
		process_clean(proc);
		continue;
	}

	//scan_proc_dir(process_list, pid_path, proc);
	
	if(!pre_exist){
#ifdef DAEMON
		log_open();
		syslog(LOG_NOTICE, LOG_PREFIX"new process, pid: %s, exe: %s, state: %c\n", name, proc->exe, proc->state);
		log_close();
#endif

		printf("new process, pid: %s, exe: %s, state: %c\n", name, proc->exe, proc->state);

		pid_t child = fork();
		if(child == 0){ 
			int ret;

			proc->tracer = child;
			ret = get_ttypath(proc);
			if(-1 == ret){
				printf("tty not found\n");
			}

			if(!process_promise_pass(proc)){
				process_clean(proc);
				exit(EXIT_FAILURE);
			}

			fdlist_init(&proc->fdlist);
			devbuflist_init(&proc->devbuflist);
			perffdlist_init(&proc->perf_fdlist);
			wsl_init(&proc->write_sample_list);
			swsl_init(&proc->socket_write_sample_list);
			cache_init(&proc->cache);

			Perf_fd *perf_fd1, *perf_fd2;

			// read process open fd list(read here because malloc memory cannot be shared with child)
			process_updateFdList(proc);

			// get device mmap buffer list
			process_updateDevBufList(proc);

			perf_fd1 = perf_event_register(proc, PERF_TYPE_RAW, ALL_LOADS, PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR);
			assert(perf_fd1 != NULL);
			perf_fd2 = perf_event_register(proc, PERF_TYPE_TRACEPOINT, SYSCALL_WRITE, PERF_SAMPLE_IDENTIFIER|PERF_SAMPLE_IP| PERF_SAMPLE_ADDR |
												PERF_SAMPLE_TID|PERF_SAMPLE_TIME|PERF_SAMPLE_CPU|PERF_SAMPLE_PERIOD|PERF_SAMPLE_RAW);
			assert(perf_fd2 != NULL);
			
			// perf sampling load address thread, here is all load event
			pthread_t thr1;
			pthread_data_t thr_data1;
			thr_data1.proc = proc;
			thr_data1.perf_fd = perf_fd1;
			ret = pthread_create(&thr1, NULL, load_evt_monitoring, (void *) &thr_data1);
			if(ret != 0)
				handle_error("load event monitor created failed\n");
			ret = pthread_detach(thr1);
			if(ret != 0)
				handle_error("detach load event monitor failed\n");

			// perf sampling tracepoints thread, here is sys_enter_write
			pthread_t thr2;
			pthread_data_t thr_data2;
			thr_data2.proc = proc;
			thr_data2.perf_fd = perf_fd2;
			ret = pthread_create(&thr2, NULL, trp_monitoring, (void *) &thr_data2);
			if(ret != 0)
				handle_error("tracepoint monitor created failed\n");
			ret = pthread_detach(thr2);
			if(ret != 0)
				handle_error("detach tracepoint monitor failed\n");

			perf_event_start(proc);

			// check all load event and sys_enter_write periodically to detect data leakage and update some process state
			List *device_list = proc->device_list;
			Node *iter;
			struct data *d;
			const char *action_mask;
			bool save;
			bool stream;
			bool ret1;
			bool ret2;
			while(true){
				//printf("usleep %lu\n", get_usleep_time(proc));
				usleep(get_usleep_time(proc));
				printf("hit: %d\n", proc->hit_cnt);

				process_stat(proc);
				if(process_is_stop(proc) || process_is_dead(proc))
					goto clean;

				process_updateFdList(proc);
				process_updateDevBufList(proc);

				if(using_camera(proc)){
					LIST_FOR_EACH(device_list, iter){
						d = LIST_ENTRY(iter, struct data);
						if(0 == strcmp(d->val1, "camera"))
							break;
					}

					action_mask = d->val2;
					save = get_action_bit(action_mask, 1);
					stream = get_action_bit(action_mask, 2);

					if(load_evt_high(proc)){
						ret1 = invalid_write(proc, save);
						ret2 = invalid_streaming(proc, stream);

						if(ret1 && ret2){
							callstack_unwind_log(proc);
							send_signal(proc, SIGSTOP, 
									"The process was writing to non-promise file " 
									"and streaming via invalid connection\n");
							goto clean;
						} else if(ret1){
							callstack_unwind_log(proc);
							send_signal(proc, SIGSTOP, 
								   "The process was writing to non-promise file\n");
							goto clean;
						} else if(ret2){
							callstack_unwind_log(proc);
							send_signal(proc, SIGSTOP, 
								   "The process was streaming via invalid connection\n");
							goto clean;
						}
					}

				}
			}

			clean:
				perf_event_stop(proc);
				perf_event_unregister(proc);
				process_clean(proc);
				exit(EXIT_SUCCESS);
		} else {
			if(!free_node_found){
				//printf("not found free node\n");
				list_push_back(process_list, proc_node);
			}
		}
	} else { // exist before
		if(!process_is_zombie(proc)){
			process_updateExe(proc); // pid might be reused, then the exe could change, such as calling execve series function
			//printf("pid: %d, state: %c, new_exe: %s\n", proc->pid, proc->state, proc->exe);
		}
	}
    }

    closedir(scan_dir);
    return;
}

