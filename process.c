#include "basis.h"
#include <pthread.h>
#include "list.h"
#include "process.h"
#include <poll.h>
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
int set_size = 1 << 6; // 6 is set_bit

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

static bool get_action_bit(const char *action, int index){
	size_t len = strlen(action);

	if(index < 0 || index > len)
		return false;

	for(size_t i = len; i > 0; i--){
		if((len - index - 1) == i)
			return (action[i] == '1');
	}
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

static int invalid_write(Process *proc, bool save){
	List *access_file_list = proc->access_file_list;
	List *wsl = proc->write_sample_list;
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

	if(save && 0 == list_size(access_file_list)) // no description of access file => break the promise
		return -ENOENT;

	pthread_spin_lock(&proc->wsl_lock);
	for(i = 0, iter = wsl->head; i < list_size(wsl); i++, iter = iter->next){
		ws = iter->data;

		sprintf(fdstr, "%d", ws->fd);
		strcpy(path, basepath);
		strcat(path, fdstr);
		ret = readlink(path, buf, BUF_SIZE);
		if(-1 == ret)
			continue;
		buf[ret] = 0;

		LIST_FOR_EACH(access_file_list, fileiter){
			filedata = LIST_ENTRY(fileiter, struct data);
			if(0 == strcmp(filedata->val1, buf)){
				if(false == get_action_bit(filedata->val2, 1)){ // bit1 is write bit
					pthread_spin_unlock(&proc->wsl_lock);
					return -EINVAL;
				} else {
					pthread_spin_unlock(&proc->wsl_lock);
					return 0;
				}
			}
		}

		//printf("fd: %lu, buf: %lu, len: %lu\n", ws->fd, ws->buf, ws->len);
	}
	pthread_spin_unlock(&proc->wsl_lock);

	return -EINVAL;
}

static bool invalid_streaming(Process *proc, bool stream){
	List *wsl = proc->write_sample_list;
	Node *iter;
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

	/*
	if(0 == list_size(connections_list)) // no description of access file => break the promise
		return -ENOENT;
		*/

	pthread_spin_lock(&proc->wsl_lock);
	for(i = 0, iter = wsl->head; i < list_size(wsl); i++, iter = iter->next){
		ws = iter->data;

		sprintf(sockfdstr, "%d", ws->fd);
		strcpy(path, basepath);
		strcat(path, sockfdstr);
		ret = readlink(path, buf, BUF_SIZE);
		if(-1 == ret)
			continue;
		buf[ret] = 0;

		if(strstr(buf, "socket"))
			return true;

		//printf("fd: %lu, buf: %lu, len: %lu\n", ws->fd, ws->buf, ws->len);
	}
	pthread_spin_unlock(&proc->wsl_lock);

	return false;
}

static int parse_net_lines(FILE *netfile, const char *sock_inode, char *rem_addr){
	char buf[BUF_SIZE];
	char *inode_ptr;
	char *rem_addr_ptr;
	char *rem_addr_qtr;
	size_t len;
	
	while(fgets(buf, BUF_SIZE, netfile)){
		inode_ptr = buf;
		rem_addr_ptr = buf;

		if(strstr(buf, sock_inode)){
			rem_addr_ptr = strchr(rem_addr_ptr + 1, ':');
			for(int i = 0; i < 2; i++)
				rem_addr_ptr = strchr(rem_addr_ptr + 1, ' ');
			rem_addr_qtr = strchr(rem_addr_ptr + 1, ' ');
			len = rem_addr_qtr - rem_addr_ptr;
			strncpy(rem_addr, rem_addr_ptr + 1, len);
			rem_addr[len] = 0;
			return 0;
		}
	}

	return 1;
} 
static int get_sock_inode_by_sockfd(Process *proc, int sockfd, char *sock_inode){
	char buf[BUF_SIZE] = {0};
	char path[BUF_SIZE] = {0};
	char pidstr[32] = {0};
	char sockfdstr[32] = {0};
	int ret;
	char *ptr, *qtr;

	sprintf(pidstr, "%d", proc->pid);
	sprintf(sockfdstr, "%d", sockfd);

	strcpy(path, PROC_DIR);
	strcat(path, "/");
	strcat(path, pidstr);
	strcat(path, "/");
	strcat(path, "fd");
	strcat(path, "/");
	strcat(path, sockfdstr);

	ret = readlink(path, buf, BUF_SIZE);
	if(-1 == ret)
		return 1;
	buf[ret] = 0;

	ptr = buf;
	ptr = strchr(buf, '[') + 1;
	qtr = strchr(ptr, ']');
	strncpy(sock_inode, ptr, qtr - ptr);
	sock_inode[qtr - ptr] = 0;
	//printf("sock_inode: %s, %d, %c, %c\n", sock_inode, qtr - ptr, *ptr, *qtr);
	return 0;
}

static void get_ip_port_from_rem_addr(const char *rem_addr, int ipv4, char *ip, char *port){
	char tmp[64] = {0};
	uint16_t port_val;
	char *ptr, *qtr;

	ptr = rem_addr;
	if(ipv4){
		uint8_t *rtr;
		uint32_t ip_val;

		qtr = strchr(ptr, ':');
		strcpy(tmp, "0x");
		strncat(tmp, ptr, qtr - ptr);
		tmp[qtr - ptr + 2] = 0;
		ip_val = (uint32_t) strtoul(tmp, NULL, 16);
		ip_val = ntohl(ip_val);

		rtr = ((uint8_t *) &ip_val) + 3;
                for(int i = 4; i > 0; i--){
                        memset(tmp, 0, 64);
                        sprintf(tmp, "%u", *rtr);
			printf("tmp: %s\n", tmp);

                        if(i == 1){
                                strcat(ip, tmp);
                                break;
                        }

                        strcat(ip, tmp);
                        strcat(ip, ".");
                        rtr--;
                }
	} else { // ipv6
		qtr = strchr(ptr, ':');
                strncat(tmp, ptr, qtr - ptr);
                tmp[qtr - ptr] = 0;

                ptr = ptr + 31;
                for(int i = 0; i < 8; i++){
                        for(int j = 0; j < 4; j++){
                                sprintf(tmp, "%c", *ptr);
                                strcat(ip, tmp);
                                ptr--;
                        }

                        if(i == 7)
                                break;

                        strcat(ip, ":");
                }
	}

	ptr = strchr(rem_addr, ':') + 1;
	memset(tmp, 0, 64);
	strcpy(tmp, "0x");
	strcat(tmp, ptr);
	port_val = (uint16_t) strtoul(tmp, NULL, 16);
	sprintf(port, "%u", port_val);
}

static int get_rem_addr_by_sockfd(Process *proc, int sockfd, char *rem_addr, int *tcp, int *ipv4){
	int ret;
	char sock_inode[16];
	ret = get_sock_inode_by_sockfd(proc, sockfd, sock_inode);
	if(ret)
		return 1;

	// try tcp first
	char tcp_file[32] = {0};
	strcpy(tcp_file, PROC_DIR);
	strcat(tcp_file, "/net/tcp");
	FILE *net_file_ptr = fopen(tcp_file, "r");
	if(!net_file_ptr)
		return 1;

	ret = parse_net_lines(net_file_ptr, sock_inode, rem_addr);
	fclose(net_file_ptr);
	if(!ret) {
		*tcp = 1;
		*ipv4 = 1;
		return 0;
	}
	
	// try tcp6 first
	memset(tcp_file, 0, 32);
	strcpy(tcp_file, PROC_DIR);
	strcat(tcp_file, "/net/tcp6");
	net_file_ptr = fopen(tcp_file, "r");
	if(!net_file_ptr)
		return 1;

	ret = parse_net_lines(net_file_ptr, sock_inode, rem_addr);
	fclose(net_file_ptr);
	if(!ret){
		*tcp = 1;
		*ipv4 = 0;
		return 0;
	}

	// try udp
	char udp_file[32] = {0};
	strcpy(udp_file, PROC_DIR);
	strcat(udp_file, "/net/udp");
	net_file_ptr = fopen(udp_file, "r");
	if(!net_file_ptr)
		return 1;

	ret = parse_net_lines(net_file_ptr, sock_inode, rem_addr);
	fclose(net_file_ptr);
	if(!ret){
		*tcp = 0;
		*ipv4 = 1;
		return 0;
	}
	
	// try udp6
	memset(udp_file, 0, 32);
	strcpy(udp_file, PROC_DIR);
	strcat(udp_file, "/net/udp6");
	net_file_ptr = fopen(udp_file, "r");
	if(!net_file_ptr)
		return 1;

	ret = parse_net_lines(net_file_ptr, sock_inode, rem_addr);
	fclose(net_file_ptr);
	if(!ret){
		*tcp = 0;
		*ipv4 = 0;
		return 0;
	}
	
	return 1;
}

bool if_parse_error(struct json_object* obj, Process *proc)
{
    if(obj == NULL)
    {
        send_signal(proc, SIGSTOP, "JSON file error\n");
		return false;
    }
	return true;
}

struct data *data_new(char* val1, char* val2){
	struct data *d = malloc(sizeof(struct data));
	if(!d)
		return NULL;

	d->val1 = val1;
	d->val2 = val2;
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
			send_signal(proc, SIGKILL, "config file is empty\n");
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
		send_signal(proc, SIGKILL, "No config file exist\n");
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
		char* ipport_ = json_object_get_string(ipport);
		char* mask_ = json_object_get_string(mask);
		d = data_new(ipport_, mask_);
		node = node_create(d);
		list_push_back(proc->connection_list, node);
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

int connection_list_init(List** connection_list)
{
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*connection_list = tmp;
	return 0;
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

int perffdlist_init(List **perffdlist){
	List *tmp= malloc(sizeof(List));
	if(!tmp)
		return 1;

	LIST_INIT(tmp);

	*perffdlist = tmp;
	return 0;
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

	*write_sample_list = tmp;
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

	proc->pid = pid;
	proc->state = 0;
	proc->flags = 0;
	memset(proc->exe, 0, sizeof(PATH_MAX));
	proc->tracer = 0;
	proc->last_run_cpu = -1;

	// perf related
	proc->perf_fdlist = NULL;
	pthread_spin_init(&proc->wsl_lock, PTHREAD_PROCESS_SHARED);

	return proc;
}

void process_destroy(Process *proc){
	pthread_spin_destroy(&proc->wsl_lock);
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
	proc->perf_fdlist = NULL;
	proc->devbuflist = NULL;
	proc->device_list = NULL;
	proc->access_file_list = NULL;
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
	    /*
	    if(strstr(fd_path, "socket")){
	    	char rem_addr[32] = {0};
	    	char ip[32] = {0};
	    	char port[32] = {0};
		int tcp;
		int ipv4;
		get_rem_addr_by_sockfd(proc, fd, rem_addr, &tcp, &ipv4);
		printf("rem_addr: %s, tcp: %d, ipv4: %d\n", rem_addr, tcp, ipv4);
		get_ip_port_from_rem_addr(rem_addr, ipv4, ip, port);
		printf("ip: %s, port: %s\n", ip, port);
	    }
	    */

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
	double ratio = ((double) clock_speed / 2) / clock_speed;

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
}

// skip pid of repeat if 'repeat' in /proc/[pid]/task directory since it is same as [pid]
void scan_proc_dir(List *list, const char *dir, Process *repeat, double period){ 
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

	scan_proc_dir(list, pid_path, proc, period);

	if(process_is_stop(proc))
		continue;

	if(process_is_kernel_thread(proc)){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}

	if(process_is_trusted(proc)){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}

	if(!pre_exist){
#ifdef DAEMON
		log_open();
		syslog(LOG_NOTICE, LOG_PREFIX"new process, pid: %s, exe: %s, state: %c\n", name, proc->exe, proc->state);
		log_close();
#endif

		printf("new process, pid: %s, exe: %s, state: %c\n", name, proc->exe, proc->state);

		pid_t child = fork();
		if(child == 0){ 
			proc->tracer = child;

			if(!process_promise_pass(proc)){
				process_destroy(proc);
				node_destroy(proc_node);
				exit(EXIT_FAILURE);
			}

			fdlist_init(&proc->fdlist);
			devbuflist_init(&proc->devbuflist);
			perffdlist_init(&proc->perf_fdlist);
			wsl_init(&proc->write_sample_list);
			cache_init(&proc->cache, set_size, assoc);

			int ret;
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
			bool video;
			bool save;
			bool stream;
			while(true){
				//printf("usleep %lu\n", get_usleep_time(proc));
				usleep(get_usleep_time(proc));
				printf("hit: %d\n", proc->hit_cnt);

				process_stat(proc);
				process_updateFdList(proc);
				process_updateDevBufList(proc);

				if(using_camera(proc)){
					LIST_FOR_EACH(device_list, iter){
						d = LIST_ENTRY(iter, struct data);
						if(0 == strcmp(d->val1, "camera"))
							break;
					}

					action_mask = d->val2;
					video = get_action_bit(action_mask, 0);
					save = get_action_bit(action_mask, 1);
					stream = get_action_bit(action_mask, 2);

					if(load_evt_high(proc)){
						printf("high load event\n");
						if(invalid_write(proc, save)){
							send_signal(proc, SIGSTOP, 
								   "The process claimed that it will not save video, but it did!\n");
						} 
						
						if(invalid_streaming(proc, stream)){
							send_signal(proc, SIGSTOP, 
								   "The process claimed that it will not video invalid_streaming, but it did!\n");
						}
					}

				}
			
				if(process_is_dead(proc)){
					perf_event_stop(proc);
					perf_event_unregister(proc);
					printSummary(proc->hit_cnt, proc->miss_cnt, proc->eviction_cnt);
					process_clean(proc);
					printf("tracee exit\n");
					_exit(EXIT_SUCCESS);
				}
			}
		} else {
			list_push_back(list, proc_node);
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

