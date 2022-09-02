#include "basis.h"
#include "list.h"
#include "process.h"
#include <libelf.h>
#include <sys/mman.h>
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
        if(strcmp(&strtab[shdr[i].sh_name], ".test") != 0)
            continue;
        size_t k;
        FILE* fp;
        fp = fopen ("file.js", "w+");
        for (k = shdr[i].sh_offset; k < shdr[i].sh_offset + shdr[i].sh_size; k++) 
        {
            fprintf(fp,"%c", data[k]);
        }   
        fclose(fp);
    }
	JsonParser *parser = json_parser_new();
	JsonNode *node = json_node_new(JSON_NODE_OBJECT);
	json_parser_load_from_file(parser, "test.txt", NULL);
	node = json_parser_get_root(parser);
    
	JsonObject *obj2 = json_object_new();
	obj2 = json_node_get_object(node);


	return true;
}


bool process_has_exe(Process *proc){
	return proc->exe[0] != 0;
}

bool process_match_exe(Process *proc, const char *untrusted_proc){
	if(!process_has_exe(proc))
		return false;
	return strcmp(proc->exe, untrusted_proc) == 0 ? true : false;
}

bool process_trusted(Process *proc, Config *cf){
	Conf *c = NULL;
	Node *n = cf->list.head;
	size_t cf_list_size = cf->list.size;

	for(size_t i = 0; i < cf_list_size; i++){
		c = n->data;
		if(strcmp(c->key, "prog") == 0){
			if(process_match_exe(proc, c->val)){
				return false;
			}
		}
		n = n->next;
	}

	return true;
}

Process *process_create(int pid){
	Process *proc = malloc(sizeof(Process));
	if(!proc)
		return NULL;

	proc->pid = pid;
	proc->state = 0;
	proc->flags = 0;
	memset(proc->exe, 0, sizeof(PATH_MAX));
	return proc;
}

void process_destroy(Process *proc){
	free(proc);
	return;
}

int process_stat(Process *proc, const char *pid){
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
	{
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
	
	return 0;
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

        if(strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
                continue;

	// skip self
	if(strcmp(name, self_name) == 0)
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
	Process *proc = proc_node->data;
	process_stat(proc, name);

	scan_proc_dir(list, pid_path, proc, period, cf);

	if(!process_promise_pass(proc)){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}

	if(proc->flags & PF_KTHREAD){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}

	if(process_trusted(proc, cf)){
		process_destroy(proc);
		node_destroy(proc_node);
		continue;
	}

	if(!pre_exist){
		printf("new one, pid: %s, exe: %s, state: %c\n", name, proc->exe, proc->state);
		list_push_back(list, proc_node);
	} else { // check zombie process here

	}
    }

    closedir(scan_dir);
    return;
}

