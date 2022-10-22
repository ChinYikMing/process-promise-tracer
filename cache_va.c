#include "cache_va.h"
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

cacheline **cache_create(int set, int assoc){
	cacheline **cache = NULL;

	cache = malloc(sizeof(cacheline *) * set);      // may be unsigned integer overflow, be careful!
	if(!cache)
		return NULL;

	void *ptr;
	int i, j;
	for(i = 0; i < set; i++){
		ptr = malloc(sizeof(cacheline) * assoc);  // also may be unsigned integer overflow, be careful!
		if(!ptr){
			for(j = 0; j < i; j++){
				free(cache[j]);
			}
			free(cache);
			return NULL;
		}

		cache[i] = ptr;

		for(j = 0; j < assoc; j++){
			cache[i][j].valid = false;
			cache[i][j].tag = 0;
			cache[i][j].ref_cnt = 0;
		}
	}

	return cache;
}

void cacheline_destroy(cacheline *cl){
	free(cl);
}

void cache_destroy(cacheline **cache, int set){
	if(!cache)
		return;

	cacheline *cl;
	for(int i = 0; i < set; i++){
		cl = cache[i];
		cacheline_destroy(cl);
	}

	free(cache);
}

void printSummary(int hits, int misses, int evictions)
{
    printf("hits:%d misses:%d evictions:%d\n", hits, misses, evictions);
}

void cache_virtaddr(Process *proc, int set_bit, int assoc, int block_bit, const char *expr){
	cacheline **cache = proc->cache;
	char operation;
	uint64_t addr;

	int set_size = 1 << set_bit;
	int block_size = 1 << block_bit;

	int64_t set_idx;
	uint64_t tag;

	//printf("expr: %s\n", expr);
	sscanf(expr, "%c %lx", &operation, &addr);

	set_idx = (addr / block_size) % set_size;
	tag = addr >> (set_bit + block_bit);
	cacheline *empty_cacheline;
	cacheline *hit_cacheline;
	cacheline *lru_cacheline;

	proc->glob_ref_cnt++;

	switch(operation){
		case 'L':
			if((hit_cacheline = check_cacheline_in_set_hit(cache[set_idx], assoc, tag))){
				proc->hit_cnt++;
				set_cacheline_ref_cnt(hit_cacheline, proc->glob_ref_cnt);

				break;
			}

			goto load_store_common;

		case 'S':
			if((hit_cacheline = check_cacheline_in_set_hit(cache[set_idx], assoc, tag)) != NULL){
				proc->hit_cnt++;
				set_cacheline_ref_cnt(hit_cacheline, proc->glob_ref_cnt);

				break;
			}

load_store_common:
			if((empty_cacheline = find_empty_cacheline_in_set(cache[set_idx], assoc)) == NULL){
				proc->eviction_cnt++;
				proc->miss_cnt++;

				lru_cacheline = find_lru_cacheline_in_set(cache[set_idx], assoc);
				assert(lru_cacheline != NULL);

				set_cacheline_tag(lru_cacheline, tag);
				set_cacheline_valid(lru_cacheline, VALID);
				set_cacheline_ref_cnt(lru_cacheline, proc->glob_ref_cnt);

				break;
			}

			proc->miss_cnt++;
			set_cacheline_tag(empty_cacheline, tag);
			set_cacheline_valid(empty_cacheline, VALID);
			set_cacheline_ref_cnt(empty_cacheline, proc->glob_ref_cnt);

			break;

		default:
			break;
	}

}

uint8_t get_cacheline_valid_bit(cacheline cl){
	return cl.valid;
}

void set_cacheline_valid(cacheline *cl, int8_t valid){
	cl->valid = valid;
}

void set_cacheline_tag(cacheline *cl, uint64_t tag){
	cl->tag = tag;
}

void up_cacheline_ref_cnt(cacheline *cl){
	cl->ref_cnt++;
}

void set_cacheline_ref_cnt(cacheline *cl, uint64_t ref_cnt){
	cl->ref_cnt = ref_cnt;
}

uint64_t get_cacheline_tag(cacheline cl){
	return cl.tag;
}

uint64_t get_cacheline_ref_cnt(cacheline cl){
	return cl.ref_cnt;
}

bool is_cacheline_valid(cacheline cl){
	return get_cacheline_valid_bit(cl) == 1 ? true : false;
}

bool is_cacheline_match_tag(cacheline cl, uint64_t tag){
	return cl.tag == tag ? true : false;
}

cacheline *find_empty_cacheline_in_set(cacheline *cl_in_set, int assoc){
	for(int i = 0; i < assoc; i++){
		if(!is_cacheline_valid(cl_in_set[i])){
			return (cl_in_set + i);
		}
	}

	return NULL;
}

cacheline *check_cacheline_in_set_hit(cacheline *cl_in_set, int assoc, uint64_t tag){
	for(int i = 0; i < assoc; i++){
		if(is_cacheline_valid(cl_in_set[i]) &&
		   is_cacheline_match_tag(cl_in_set[i], tag)){
			return (cl_in_set + i);
		}
	}

	return NULL;
}

cacheline *find_lru_cacheline_in_set(cacheline *cl_in_set, int assoc){
	cacheline *lru_cacheline = cl_in_set;
	uint64_t least_ref_cnt;
	uint64_t curr_least_ref_cnt;

	least_ref_cnt = cl_in_set[0].ref_cnt;
	for(int i = 1; i < assoc; i++){
		curr_least_ref_cnt = cl_in_set[i].ref_cnt;

		if(curr_least_ref_cnt < least_ref_cnt){
			least_ref_cnt = curr_least_ref_cnt;
			lru_cacheline = cl_in_set + i;
		}
	}

	return lru_cacheline;
}
