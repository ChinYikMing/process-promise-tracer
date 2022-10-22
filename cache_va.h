#ifndef CACHE_VA_HDR
#define CACHE_VA_HDR

#define VALID 0x1
#define DIRTY 0x1

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/syscall.h>

typedef struct cache_line {  // 64 bit address space
	uint8_t valid;
	uint64_t tag;
	uint64_t ref_cnt;   // to implement LRU replacement policy
} cacheline;

cacheline **cache_create(int set, int assoc);
void cache_destroy(cacheline **cache, int set);

uint8_t get_cacheline_valid_bit(cacheline cl);
uint64_t get_cacheline_tag(cacheline cl);
uint64_t get_cacheline_ref_cnt(cacheline cl);
void set_cacheline_valid(cacheline *cl, int8_t valid);
void set_cacheline_tag(cacheline *cl, uint64_t tag);
void set_cacheline_ref_cnt(cacheline *cl, uint64_t ref_cnt);
void up_cacheline_ref_cnt(cacheline *cl);
bool is_cacheline_valid(cacheline cl);
bool is_cacheline_match_tag(cacheline cl, uint64_t tag);
cacheline *find_empty_cacheline_in_set(cacheline *cl_in_set, int assoc);
cacheline *check_cacheline_in_set_hit(cacheline *cl_in_set, int assoc, uint64_t tag);
cacheline *find_lru_cacheline_in_set(cacheline *cl_in_set, int assoc);

#endif
