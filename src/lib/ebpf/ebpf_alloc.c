#include "ebpf_alloc.h"

#include <stdint.h>
#include <stddef.h>
#include <memory.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>


static uintptr_t total_allocs = 0;
static uintptr_t total_mem = 0;

void *ebpf_malloc(size_t size) {
	void *mem = malloc(sizeof(uintptr_t)+size);
	assert(mem);
	*(uintptr_t*)mem = size;
	total_allocs++;
	total_mem += size;
	return (char*)mem+sizeof(uintptr_t);
}

void *ebpf_free(void *ptr) {
	if (ptr) {
		total_mem -= *(uintptr_t*)((char*)ptr-sizeof(uintptr_t));
		free((char*)ptr-sizeof(uintptr_t));
		total_allocs--;
	}
}

void ebpf_alloc_check(bool zero) {
	printf("alloc ti:%lu sz:%lu\n", total_allocs, total_mem);
	if (zero) {
		assert(total_allocs == 0);
		assert(total_mem == 0);
	}
}
