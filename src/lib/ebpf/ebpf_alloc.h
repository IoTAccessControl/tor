#ifndef EBPF_ALLOC_
#define EBPF_ALLOC_

#include <stdbool.h>
#include <stddef.h>

void *ebpf_malloc(size_t size);
void *ebpf_free(void *ptr);
void ebpf_alloc_check(bool zero);

#endif // EBPF_ALLOC_
