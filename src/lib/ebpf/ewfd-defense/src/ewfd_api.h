#ifndef _EWFD_UNIT_H_
#define _EWFD_UNIT_H_

#include "ewfd_maps.h"
#include "ewfd_helper.h"

#include <stdint.h>
#include <stdlib.h>

/*
eWFD接口：
*/

struct ebpf_vm;
typedef struct ewfd_unit_t {
	struct ebpf_vm *vm;
	int times;
	uint32_t total_ti;
	ewfd_map_fdtable_st map_table;
} ewfd_unit_st;

struct ewfd_unit_t *ewfd_unit_new(void);
void ewfd_unit_clear(struct ewfd_unit_t *unit);
int ebpf_run_code(struct ebpf_vm *vm, void *mem, size_t mem_len, uint64_t *ret_val);

#endif // _EWFD_UNIT_H_
