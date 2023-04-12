#ifndef ewfd_unit_H_
#define ewfd_unit_H_

#include <stdint.h>
#include <stdbool.h>

/** 封装libebpf vm
模仿BPF_PROG_TYPE_SYSCALL类型，用eBPF加载eBPF。
https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/skel_internal.h#L331
1. map create 类型
*/

typedef struct ewfd_code_t {
	int code_type;
	int code_len;
	uint64_t code[0];
} ewfd_code_st;

/** ewfd ringbuffer & map
模仿linux fd设计：

*/
typedef struct ewfd_map_t {
	uint8_t map_type;
} ewfd_map_st;

typedef struct ewfd_map_fdtable_t {
	uint32_t max_fds;
	ewfd_map_st **fd_table;
} ewfd_map_fdtable_st;

/**
ewfd-unit绑定多个ebpf-vm，
- init, create map
- run,
*/
typedef struct ewfd_unit_t {
	void *ebpf_vm;
	int times;
	uint32_t total_ti;
	ewfd_map_fdtable_st map_table;
} ewfd_unit_st;

ewfd_unit_st* init_ewfd_unit(void);
bool ewfd_unit_set_code(ewfd_code_st *ewfd_code);
void free_ewfd_unit(ewfd_unit_st *ewfd_unit);
uint64_t run_ewfd_unit(ewfd_unit_st *ewfd_unit, void *ewfd_ctx);

#endif // ewfd_unit_H_
